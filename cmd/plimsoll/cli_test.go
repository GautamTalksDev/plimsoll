// Copyright 2026 The PLIMSOLL Authors
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/GautamTalksDev/plimsoll/internal/adapt"
	"github.com/GautamTalksDev/plimsoll/internal/attestation"
	"github.com/GautamTalksDev/plimsoll/internal/cliout"
	"github.com/GautamTalksDev/plimsoll/internal/decide"
	"github.com/GautamTalksDev/plimsoll/internal/logclient"
	"github.com/GautamTalksDev/plimsoll/internal/payload"
	"github.com/GautamTalksDev/plimsoll/internal/seal"
	"github.com/GautamTalksDev/plimsoll/internal/testbin"
)

func TestE2ESealAttestLocal(t *testing.T) {
	dir := t.TempDir()
	copyTree(t, filepath.Join("..", "..", "testdata", "e2e"), dir)
	key := filepath.Join(dir, "test.key")
	logPath := filepath.Join(dir, "log.sqlite")
	plimsoll := buildPlimsoll(t)
	prereg := filepath.Join(dir, "prereg.yaml")

	out, err := runCmd(plimsoll, dir, "seal", "--file", prereg, "--key", key)
	if err != nil {
		t.Fatalf("seal: %v\n%s", err, out)
	}
	if !strings.Contains(out, cliout.LocalOnlyWarning) {
		t.Fatalf("expected LOCAL ONLY warning:\n%s", out)
	}
	sealFile := filepath.Join(dir, "e2e-claim.seal.json")
	if _, err := os.Stat(sealFile); err != nil {
		t.Fatal(err)
	}

	out, err = runCmd(plimsoll, dir, "attest", "--seal", sealFile, "--results", filepath.Join(dir, "results_pass.json"), "--key", key)
	if err != nil {
		t.Fatalf("attest expected exit 0: %v\n%s", err, out)
	}
	if !strings.Contains(out, "PASS") {
		t.Fatalf("expected PASS:\n%s", out)
	}

	out, err = runCmd(plimsoll, dir, "seal", "--file", prereg, "--publish", "--key", key, "--log", logPath)
	if err != nil {
		t.Fatalf("seal publish: %v\n%s", err, out)
	}
	if strings.Contains(out, cliout.LocalOnlyWarning) {
		t.Fatal("publish should not show LOCAL ONLY")
	}

	var prev []string
	for i := 0; i < 5; i++ {
		code, out, err := runCmdExit(plimsoll, dir, "attest", "--seal", sealFile, "--results", filepath.Join(dir, "results_fail.json"), "--publish", "--key", key, "--log", logPath)
		if err != nil {
			t.Fatalf("attest run %d: %v\n%s", i+1, err, out)
		}
		if code != 1 {
			t.Fatalf("run %d: exit=%d want FAIL(1)\n%s", i+1, code, out)
		}
		wantAttempt := "Attempt " + strconv.Itoa(i+1) + " of this seal."
		if !strings.Contains(out, wantAttempt) {
			t.Fatalf("run %d: missing %q in:\n%s", i+1, wantAttempt, out)
		}
		if i > 0 {
			for _, p := range prev {
				if !strings.Contains(out, p) {
					t.Fatalf("run %d: missing previous verdict %q in:\n%s", i+1, p, out)
				}
			}
		}
		prev = append(prev, "FAIL")
	}
}

func TestNoNetworkWithoutPublish(t *testing.T) {
	dir := t.TempDir()
	copyTree(t, filepath.Join("..", "..", "testdata", "e2e"), dir)
	key := filepath.Join(dir, "test.key")
	plimsoll := buildPlimsoll(t)
	prereg := filepath.Join(dir, "prereg.yaml")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	if _, err := runCmd(plimsoll, dir, "seal", "--file", prereg, "--key", key); err != nil {
		t.Fatal(err)
	}
	sealFile := filepath.Join(dir, "e2e-claim.seal.json")
	if _, err := runCmd(plimsoll, dir, "attest", "--seal", sealFile, "--results", filepath.Join(dir, "results_pass.json"), "--key", key); err != nil {
		t.Fatal(err)
	}
}

func TestOutboundPayloadAllowlist(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	dir := t.TempDir()
	lc, err := logclient.OpenSQLite(filepath.Join(dir, "l.sqlite"), priv)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lc.Close() }()
	var payloads [][]byte
	lc.SetRecordHook(func(b []byte) { payloads = append(payloads, append([]byte(nil), b...)) })

	s := testSeal()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	signed, err := s.ForSign().Sign(priv)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := signed.Seal.CanonicalHash()
	if _, err := lc.PublishSeal(signed, hash, pub); err != nil {
		t.Fatal(err)
	}
	rs := &adapt.ResultSet{
		Harness: "generic", HarnessVer: "1.0.0",
		RowDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		Metrics: map[string]adapt.MetricValues{
			"acc": {MetricID: "acc", Raw: []string{"1"}, N: 1},
		},
		Extra: json.RawMessage("{}"),
	}
	v, err := decide.Evaluate(s, rs)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := attestation.Build(hash, s, rs, v)
	if err != nil {
		t.Fatal(err)
	}
	signedAtt, err := attestation.Sign(doc, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lc.PublishAttestation(signedAtt); err != nil {
		t.Fatal(err)
	}
	if len(payloads) != 2 {
		t.Fatalf("payloads=%d want 2", len(payloads))
	}
	if err := payload.AssertSealPublish(payloads[0]); err != nil {
		t.Fatal(err)
	}
	if err := payload.AssertAttestationPublish(payloads[1]); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payloads[1], []byte(`"rows"`)) {
		t.Fatal("attestation payload contains rows")
	}
}

func TestSanitizeUntrustedResults(t *testing.T) {
	in := "\x1b[31mPASS\x1b[0m \u202esecret"
	out := cliout.Sanitize(in)
	if strings.Contains(out, "\x1b") {
		t.Fatalf("ANSI not stripped: %q", out)
	}
	if strings.Contains(out, "\u202e") {
		t.Fatalf("bidi not stripped: %q", out)
	}
}

func TestVerdictExitCodes(t *testing.T) {
	if verdictExit(&decide.Verdict{Result: "PASS"}) != 0 {
		t.Fatal("PASS")
	}
	if verdictExit(&decide.Verdict{Result: "FAIL"}) != 1 {
		t.Fatal("FAIL")
	}
	if verdictExit(&decide.Verdict{Result: "INVALID"}) != 2 {
		t.Fatal("INVALID")
	}
}

func testSeal() *seal.Seal {
	return &seal.Seal{
		PlimsollVersion: seal.Version,
		CreatedAt:       "2026-08-25T00:00:00Z",
		CanonVersion:    seal.CanonVersion,
		Subject: seal.Subject{
			Name: "t",
			SystemUnderTest: seal.SystemUnderTest{
				Model:        "m",
				PromptSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				ConfigSHA256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		},
		Dataset: seal.Dataset{
			N:        1,
			SHA256:   "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			Sampling: "exhaustive",
		},
		Harness: seal.Harness{
			Tool: "generic", Version: "1.0.0",
			ConfigSHA256: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		},
		Metrics: []seal.Metric{{
			ID: "acc", Name: "a", DefinitionURI: "https://example.invalid/m", Direction: "higher_is_better",
		}},
		DecisionRule: seal.DecisionRule{
			Expression: "acc.mean >= 0.5", PrimaryMetric: "acc",
			Threshold: "0.5", Comparison: ">=", Precision: 1,
		},
		PlannedAttempts: 1,
		AnalysisPlan:    "t",
	}
}

func buildPlimsoll(t *testing.T) string {
	return testbin.Plimsoll(t)
}

func runCmd(bin, dir string, args ...string) (string, error) {
	code, out, err := runCmdExit(bin, dir, args...)
	if err != nil {
		return out, err
	}
	if code != 0 {
		return out, &exitCode{code: code}
	}
	return out, nil
}

func runCmdExit(bin, dir string, args ...string) (int, string, error) {
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	out := buf.String()
	if err == nil {
		return 0, out, nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), out, nil
	}
	return -1, out, err
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	_ = filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
}
