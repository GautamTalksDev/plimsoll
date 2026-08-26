// Copyright 2026 The PLIMSOLL Authors
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

//go:build !js

package verify_test

import (
	"crypto/ed25519"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GautamTalksDev/plimsoll/internal/attestation"
	"github.com/GautamTalksDev/plimsoll/internal/keys"
	"github.com/GautamTalksDev/plimsoll/internal/logclient"
	"github.com/GautamTalksDev/plimsoll/internal/logserver"
	"github.com/GautamTalksDev/plimsoll/internal/testbin"
	"github.com/GautamTalksDev/plimsoll/internal/verify"
)

func TestVerifyOfflineWithNetworkDown(t *testing.T) {
	env := publishE2E(t, 1, "results_pass.json")
	bundlePath := filepath.Join(env.dir, "bundle.json")
	bundle, err := verify.BuildBundleFromLog(env.lcLog.Log(), env.pub, env.lastAtt)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify.WriteBundle(bundlePath, bundle); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	report, err := verify.Run(env.attPath, verify.Options{Offline: true, BundlePath: bundlePath})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != verify.VerdictVerified {
		t.Fatalf("verdict=%q want VERIFIED", report.Verdict)
	}
	assertAllPass(t, report, "V8", "V9")
}

func TestVerifyAgainstSecondLogHTTP(t *testing.T) {
	env := publishE2E(t, 1, "results_pass.json")
	srv := httptest.NewServer(logserver.New(env.lcLog.Log(), env.pub).Handler())
	defer srv.Close()
	report, err := verify.Run(env.attPath, verify.Options{LogURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != verify.VerdictVerified {
		t.Fatalf("verdict=%q checks=%+v", report.Verdict, report.Checks)
	}
}

func TestTamperedSQLiteFailsVerification(t *testing.T) {
	env := publishE2E(t, 1, "results_pass.json")
	if err := env.lcLog.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tamperCanonicalInSQLite(env.logPath); err != nil {
		t.Fatal(err)
	}
	priv, pub, err := keys.LoadOrCreate(filepath.Join(env.dir, "test.key"))
	if err != nil {
		t.Fatal(err)
	}
	lc, err := logclient.OpenSQLite(env.logPath, priv)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lc.Close() }()
	srv := httptest.NewServer(logserver.New(lc.Log(), pub).Handler())
	defer srv.Close()
	report, err := verify.Run(env.attPath, verify.Options{LogURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != verify.VerdictNotVerified {
		t.Fatalf("expected NOT VERIFIED after tamper, got %q", report.Verdict)
	}
}

func TestFiveAttemptsVerifiedWithDisclosures(t *testing.T) {
	env := publishE2E(t, 5, "results_fail.json")
	srv := httptest.NewServer(logserver.New(env.lcLog.Log(), env.pub).Handler())
	defer srv.Close()
	report, err := verify.Run(env.attPath, verify.Options{LogURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != verify.VerdictVerifiedDisclosures {
		t.Fatalf("verdict=%q want VERIFIED WITH DISCLOSURES", report.Verdict)
	}
	if report.Disclosure == nil || report.Disclosure.TotalAttempts != 5 {
		t.Fatalf("disclosure=%+v", report.Disclosure)
	}
	for i := 1; i <= 5; i++ {
		found := false
		for _, a := range report.Disclosure.Attempts {
			if a.AttemptNo == i && a.Verdict == "FAIL" {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing attempt %d FAIL in %+v", i, report.Disclosure.Attempts)
		}
	}
	v8 := findCheck(report, "V8")
	if v8 == nil || !strings.Contains(v8.Reason, "#5=FAIL") {
		t.Fatalf("V8 reason=%q", v8.Reason)
	}
}

func TestCLIVerify(t *testing.T) {
	env := publishE2E(t, 1, "results_pass.json")
	bundlePath := filepath.Join(env.dir, "bundle.json")
	bundle, err := verify.BuildBundleFromLog(env.lcLog.Log(), env.pub, env.lastAtt)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify.WriteBundle(bundlePath, bundle); err != nil {
		t.Fatal(err)
	}
	plimsoll := buildPlimsoll(t)
	out, err := runPlimsoll(plimsoll, env.dir, "verify", env.attPath, "--offline", "--bundle", bundlePath)
	if err != nil {
		t.Fatalf("verify cli: %v\n%s", err, out)
	}
	if !strings.Contains(out, "VERIFIED") {
		t.Fatalf("output:\n%s", out)
	}
}

type e2eEnv struct {
	dir     string
	logPath string
	attPath string
	lastAtt *attestation.Document
	lcLog   *logclient.Client
	pub     ed25519.PublicKey
}

func publishE2E(t *testing.T, attempts int, resultsFile string) *e2eEnv {
	t.Helper()
	dir := t.TempDir()
	copyTree(t, filepath.Join("..", "..", "testdata", "e2e"), dir)
	key := filepath.Join(dir, "test.key")
	logPath := filepath.Join(dir, "log.sqlite")
	plimsoll := buildPlimsoll(t)
	prereg := filepath.Join(dir, "prereg.yaml")

	if out, err := runPlimsoll(plimsoll, dir, "seal", "--file", prereg, "--key", key, "--publish", "--log", logPath); err != nil {
		t.Fatalf("seal publish: %v\n%s", err, out)
	}
	sealFile := filepath.Join(dir, "e2e-claim.seal.json")
	var attPath string
	for i := 0; i < attempts; i++ {
		out, err := runPlimsollAllowExit(plimsoll, dir, 1, "attest", "--seal", sealFile, "--results", filepath.Join(dir, resultsFile), "--key", key, "--publish", "--log", logPath)
		if err != nil {
			t.Fatalf("attest %d: %v\n%s", i+1, err, out)
		}
		attPath = filepath.Join(dir, "e2e-claim.attest.json")
	}
	priv, pub, err := keys.LoadOrCreate(key)
	if err != nil {
		t.Fatal(err)
	}
	lc, err := logclient.OpenSQLite(logPath, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lc.Close() })
	att, err := verify.LoadAttestation(attPath)
	if err != nil {
		t.Fatal(err)
	}
	return &e2eEnv{dir: dir, logPath: logPath, attPath: attPath, lastAtt: att, lcLog: lc, pub: pub}
}

func assertAllPass(t *testing.T, r *verify.Report, skip ...string) {
	t.Helper()
	skipSet := map[string]bool{}
	for _, id := range skip {
		skipSet[id] = true
	}
	for _, c := range r.Checks {
		if skipSet[c.ID] {
			continue
		}
		if !c.Pass {
			t.Fatalf("%s failed: %s", c.ID, c.Reason)
		}
	}
}

func findCheck(r *verify.Report, id string) *verify.Check {
	for i := range r.Checks {
		if r.Checks[i].ID == id {
			return &r.Checks[i]
		}
	}
	return nil
}

func bytesReplaceInFile(t *testing.T, path string, data []byte, from, to byte) bool {
	t.Helper()
	idx := -1
	for i, b := range data {
		if b == from {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false
	}
	data[idx] = to
	return os.WriteFile(path, data, 0o644) == nil
}

func tamperCanonicalInSQLite(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	needle := []byte("plimsoll-canon")
	idx := bytesIndex(b, needle)
	if idx < 0 {
		return os.ErrNotExist
	}
	pos := idx + len(needle) + 8
	if pos >= len(b) {
		return os.ErrInvalid
	}
	b[pos] ^= 0xff
	return os.WriteFile(path, b, 0o644)
}

func bytesIndex(b, sub []byte) int {
	for i := 0; i+len(sub) <= len(b); i++ {
		ok := true
		for j := range sub {
			if b[i+j] != sub[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

func runPlimsollAllowExit(bin, dir string, allowExit int, args ...string) (string, error) {
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	out := buf.String()
	if err == nil {
		return out, nil
	}
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == allowExit {
		return out, nil
	}
	return out, err
}

func buildPlimsoll(t *testing.T) string {
	return testbin.Plimsoll(t)
}

func runPlimsoll(bin, dir string, args ...string) (string, error) {
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
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
