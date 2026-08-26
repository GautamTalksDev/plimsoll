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

package verify_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GautamTalksDev/plimsoll/internal/attestation"
	"github.com/GautamTalksDev/plimsoll/internal/keys"
	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/logd"
	"github.com/GautamTalksDev/plimsoll/internal/verify"
)

func TestRunBrowserOfflineBundle(t *testing.T) {
	env := browserEnv(t)
	att := env.att
	bundle, err := verify.BuildBundleFromLog(env.l, env.pub, att)
	if err != nil {
		t.Fatal(err)
	}
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	report, err := verify.RunBrowser(string(env.attJSON), string(bundleJSON), "", true)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != verify.VerdictVerified {
		t.Fatalf("verdict=%q", report.Verdict)
	}
	if len(report.Checks) != 9 {
		t.Fatalf("checks=%d", len(report.Checks))
	}
}

func TestRunBrowserEnvelopeOneCheckpoint(t *testing.T) {
	env := browserEnv(t)
	_, envWrap, err := verify.ParseAttestationBytes(env.attJSON)
	if err != nil || envWrap == nil {
		t.Fatalf("expected plimsoll-attest-v1 envelope: err=%v", err)
	}
	resp, err := http.Get(env.srv.URL + "/checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("checkpoint status=%d", resp.StatusCode)
	}
	cpJSON, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	report, err := verify.RunBrowser(string(env.attJSON), "", string(cpJSON), false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != verify.VerdictVerified {
		t.Fatalf("verdict=%q", report.Verdict)
	}
	for _, c := range report.Checks {
		if !c.Pass {
			t.Fatalf("%s failed: %s", c.ID, c.Reason)
		}
	}
}

func TestVerifyURL(t *testing.T) {
	u := verify.VerifyURL("https://example.com/verify", "https://log.example.com", "abc123")
	if !strings.Contains(u, "log=") || !strings.Contains(u, "digest=abc123") {
		t.Fatalf("url=%q", u)
	}
}

type browserTestEnv struct {
	dir     string
	l       *log.Log
	pub     []byte
	srv     *httptest.Server
	att     *attestation.Document
	attJSON []byte
}

func browserEnv(t *testing.T) *browserTestEnv {
	t.Helper()
	dir := t.TempDir()
	copyTree(t, filepath.Join("..", "..", "testdata", "e2e"), dir)
	key := filepath.Join(dir, "test.key")
	logPath := filepath.Join(dir, "log.sqlite")
	plimsoll := buildPlimsoll(t)
	prereg := filepath.Join(dir, "prereg.yaml")
	if out, err := runPlimsoll(plimsoll, dir, "seal", "--file", prereg, "--key", key, "--publish", "--log", logPath); err != nil {
		t.Fatalf("seal: %v\n%s", err, out)
	}
	sealFile := filepath.Join(dir, "e2e-claim.seal.json")
	if out, err := runPlimsoll(plimsoll, dir, "attest", "--seal", sealFile, "--results", filepath.Join(dir, "results_pass.json"), "--key", key, "--publish", "--log", logPath); err != nil {
		t.Fatalf("attest: %v\n%s", err, out)
	}
	attPath := filepath.Join(dir, "e2e-claim.attest.json")
	attJSON, err := os.ReadFile(attPath)
	if err != nil {
		t.Fatal(err)
	}
	att, err := verify.LoadAttestation(attPath)
	if err != nil {
		t.Fatal(err)
	}
	priv, pub, err := keys.LoadOrCreate(key)
	if err != nil {
		t.Fatal(err)
	}
	l, err := log.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logSrv := logd.New(logd.Config{Log: l, PrivKey: priv, PublicKey: pub})
	srv := httptest.NewServer(logSrv.Handler())
	t.Cleanup(func() {
		srv.Close()
		_ = logSrv.Close()
	})
	return &browserTestEnv{dir: dir, l: l, pub: pub, srv: srv, att: att, attJSON: attJSON}
}
