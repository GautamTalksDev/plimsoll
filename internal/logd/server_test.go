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

package logd_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GautamTalksDev/plimsoll/internal/adapt"
	"github.com/GautamTalksDev/plimsoll/internal/attestation"
	"github.com/GautamTalksDev/plimsoll/internal/decide"
	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/logclient"
	"github.com/GautamTalksDev/plimsoll/internal/logd"
	"github.com/GautamTalksDev/plimsoll/internal/seal"
	"github.com/GautamTalksDev/plimsoll/internal/site"
	"github.com/GautamTalksDev/plimsoll/internal/verify"
)

func testKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func startLogd(t *testing.T, cfg logd.Config) (*logd.Server, *httptest.Server) {
	t.Helper()
	s := logd.New(cfg)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(func() {
		ts.Close()
		_ = s.Close()
	})
	return s, ts
}

func TestLogdVerifyE2E(t *testing.T) {
	priv, pub := testKey(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "log.sqlite")
	l, err := log.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, srv := startLogd(t, logd.Config{Log: l, PrivKey: priv, PublicKey: pub})

	lc := logclient.NewHTTP(srv.URL, priv, srv.Client())
	defer func() { _ = lc.Close() }()

	ss, sealHash := testSignedSeal(t, priv, `<script>alert(1)</script>`)
	if _, err := lc.PublishSeal(ss, sealHash, pub); err != nil {
		t.Fatal(err)
	}
	rs := testResultSet()
	v, _ := decide.Evaluate(ss.Seal, rs)
	doc, _ := attestation.Build(sealHash, ss.Seal, rs, v)
	signed, _ := attestation.Sign(doc, priv)
	if _, err := lc.PublishAttestation(signed); err != nil {
		t.Fatal(err)
	}
	attPath := filepath.Join(dir, "att.json")
	b, _ := json.MarshalIndent(signed.Document, "", "  ")
	if err := os.WriteFile(attPath, b, 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := verify.Run(attPath, verify.Options{LogURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != verify.VerdictVerified {
		t.Fatalf("verdict=%q", report.Verdict)
	}
}

func TestSubmitRejectsExtraField(t *testing.T) {
	priv, pub := testKey(t)
	l, err := log.Open(filepath.Join(t.TempDir(), "l.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	_, srv := startLogd(t, logd.Config{Log: l, PrivKey: priv, PublicKey: pub})
	body := []byte(`{"seal_hash":"x","canonical_b64":"e30=","submitter_id":"t","submitted_at":1,"supersedes":"","signature_b64":"AA==","public_key_b64":"AA==","extra":"nope"}`)
	res, err := http.Post(srv.URL+"/submit", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", res.StatusCode)
	}
}

func TestTamperedDBFailsVerify(t *testing.T) {
	priv, pub := testKey(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "log.sqlite")
	l, err := log.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s, srv := startLogd(t, logd.Config{Log: l, PrivKey: priv, PublicKey: pub})
	lc := logclient.NewHTTP(srv.URL, priv, srv.Client())
	ss, sealHash := testSignedSeal(t, priv, "safe-name")
	if _, err := lc.PublishSeal(ss, sealHash, pub); err != nil {
		t.Fatal(err)
	}
	rs := testResultSet()
	v, _ := decide.Evaluate(ss.Seal, rs)
	doc, _ := attestation.Build(sealHash, ss.Seal, rs, v)
	signed, _ := attestation.Sign(doc, priv)
	if _, err := lc.PublishAttestation(signed); err != nil {
		t.Fatal(err)
	}
	srv.Close()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tamperCanonicalInSQLite(dbPath); err != nil {
		t.Fatal(err)
	}
	l2, err := log.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, srv2 := startLogd(t, logd.Config{Log: l2, PrivKey: priv, PublicKey: pub})
	attPath := filepath.Join(dir, "att.json")
	ab, err := json.Marshal(signed.Document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(attPath, ab, 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := verify.Run(attPath, verify.Options{LogURL: srv2.URL})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != verify.VerdictNotVerified {
		t.Fatalf("expected NOT VERIFIED got %q", report.Verdict)
	}
}

func TestBadgeShowsAttemptCount(t *testing.T) {
	priv, pub := testKey(t)
	l, err := log.Open(filepath.Join(t.TempDir(), "l.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	_, srv := startLogd(t, logd.Config{Log: l, PrivKey: priv, PublicKey: pub})
	lc := logclient.NewHTTP(srv.URL, priv, srv.Client())
	ss, sealHash := testSignedSeal(t, priv, "badge-test")
	if _, err := lc.PublishSeal(ss, sealHash, pub); err != nil {
		t.Fatal(err)
	}
	rs := testResultSet()
	for i := 0; i < 3; i++ {
		v, _ := decide.Evaluate(ss.Seal, rs)
		doc, _ := attestation.Build(sealHash, ss.Seal, rs, v)
		signed, _ := attestation.Sign(doc, priv)
		if _, err := lc.PublishAttestation(signed); err != nil {
			t.Fatal(err)
		}
	}
	res, err := http.Get(srv.URL + "/seal/" + strings.ReplaceAll(sealHash, ":", "%3A") + "/badge.svg")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "verified (3)") {
		t.Fatalf("badge=%s", buf.String())
	}
}

func TestSiteEscapesScriptSubject(t *testing.T) {
	priv, pub := testKey(t)
	dir := t.TempDir()
	l, err := log.Open(filepath.Join(dir, "l.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	spec := filepath.Join(dir, "spec.md")
	if err := os.WriteFile(spec, []byte("# Spec\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	siteRenderer, err := site.New(l, pub, spec, "http://test")
	if err != nil {
		t.Fatal(err)
	}
	_, srv := startLogd(t, logd.Config{
		Log: l, PrivKey: priv, PublicKey: pub, Site: siteRenderer,
	})
	lc := logclient.NewHTTP(srv.URL, priv, srv.Client())
	ss, sealHash := testSignedSeal(t, priv, `<script>alert(1)</script>`)
	if _, err := lc.PublishSeal(ss, sealHash, pub); err != nil {
		t.Fatal(err)
	}
	res, err := http.Get(srv.URL + "/seal/" + strings.ReplaceAll(sealHash, ":", "%3A"))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "<script>") {
		t.Fatalf("xss in page: %s", buf.String())
	}
}

func testSignedSeal(t *testing.T, priv ed25519.PrivateKey, subjectName string) (*seal.SignedSeal, string) {
	t.Helper()
	s := &seal.Seal{
		PlimsollVersion: seal.Version, CanonVersion: seal.CanonVersion,
		CreatedAt: "2026-08-25T12:00:00Z",
		Subject: seal.Subject{
			Name: subjectName,
			SystemUnderTest: seal.SystemUnderTest{
				Model: "m", PromptSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				ConfigSHA256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			},
		},
		Dataset:         seal.Dataset{N: 1, SHA256: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", Sampling: "exhaustive"},
		Harness:         seal.Harness{Tool: "generic", Version: "1.0.0", ConfigSHA256: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
		Metrics:         []seal.Metric{{ID: "acc", Name: "a", DefinitionURI: "https://example.invalid/m", Direction: "higher_is_better"}},
		DecisionRule:    seal.DecisionRule{Expression: "acc.mean >= 0.5", PrimaryMetric: "acc", Threshold: "0.5", Comparison: ">=", Precision: 1},
		PlannedAttempts: 3, AnalysisPlan: "t",
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	ss, _ := s.ForSign().Sign(priv)
	hash, _ := ss.Seal.CanonicalHash()
	return ss, hash
}

func testResultSet() *adapt.ResultSet {
	return &adapt.ResultSet{
		Harness: "generic", HarnessVer: "1.0.0",
		RowDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		Metrics:   map[string]adapt.MetricValues{"acc": {MetricID: "acc", Raw: []string{"1"}, N: 1}},
	}
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
