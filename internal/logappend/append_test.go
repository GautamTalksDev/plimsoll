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

package logappend_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GautamTalksDev/plimsoll/internal/adapt"
	"github.com/GautamTalksDev/plimsoll/internal/attestation"
	"github.com/GautamTalksDev/plimsoll/internal/decide"
	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/logappend"
	"github.com/GautamTalksDev/plimsoll/internal/seal"
)

func TestRejectExtraField(t *testing.T) {
	l, priv := openLog(t)
	body := []byte(`{"seal_hash":"sha256:` + strings.Repeat("a", 64) + `","canonical_b64":"e30=","submitter_id":"t","submitted_at":1,"supersedes":"","signature_b64":"AA==","public_key_b64":"AA==","extra":true}`)
	if _, err := logappend.Append(l, priv, body); err == nil {
		t.Fatal("expected reject extra field")
	}
}

func TestRejectBadSealSignature(t *testing.T) {
	l, logPriv := openLog(t)
	authorPriv, authorPub := testKey(t)
	ss, sealHash := signedSeal(t, authorPriv, "ok")
	canon, err := ss.Seal.ForSign().CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	badSig := make([]byte, ed25519.SignatureSize)
	body, _ := json.Marshal(map[string]any{
		"seal_hash":      sealHash,
		"canonical_b64":  base64.StdEncoding.EncodeToString(canon),
		"submitter_id":   ss.Seal.Subject.Name,
		"submitted_at":   int64(1),
		"supersedes":     "",
		"signature_b64":  base64.StdEncoding.EncodeToString(badSig),
		"public_key_b64": base64.StdEncoding.EncodeToString(authorPub),
	})
	if _, err := logappend.Append(l, logPriv, body); err == nil {
		t.Fatal("expected reject bad signature")
	}
}

func TestAppendSealAndAttestation(t *testing.T) {
	l, logPriv := openLog(t)
	authorPriv, authorPub := testKey(t)
	ss, sealHash := signedSeal(t, authorPriv, "claim")
	canon, err := ss.Seal.ForSign().CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	sealBody, _ := json.Marshal(map[string]any{
		"seal_hash":      sealHash,
		"canonical_b64":  base64.StdEncoding.EncodeToString(canon),
		"submitter_id":   ss.Seal.Subject.Name,
		"submitted_at":   int64(1_700_000_000),
		"supersedes":     "",
		"signature_b64":  base64.StdEncoding.EncodeToString(ss.Signature),
		"public_key_b64": base64.StdEncoding.EncodeToString(authorPub),
	})
	r, err := logappend.Append(l, logPriv, sealBody)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != logappend.KindSeal || r.Idx != 0 || r.Hash != sealHash {
		t.Fatalf("result=%+v", r)
	}
	msg := r.CommitMessage()
	if strings.Contains(msg, "claim") || strings.Contains(msg, "<") {
		t.Fatalf("commit message leaked free text: %q", msg)
	}
	if !strings.HasPrefix(msg, "append: seal sha256:") {
		t.Fatalf("msg=%q", msg)
	}

	rs := &adapt.ResultSet{
		Harness: "generic", HarnessVer: "1.0.0",
		RowDigest: "sha256:" + strings.Repeat("0", 64),
		Metrics:   map[string]adapt.MetricValues{"acc": {MetricID: "acc", Raw: []string{"1"}, N: 1}},
	}
	v, err := decide.Evaluate(ss.Seal, rs)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := attestation.Build(sealHash, ss.Seal, rs, v)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := attestation.Sign(doc, authorPriv)
	if err != nil {
		t.Fatal(err)
	}
	attBody, _ := json.Marshal(map[string]any{
		"seal_hash":     sealHash,
		"result_digest": signed.Document.ResultDigest,
		"verdict":       signed.Document.Verdict,
		"canonical_b64": base64.StdEncoding.EncodeToString(signed.Canonical),
		"signature_b64": base64.StdEncoding.EncodeToString(signed.Signature),
	})
	r2, err := logappend.Append(l, logPriv, attBody)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Kind != logappend.KindAttestation || r2.Idx != 1 {
		t.Fatalf("result=%+v", r2)
	}
	if r2.CommitMessage() != "append: attestation "+r2.Hash+" idx=1" {
		t.Fatalf("msg=%q", r2.CommitMessage())
	}
}

func TestRejectAttestationBadSignature(t *testing.T) {
	l, logPriv := openLog(t)
	authorPriv, authorPub := testKey(t)
	ss, sealHash := signedSeal(t, authorPriv, "claim")
	canon, _ := ss.Seal.ForSign().CanonicalBytes()
	sealBody, _ := json.Marshal(map[string]any{
		"seal_hash": sealHash, "canonical_b64": base64.StdEncoding.EncodeToString(canon),
		"submitter_id": "claim", "submitted_at": int64(1), "supersedes": "",
		"signature_b64":  base64.StdEncoding.EncodeToString(ss.Signature),
		"public_key_b64": base64.StdEncoding.EncodeToString(authorPub),
	})
	if _, err := logappend.Append(l, logPriv, sealBody); err != nil {
		t.Fatal(err)
	}
	rs := &adapt.ResultSet{
		Harness: "generic", HarnessVer: "1.0.0",
		RowDigest: "sha256:" + strings.Repeat("0", 64),
		Metrics:   map[string]adapt.MetricValues{"acc": {MetricID: "acc", Raw: []string{"1"}, N: 1}},
	}
	v, _ := decide.Evaluate(ss.Seal, rs)
	doc, _ := attestation.Build(sealHash, ss.Seal, rs, v)
	signed, _ := attestation.Sign(doc, authorPriv)
	bad := make([]byte, ed25519.SignatureSize)
	attBody, _ := json.Marshal(map[string]any{
		"seal_hash": sealHash, "result_digest": signed.Document.ResultDigest,
		"verdict":       signed.Document.Verdict,
		"canonical_b64": base64.StdEncoding.EncodeToString(signed.Canonical),
		"signature_b64": base64.StdEncoding.EncodeToString(bad),
	})
	if _, err := logappend.Append(l, logPriv, attBody); err == nil {
		t.Fatal("expected reject bad attestation signature")
	}
}

func openLog(t *testing.T) (*log.Log, ed25519.PrivateKey) {
	t.Helper()
	priv, _ := testKey(t)
	l, err := log.Open(filepath.Join(t.TempDir(), "log.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, priv
}

func testKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func signedSeal(t *testing.T, priv ed25519.PrivateKey, name string) (*seal.SignedSeal, string) {
	t.Helper()
	s := &seal.Seal{
		PlimsollVersion: seal.Version, CanonVersion: seal.CanonVersion,
		CreatedAt: "2026-08-25T12:00:00Z",
		Subject: seal.Subject{
			Name: name,
			SystemUnderTest: seal.SystemUnderTest{
				Model: "m", PromptSHA256: "sha256:" + strings.Repeat("a", 64),
				ConfigSHA256: "sha256:" + strings.Repeat("b", 64),
			},
		},
		Dataset:         seal.Dataset{N: 1, SHA256: "sha256:" + strings.Repeat("c", 64), Sampling: "exhaustive"},
		Harness:         seal.Harness{Tool: "generic", Version: "1.0.0", ConfigSHA256: "sha256:" + strings.Repeat("d", 64)},
		Metrics:         []seal.Metric{{ID: "acc", Name: "a", DefinitionURI: "https://example.invalid/m", Direction: "higher_is_better"}},
		DecisionRule:    seal.DecisionRule{Expression: "acc.mean >= 0.5", PrimaryMetric: "acc", Threshold: "0.5", Comparison: ">=", Precision: 1},
		PlannedAttempts: 3, AnalysisPlan: "t",
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	ss, err := s.ForSign().Sign(priv)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := ss.Seal.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	return ss, hash
}
