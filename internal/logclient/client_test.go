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

package logclient_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GautamTalksDev/plimsoll/internal/logclient"
	"github.com/GautamTalksDev/plimsoll/internal/seal"
)

func TestPublishSealAccepted202(t *testing.T) {
	priv, pub := testKey(t)
	var sawBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/submit" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		sawBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"accepted","note":"Appended within ~60s."}`))
	}))
	defer srv.Close()

	ss, hash := signedSeal(t, priv, "async")
	lc := logclient.NewHTTP(srv.URL, priv, srv.Client())
	res, err := lc.PublishSeal(ss, hash, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Pending {
		t.Fatal("expected Pending on 202")
	}
	if res.Index != 0 || res.InclusionProof.TreeSize != 0 {
		t.Fatalf("pending result should not claim an index: %+v", res)
	}
	if !strings.Contains(string(sawBody), `"seal_hash"`) {
		t.Fatalf("body=%s", sawBody)
	}
	if !strings.Contains(res.Note, "60s") {
		t.Fatalf("note=%q", res.Note)
	}
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
