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

package attestation

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/GautamTalksDev/plimsoll/internal/adapt"
	"github.com/GautamTalksDev/plimsoll/internal/canonical"
	"github.com/GautamTalksDev/plimsoll/internal/decide"
	"github.com/GautamTalksDev/plimsoll/internal/seal"
)

const Version = "prereg-v1"

// ResultEntry is one aggregate named in the attestation (spec §7).
type ResultEntry struct {
	MetricID  string `json:"metric_id"`
	Aggregate string `json:"aggregate"`
	Value     string `json:"value"`
}

// Document is a signed attestation. attempt_no is assigned by the log on publish.
type Document struct {
	PlimsollVersion string        `json:"plimsoll_version"`
	CanonVersion    string        `json:"canon_version"`
	SealHash        string        `json:"seal_hash"`
	CreatedAt       string        `json:"created_at"`
	NEvaluated      int           `json:"n_evaluated"`
	Results         []ResultEntry `json:"results"`
	Verdict         string        `json:"verdict"`
	Expression      string        `json:"expression"`
	Terms           []decide.Term `json:"terms"`
	Adapter         string        `json:"adapter"`
	AdapterVersion  string        `json:"adapter_version"`
	RowDigest       string        `json:"row_digest"`
	ResultDigest    string        `json:"result_digest"`
	Signature       string        `json:"signature,omitempty"`
	Reasons         []string      `json:"reasons,omitempty"`
}

// Signed bundles canonical bytes and signature.
type Signed struct {
	Document  *Document
	Canonical []byte
	Signature []byte
}

// Build constructs an attestation from evaluation output. No attempt number.
func Build(sealHash string, s *seal.Seal, rs *adapt.ResultSet, v *decide.Verdict) (*Document, error) {
	if s == nil || rs == nil || v == nil {
		return nil, fmt.Errorf("attestation: missing inputs")
	}
	doc := &Document{
		PlimsollVersion: Version,
		CanonVersion:    seal.CanonVersion,
		SealHash:        sealHash,
		CreatedAt:       time.Now().UTC().Format(time.RFC3339),
		NEvaluated:      s.Dataset.N,
		Results:         termsToResults(v.Terms),
		Verdict:         v.Result,
		Expression:      v.Expression,
		Terms:           append([]decide.Term(nil), v.Terms...),
		Adapter:         rs.Harness,
		AdapterVersion:  rs.HarnessVer,
		RowDigest:       rs.RowDigest,
		Reasons:         append([]string(nil), v.Reasons...),
	}
	digest, err := CanonicalDigest(doc)
	if err != nil {
		return nil, err
	}
	doc.ResultDigest = digest
	return doc, nil
}

func termsToResults(terms []decide.Term) []ResultEntry {
	var out []ResultEntry
	seen := map[string]struct{}{}
	for _, t := range terms {
		if t.Identifier == "" || t.Value == "" {
			continue
		}
		metricID, agg, ok := splitIdentifier(t.Identifier)
		if !ok {
			continue
		}
		key := metricID + "." + agg
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ResultEntry{
			MetricID:  metricID,
			Aggregate: agg,
			Value:     t.Value,
		})
	}
	return out
}

func splitIdentifier(id string) (metric, agg string, ok bool) {
	for i := len(id) - 1; i >= 0; i-- {
		if id[i] == '.' {
			return id[:i], id[i+1:], true
		}
	}
	return "", "", false
}

// CanonicalDigest returns sha256:<hex> of the unsigned canonical body.
func CanonicalDigest(doc *Document) (string, error) {
	b, err := canonicalBody(doc)
	if err != nil {
		return "", err
	}
	return "sha256:" + canonical.Sum256(b), nil
}

func canonicalBody(doc *Document) ([]byte, error) {
	if doc == nil {
		return nil, fmt.Errorf("attestation: nil")
	}
	unsigned := *doc
	unsigned.Signature = ""
	unsigned.ResultDigest = ""
	raw, err := json.Marshal(&unsigned)
	if err != nil {
		return nil, err
	}
	return canonical.Canonicalize(raw)
}

// Sign adds an Ed25519 signature over the canonical attestation bytes.
func Sign(doc *Document, priv ed25519.PrivateKey) (*Signed, error) {
	if doc == nil {
		return nil, fmt.Errorf("attestation: nil")
	}
	body, err := canonicalBody(doc)
	if err != nil {
		return nil, err
	}
	digest := "sha256:" + canonical.Sum256(body)
	cp := *doc
	cp.ResultDigest = digest
	sig := ed25519.Sign(priv, body)
	cp.Signature = base64.StdEncoding.EncodeToString(sig)
	return &Signed{Document: &cp, Canonical: body, Signature: sig}, nil
}

// Verify checks doc signature with pub.
func Verify(pub ed25519.PublicKey, doc *Document) error {
	if doc == nil {
		return fmt.Errorf("attestation: nil")
	}
	body, err := canonicalBody(doc)
	if err != nil {
		return err
	}
	digest := "sha256:" + canonical.Sum256(body)
	if doc.ResultDigest != digest {
		return fmt.Errorf("attestation: result_digest mismatch")
	}
	sig, err := base64.StdEncoding.DecodeString(doc.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, body, sig) {
		return fmt.Errorf("attestation: signature verification failed")
	}
	return nil
}
