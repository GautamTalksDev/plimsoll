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

package verify

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/GautamTalksDev/plimsoll/internal/attestation"
	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/logfetch"
	"github.com/GautamTalksDev/plimsoll/internal/logmerkle"
	"github.com/GautamTalksDev/plimsoll/internal/sealfile"
)

const AttestEnvelopeVersion = "plimsoll-attest-v1"

// DefaultVerifierURL is the public browser verifier base path.
const DefaultVerifierURL = "https://plimsoll.gautamkhosla.com/verify"

// AttestEnvelope is a published attestation with embedded log proofs (one checkpoint fetch for V9).
type AttestEnvelope struct {
	Version                   string                        `json:"version"`
	LogPublicKey              string                        `json:"log_public_key"`
	Attestation               attestation.Document          `json:"attestation"`
	Seal                      sealfile.Document             `json:"seal"`
	AttestationInclusionProof sealfile.StoredInclusionProof `json:"attestation_inclusion_proof"`
	AttestationCheckpoint     checkpointJSON                `json:"attestation_checkpoint"`
	Attempts                  []logmerkle.Attempt           `json:"attempts"`
	LatestCheckpoint          *checkpointJSON               `json:"latest_checkpoint,omitempty"`
	Consistency               *consistencyJSON              `json:"consistency,omitempty"`
}

// VerifyURL returns a browser verifier link for an attestation result digest.
func VerifyURL(verifierBase, logURL, resultDigest string) string {
	base := strings.TrimRight(verifierBase, "/")
	if base == "" {
		base = DefaultVerifierURL
	}
	q := "log=" + urlEncode(strings.TrimRight(logURL, "/"))
	if resultDigest != "" {
		q += "&digest=" + urlEncode(resultDigest)
	}
	return base + "?" + q
}

func urlEncode(s string) string {
	return strings.ReplaceAll(s, ":", "%3A")
}

// ParseAttestationBytes reads an attestation from JSON bytes (plain, wrapped, or envelope).
func ParseAttestationBytes(b []byte) (*attestation.Document, *AttestEnvelope, error) {
	var env AttestEnvelope
	if err := json.Unmarshal(b, &env); err == nil && env.Version == AttestEnvelopeVersion && env.Attestation.SealHash != "" {
		return &env.Attestation, &env, nil
	}
	var wrap struct {
		Attestation *attestation.Document `json:"attestation"`
	}
	if err := json.Unmarshal(b, &wrap); err == nil && wrap.Attestation != nil {
		return wrap.Attestation, nil, nil
	}
	var doc attestation.Document
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, nil, fmt.Errorf("verify: parse attestation: %w", err)
	}
	if doc.SealHash == "" {
		return nil, nil, fmt.Errorf("verify: not an attestation document")
	}
	return &doc, nil, nil
}

// ParseBundleBytes reads an offline verification bundle from JSON bytes.
func ParseBundleBytes(b []byte) (*Bundle, error) {
	var bundle Bundle
	if err := json.Unmarshal(b, &bundle); err != nil {
		return nil, fmt.Errorf("verify: parse bundle: %w", err)
	}
	if bundle.Version != BundleVersion {
		return nil, fmt.Errorf("verify: unsupported bundle version %q", bundle.Version)
	}
	return &bundle, nil
}

// RunBrowser verifies using attestation JSON and optional bundle or latest checkpoint JSON.
// For offline mode pass bundleJSON; for online envelope mode pass latestCheckpointJSON only.
func RunBrowser(attJSON, bundleJSON, latestCheckpointJSON string, offline bool) (*Report, error) {
	att, env, err := ParseAttestationBytes([]byte(attJSON))
	if err != nil {
		return nil, err
	}
	var mat *material
	if bundleJSON != "" {
		b, err := ParseBundleBytes([]byte(bundleJSON))
		if err != nil {
			return nil, err
		}
		mat, err = materialFromBundleStruct(b, att)
		if err != nil {
			return nil, err
		}
		opt := Options{Offline: offline, SkipV9: offline && b.LatestCheckpoint == nil}
		return buildReport(mat, opt), nil
	}
	if env == nil {
		return nil, fmt.Errorf("verify: provide a verification bundle or a published attestation envelope (plimsoll-attest-v1)")
	}
	mat, err = materialFromEnvelope(env, att)
	if err != nil {
		return nil, err
	}
	opt := Options{Offline: false}
	if latestCheckpointJSON != "" {
		var cp checkpointJSON
		if err := json.Unmarshal([]byte(latestCheckpointJSON), &cp); err != nil {
			return nil, err
		}
		latest := cpFromJSON(cp)
		mat.latestCP = &latest
		if mat.attCP != nil && mat.attCP.TreeSize == latest.TreeSize && mat.attCP.RootHash == latest.RootHash {
			// V9: attestation checkpoint is still the log head — one fetch is enough.
		} else if env.Consistency != nil && env.LatestCheckpoint != nil {
			envLatest := cpFromJSON(*env.LatestCheckpoint)
			if envLatest.TreeSize == latest.TreeSize && envLatest.RootHash == latest.RootHash {
				mat.consistency = consistencyFromJSON(env.Consistency)
			}
		}
	} else if env.LatestCheckpoint != nil {
		latest := cpFromJSON(*env.LatestCheckpoint)
		mat.latestCP = &latest
		if env.Consistency != nil {
			mat.consistency = consistencyFromJSON(env.Consistency)
		}
		opt.Offline = true
		opt.SkipV9 = false
	}
	return buildReport(mat, opt), nil
}

func consistencyFromJSON(c *consistencyJSON) *logfetch.ConsistencyResponse {
	if c == nil {
		return nil
	}
	cr := &logfetch.ConsistencyResponse{OldSize: c.OldSize, NewSize: c.NewSize}
	cr.OldRoot, _ = decodeHex(c.OldRoot)
	cr.NewRoot, _ = decodeHex(c.NewRoot)
	for _, h := range c.AuditPath {
		bh, _ := decodeHex(h)
		cr.AuditPath = append(cr.AuditPath, bh)
	}
	return cr
}

func materialFromBundleStruct(b *Bundle, att *attestation.Document) (*material, error) {
	if b.Attestation.ResultDigest != att.ResultDigest {
		return nil, fmt.Errorf("verify: attestation does not match bundle")
	}
	logPub, err := base64.StdEncoding.DecodeString(b.LogPublicKey)
	if err != nil {
		return nil, err
	}
	sealDoc := b.Seal
	pub, err := sealDoc.PublicKeyBytes()
	if err != nil {
		return nil, err
	}
	sealCP := cpFromJSON(b.SealCheckpoint)
	attCP := cpFromJSON(b.AttestationCheckpoint)
	mat := &material{
		pub: pub, logPub: logPub,
		sealDoc: &sealDoc, att: att,
		sealProof: &b.SealInclusionProof, sealCP: &sealCP,
		attProof: &b.AttestationInclusionProof, attCP: &attCP,
		attempts: toLogAttempts(b.Attempts),
	}
	if b.LatestCheckpoint != nil {
		cp := cpFromJSON(*b.LatestCheckpoint)
		mat.latestCP = &cp
	}
	if b.Consistency != nil {
		mat.consistency = &logfetch.ConsistencyResponse{
			OldSize: b.Consistency.OldSize, NewSize: b.Consistency.NewSize,
		}
		mat.consistency.OldRoot, _ = decodeHex(b.Consistency.OldRoot)
		mat.consistency.NewRoot, _ = decodeHex(b.Consistency.NewRoot)
		for _, h := range b.Consistency.AuditPath {
			bh, _ := decodeHex(h)
			mat.consistency.AuditPath = append(mat.consistency.AuditPath, bh)
		}
	}
	return mat, nil
}

func materialFromEnvelope(env *AttestEnvelope, att *attestation.Document) (*material, error) {
	logPub, err := base64.StdEncoding.DecodeString(env.LogPublicKey)
	if err != nil {
		return nil, err
	}
	sealDoc := env.Seal
	pub, err := sealDoc.PublicKeyBytes()
	if err != nil {
		return nil, err
	}
	attCP := cpFromJSON(env.AttestationCheckpoint)
	mat := &material{
		pub: pub, logPub: logPub,
		sealDoc: &sealDoc, att: att,
		sealProof: sealDoc.InclusionProof, sealCP: sealDoc.Checkpoint,
		attProof: &env.AttestationInclusionProof, attCP: &attCP,
		attempts: toLogAttempts(env.Attempts),
	}
	if sealDoc.InclusionProof != nil && sealDoc.Checkpoint != nil {
		mat.sealProof = sealDoc.InclusionProof
		mat.sealCP = sealDoc.Checkpoint
	}
	return mat, nil
}

func toLogAttempts(in []logmerkle.Attempt) []log.Attempt {
	out := make([]log.Attempt, len(in))
	for i, a := range in {
		out[i] = log.Attempt(a)
	}
	return out
}

// ReportJSON marshals a verification report.
func ReportJSON(r *Report) ([]byte, error) {
	return json.Marshal(r)
}

// ParseCheckpointResponse parses a flat /checkpoint HTTP response body.
func ParseCheckpointResponse(b []byte) (logmerkle.Checkpoint, []byte, error) {
	var raw struct {
		TreeSize     int64  `json:"tree_size"`
		RootHash     string `json:"root_hash"`
		Timestamp    int64  `json:"timestamp"`
		Signature    string `json:"signature"`
		LogPublicKey string `json:"log_public_key"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return logmerkle.Checkpoint{}, nil, err
	}
	pub, err := base64.StdEncoding.DecodeString(raw.LogPublicKey)
	if err != nil {
		return logmerkle.Checkpoint{}, nil, err
	}
	return logmerkle.Checkpoint{
		TreeSize: raw.TreeSize, RootHash: raw.RootHash,
		Timestamp: raw.Timestamp, Signature: raw.Signature,
	}, pub, nil
}

// ConsistencyFromCheckpoint compares attestation checkpoint to latest; returns nil if same size.
func ConsistencyFromCheckpoint(attCP, latest logmerkle.Checkpoint) *logfetch.ConsistencyResponse {
	if attCP.TreeSize >= latest.TreeSize {
		return nil
	}
	oldRoot, _ := hex.DecodeString(attCP.RootHash)
	newRoot, _ := hex.DecodeString(latest.RootHash)
	return &logfetch.ConsistencyResponse{
		OldSize: attCP.TreeSize, NewSize: latest.TreeSize,
		OldRoot: oldRoot, NewRoot: newRoot,
	}
}
