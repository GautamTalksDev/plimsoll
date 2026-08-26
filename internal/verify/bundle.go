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

package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/GautamTalksDev/plimsoll/internal/attestation"
	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/logfetch"
	"github.com/GautamTalksDev/plimsoll/internal/logmerkle"
)

// BuildAttestEnvelope assembles a plimsoll-attest-v1 envelope after publish.
func BuildAttestEnvelope(l *log.Log, logPub ed25519.PublicKey, att *attestation.Document) (*AttestEnvelope, error) {
	mat, err := materialFromLocalLog(l, logPub, att)
	if err != nil {
		return nil, err
	}
	env := &AttestEnvelope{
		Version:                   AttestEnvelopeVersion,
		LogPublicKey:              base64.StdEncoding.EncodeToString(logPub),
		Attestation:               *att,
		Seal:                      *mat.sealDoc,
		AttestationInclusionProof: *mat.attProof,
		AttestationCheckpoint:     cpToJSON(*mat.attCP),
		Attempts:                  toMerkleAttempts(mat.attempts),
	}
	if mat.latestCP != nil {
		j := cpToJSON(*mat.latestCP)
		env.LatestCheckpoint = &j
	}
	if mat.consistency != nil {
		audit := make([]string, len(mat.consistency.AuditPath))
		for i, h := range mat.consistency.AuditPath {
			audit[i] = fmt.Sprintf("%x", h)
		}
		env.Consistency = &consistencyJSON{
			OldSize: mat.consistency.OldSize, NewSize: mat.consistency.NewSize,
			OldRoot: fmt.Sprintf("%x", mat.consistency.OldRoot),
			NewRoot: fmt.Sprintf("%x", mat.consistency.NewRoot),
			AuditPath: audit,
		}
	}
	return env, nil
}

// BuildAttestEnvelopeHTTP assembles an envelope using a remote log (post-publish).
func BuildAttestEnvelopeHTTP(baseURL string, att *attestation.Document) (*AttestEnvelope, error) {
	fc := logfetch.New(baseURL, nil)
	mat, err := materialFromHTTP(fc, att)
	if err != nil {
		return nil, err
	}
	env := &AttestEnvelope{
		Version:                   AttestEnvelopeVersion,
		LogPublicKey:              base64.StdEncoding.EncodeToString(mat.logPub),
		Attestation:               *att,
		Seal:                      *mat.sealDoc,
		AttestationInclusionProof: *mat.attProof,
		AttestationCheckpoint:     cpToJSON(*mat.attCP),
		Attempts:                  toMerkleAttempts(mat.attempts),
	}
	if mat.latestCP != nil {
		j := cpToJSON(*mat.latestCP)
		env.LatestCheckpoint = &j
	}
	if mat.consistency != nil {
		audit := make([]string, len(mat.consistency.AuditPath))
		for i, h := range mat.consistency.AuditPath {
			audit[i] = fmt.Sprintf("%x", h)
		}
		env.Consistency = &consistencyJSON{
			OldSize: mat.consistency.OldSize, NewSize: mat.consistency.NewSize,
			OldRoot: fmt.Sprintf("%x", mat.consistency.OldRoot),
			NewRoot: fmt.Sprintf("%x", mat.consistency.NewRoot),
			AuditPath: audit,
		}
	}
	return env, nil
}

func toMerkleAttempts(in []log.Attempt) []logmerkle.Attempt {
	out := make([]logmerkle.Attempt, len(in))
	for i, a := range in {
		out[i] = logmerkle.Attempt(a)
	}
	return out
}

// LoadBundle reads a verification bundle from path.
func LoadBundle(path string) (*Bundle, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var bundle Bundle
	if err := json.Unmarshal(b, &bundle); err != nil {
		return nil, fmt.Errorf("verify: parse bundle: %w", err)
	}
	if bundle.Version != BundleVersion {
		return nil, fmt.Errorf("verify: unsupported bundle version %q", bundle.Version)
	}
	return &bundle, nil
}

// WriteBundle writes bundle to path.
func WriteBundle(path string, b *Bundle) error {
	if b.Version == "" {
		b.Version = BundleVersion
	}
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644) //nolint:gosec // G306 -- public offline verify bundle
}

// BuildBundleFromLog assembles a bundle for offline verification.
func BuildBundleFromLog(l *log.Log, logPub ed25519.PublicKey, att *attestation.Document) (*Bundle, error) {
	mat, err := materialFromLocalLog(l, logPub, att)
	if err != nil {
		return nil, err
	}
	b := &Bundle{
		Version:                   BundleVersion,
		LogPublicKey:              base64.StdEncoding.EncodeToString(logPub),
		Seal:                      *mat.sealDoc,
		Attestation:               *att,
		SealInclusionProof:        *mat.sealProof,
		SealCheckpoint:            cpToJSON(*mat.sealCP),
		AttestationInclusionProof:   *mat.attProof,
		AttestationCheckpoint:     cpToJSON(*mat.attCP),
		Attempts:                  mat.attempts,
	}
	if mat.latestCP != nil {
		j := cpToJSON(*mat.latestCP)
		b.LatestCheckpoint = &j
	}
	if mat.consistency != nil {
		audit := make([]string, len(mat.consistency.AuditPath))
		for i, h := range mat.consistency.AuditPath {
			audit[i] = fmt.Sprintf("%x", h)
		}
		b.Consistency = &consistencyJSON{
			OldSize: mat.consistency.OldSize, NewSize: mat.consistency.NewSize,
			OldRoot: fmt.Sprintf("%x", mat.consistency.OldRoot),
			NewRoot: fmt.Sprintf("%x", mat.consistency.NewRoot),
			AuditPath: audit,
		}
	}
	return b, nil
}

func materialFromBundle(path string, att *attestation.Document) (*material, error) {
	b, err := LoadBundle(path)
	if err != nil {
		return nil, err
	}
	if b.Attestation.ResultDigest != att.ResultDigest {
		return nil, fmt.Errorf("verify: attestation file does not match bundle")
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
		attempts: b.Attempts,
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
