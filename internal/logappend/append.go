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

// Package logappend validates and appends submit payloads for the public
// static log. This is the Action trust boundary: the Worker is not trusted.
package logappend

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/GautamTalksDev/plimsoll/internal/attestation"
	"github.com/GautamTalksDev/plimsoll/internal/canonical"
	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/payload"
	"github.com/GautamTalksDev/plimsoll/internal/seal"
)

var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Kind is the machine-readable append kind for commit messages.
type Kind string

const (
	KindSeal        Kind = "seal"
	KindAttestation Kind = "attestation"
)

// Result is emitted after a successful append. Fields are constrained so
// they are safe for commit messages (no attacker-controlled free text).
type Result struct {
	Kind Kind
	Hash string // seal_hash or result_digest; matches digestRe
	Idx  int64
}

// CommitMessage returns "append: {kind} {hash} idx={n}" with no free text.
func (r Result) CommitMessage() string {
	return fmt.Sprintf("append: %s %s idx=%d", r.Kind, r.Hash, r.Idx)
}

// Append validates body then appends to l and signs a checkpoint with priv.
func Append(l *log.Log, priv ed25519.PrivateKey, body []byte) (Result, error) {
	kind, err := payload.AssertSubmit(body)
	if err != nil {
		return Result{}, err
	}
	switch kind {
	case payload.SubmitSeal:
		return appendSeal(l, priv, body)
	case payload.SubmitAttestation:
		return appendAttestation(l, priv, body)
	default:
		return Result{}, fmt.Errorf("logappend: unrecognized submit kind")
	}
}

func appendSeal(l *log.Log, priv ed25519.PrivateKey, body []byte) (Result, error) {
	var in struct {
		SealHash     string `json:"seal_hash"`
		CanonicalB64 string `json:"canonical_b64"`
		SubmitterID  string `json:"submitter_id"`
		SubmittedAt  int64  `json:"submitted_at"`
		Supersedes   string `json:"supersedes"`
		SignatureB64 string `json:"signature_b64"`
		PublicKeyB64 string `json:"public_key_b64"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return Result{}, fmt.Errorf("logappend: seal json: %w", err)
	}
	if !digestRe.MatchString(in.SealHash) {
		return Result{}, fmt.Errorf("logappend: invalid seal_hash format")
	}
	canonicalBytes, err := base64.StdEncoding.DecodeString(in.CanonicalB64)
	if err != nil {
		return Result{}, fmt.Errorf("logappend: canonical_b64: %w", err)
	}
	if !strings.HasPrefix(string(canonicalBytes), canonical.CanonVersionPrefix) {
		return Result{}, fmt.Errorf("logappend: unknown or missing canon_version prefix")
	}
	gotHash := "sha256:" + canonical.Sum256(canonicalBytes)
	if gotHash != in.SealHash {
		return Result{}, fmt.Errorf("logappend: seal_hash does not match canonical bytes")
	}
	pub, err := decodePub(in.PublicKeyB64)
	if err != nil {
		return Result{}, err
	}
	sig, err := base64.StdEncoding.DecodeString(in.SignatureB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Result{}, fmt.Errorf("logappend: invalid signature_b64")
	}
	if !ed25519.Verify(pub, canonicalBytes, sig) {
		return Result{}, fmt.Errorf("logappend: seal signature verification failed")
	}
	var s seal.Seal
	if err := canonical.DecodeCanonical(canonicalBytes, &s); err != nil {
		return Result{}, fmt.Errorf("logappend: decode seal: %w", err)
	}
	if s.CanonVersion != seal.CanonVersion {
		return Result{}, fmt.Errorf("logappend: canon_version %q not known", s.CanonVersion)
	}
	if s.PlimsollVersion != seal.Version {
		return Result{}, fmt.Errorf("logappend: plimsoll_version %q not known", s.PlimsollVersion)
	}
	if in.SubmittedAt == 0 {
		in.SubmittedAt = time.Now().Unix()
	}
	idx, err := l.AppendSeal(log.SealInput{
		SealHash: in.SealHash, Canonical: canonicalBytes, SubmitterID: in.SubmitterID,
		SubmittedAt: in.SubmittedAt, Supersedes: in.Supersedes,
		Signature: in.SignatureB64, PublicKey: in.PublicKeyB64,
	})
	if err != nil {
		return Result{}, err
	}
	if _, err := l.SignCheckpoint(priv); err != nil {
		return Result{}, err
	}
	return Result{Kind: KindSeal, Hash: in.SealHash, Idx: idx}, nil
}

func appendAttestation(l *log.Log, priv ed25519.PrivateKey, body []byte) (Result, error) {
	var in struct {
		SealHash     string `json:"seal_hash"`
		ResultDigest string `json:"result_digest"`
		Verdict      string `json:"verdict"`
		CanonicalB64 string `json:"canonical_b64"`
		SignatureB64 string `json:"signature_b64"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return Result{}, fmt.Errorf("logappend: attestation json: %w", err)
	}
	if !digestRe.MatchString(in.SealHash) {
		return Result{}, fmt.Errorf("logappend: invalid seal_hash format")
	}
	if !digestRe.MatchString(in.ResultDigest) {
		return Result{}, fmt.Errorf("logappend: invalid result_digest format")
	}
	canonicalBytes, err := base64.StdEncoding.DecodeString(in.CanonicalB64)
	if err != nil {
		return Result{}, fmt.Errorf("logappend: canonical_b64: %w", err)
	}
	if !strings.HasPrefix(string(canonicalBytes), canonical.CanonVersionPrefix) {
		return Result{}, fmt.Errorf("logappend: unknown or missing canon_version prefix")
	}
	gotDigest := "sha256:" + canonical.Sum256(canonicalBytes)
	if gotDigest != in.ResultDigest {
		return Result{}, fmt.Errorf("logappend: result_digest does not match canonical bytes")
	}
	rec, ok, err := l.SealByHash(in.SealHash)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{}, fmt.Errorf("logappend: seal %s not in log", in.SealHash)
	}
	pub, err := decodePub(rec.PublicKey)
	if err != nil {
		return Result{}, fmt.Errorf("logappend: seal public key: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(in.SignatureB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Result{}, fmt.Errorf("logappend: invalid signature_b64")
	}
	if !ed25519.Verify(pub, canonicalBytes, sig) {
		return Result{}, fmt.Errorf("logappend: attestation signature verification failed")
	}
	var doc attestation.Document
	if err := canonical.DecodeCanonical(canonicalBytes, &doc); err != nil {
		return Result{}, fmt.Errorf("logappend: decode attestation: %w", err)
	}
	if doc.CanonVersion != seal.CanonVersion {
		return Result{}, fmt.Errorf("logappend: canon_version %q not known", doc.CanonVersion)
	}
	if doc.SealHash != in.SealHash {
		return Result{}, fmt.Errorf("logappend: attestation seal_hash mismatch")
	}
	verdict := strings.ToLower(strings.TrimSpace(in.Verdict))
	switch verdict {
	case "pass", "fail", "invalid":
	default:
		return Result{}, fmt.Errorf("logappend: invalid verdict %q", in.Verdict)
	}
	idx, err := l.AppendAttestation(log.AttestationInput{
		SealHash: in.SealHash, ResultDigest: in.ResultDigest,
		Verdict: verdict, Canonical: canonicalBytes,
	})
	if err != nil {
		return Result{}, err
	}
	if _, err := l.SignCheckpoint(priv); err != nil {
		return Result{}, err
	}
	return Result{Kind: KindAttestation, Hash: in.ResultDigest, Idx: idx}, nil
}

func decodePub(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("logappend: public_key_b64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("logappend: public key size %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}
