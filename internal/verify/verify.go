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

//go:build !js

package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/GautamTalksDev/plimsoll/internal/attestation"
	"github.com/GautamTalksDev/plimsoll/internal/canonical"
	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/logfetch"
	"github.com/GautamTalksDev/plimsoll/internal/seal"
	"github.com/GautamTalksDev/plimsoll/internal/sealfile"
)

// Run verifies attestationPath and returns a report.
func Run(attestationPath string, opt Options) (*Report, error) {
	att, err := LoadAttestation(attestationPath)
	if err != nil {
		return nil, err
	}
	return RunDocument(att, opt)
}

// RunDocument verifies an in-memory attestation document.
func RunDocument(att *attestation.Document, opt Options) (*Report, error) {
	if att == nil {
		return nil, fmt.Errorf("verify: nil attestation")
	}
	mat, err := gatherMaterial(att, opt)
	if err != nil {
		return nil, err
	}
	return buildReport(mat, opt), nil
}

// LoadAttestation reads an attestation document from path (plain doc or plimsoll-attest-v1 envelope).
func LoadAttestation(path string) (*attestation.Document, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	att, _, err := ParseAttestationBytes(b)
	return att, err
}

func gatherMaterial(att *attestation.Document, opt Options) (*material, error) {
	if opt.BundlePath != "" {
		return materialFromBundle(opt.BundlePath, att)
	}
	if opt.Offline {
		return nil, fmt.Errorf("verify: --offline requires --bundle")
	}
	if opt.LocalLog != nil {
		return materialFromLocalLog(opt.LocalLog, opt.LogPub, att)
	}
	fc := opt.Fetch
	if fc == nil {
		if opt.LogURL == "" {
			return nil, fmt.Errorf("verify: provide --bundle or --log")
		}
		fc = logfetch.New(opt.LogURL, nil)
	}
	return materialFromHTTP(fc, att)
}

func sealDocFromRecord(r log.SealRecord) (*sealfile.Document, error) {
	var s seal.Seal
	if err := canonical.DecodeCanonical(r.Canonical, &s); err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		return nil, err
	}
	doc := &sealfile.Document{
		SealHash:  r.SealHash,
		PublicKey: r.PublicKey,
		Seal: &seal.SignedSeal{
			Seal:      &s,
			Signature: sig,
		},
	}
	idx := r.Idx
	doc.LogIndex = &idx
	return doc, nil
}

func materialFromLocalLog(l *log.Log, logPub ed25519.PublicKey, att *attestation.Document) (*material, error) {
	rec, ok, err := l.SealByHash(att.SealHash)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("verify: seal %q not in log", att.SealHash)
	}
	sealDoc, err := sealDocFromRecord(rec)
	if err != nil {
		return nil, err
	}
	pub, err := sealDoc.PublicKeyBytes()
	if err != nil {
		return nil, err
	}
	sealProof, err := l.InclusionProof(rec.Idx)
	if err != nil {
		return nil, err
	}
	sealCP, err := l.CheckpointAt(sealProof.TreeSize)
	if err != nil {
		sealCP, err = l.LatestCheckpoint()
		if err != nil {
			return nil, err
		}
	}
	storedSealProof := sealfile.StoreProof(sealProof)

	attIdx, _, attOK, err := l.AttestationByDigest(att.SealHash, att.ResultDigest)
	if err != nil {
		return nil, err
	}
	if !attOK {
		return nil, fmt.Errorf("verify: attestation not in log")
	}
	attProof, err := l.InclusionProof(attIdx)
	if err != nil {
		return nil, err
	}
	attCP, err := l.CheckpointAt(attProof.TreeSize)
	if err != nil {
		attCP, err = l.LatestCheckpoint()
		if err != nil {
			return nil, err
		}
	}
	storedAttProof := sealfile.StoreProof(attProof)

	attempts, err := l.AttemptsForSeal(att.SealHash)
	if err != nil {
		return nil, err
	}
	var attSubmitted int64
	for _, a := range attempts {
		if a.ResultDigest == att.ResultDigest {
			attSubmitted = a.SubmittedAt
			break
		}
	}

	latest, err := l.LatestCheckpoint()
	if err != nil {
		return nil, fmt.Errorf("verify: latest checkpoint: %w", err)
	}
	var consistency *logfetch.ConsistencyResponse
	if attCP.TreeSize < latest.TreeSize {
		cp, err := l.ConsistencyProof(attCP.TreeSize, latest.TreeSize)
		if err != nil {
			return nil, err
		}
		audit := make([][]byte, len(cp.AuditPath))
		for i, h := range cp.AuditPath {
			audit[i] = append([]byte(nil), h...)
		}
		consistency = &logfetch.ConsistencyResponse{
			OldSize: cp.OldSize, NewSize: cp.NewSize,
			OldRoot: cp.OldRoot, NewRoot: cp.NewRoot, AuditPath: audit,
		}
	}

	sealDoc.InclusionProof = &storedSealProof
	sealDoc.Checkpoint = &sealCP

	return &material{
		pub: pub, logPub: logPub,
		sealDoc: sealDoc, att: att,
		sealProof: &storedSealProof, sealCP: &sealCP,
		attProof: &storedAttProof, attCP: &attCP,
		attempts: attempts, latestCP: &latest, consistency: consistency,
		sealSubmitted: rec.SubmittedAt, attSubmitted: attSubmitted,
	}, nil
}

func materialFromHTTP(fc *logfetch.Client, att *attestation.Document) (*material, error) {
	sr, err := fc.Seal(att.SealHash)
	if err != nil {
		return nil, err
	}
	rec := log.SealRecord{
		Idx: sr.Idx, SealHash: sr.SealHash, Canonical: sr.Canonical,
		SubmittedAt: sr.SubmittedAt, Supersedes: sr.Supersedes, LeafHash: sr.LeafHash,
		Signature: sr.Signature, PublicKey: sr.PublicKey,
	}
	sealDoc, err := sealDocFromRecord(rec)
	if err != nil {
		return nil, err
	}
	pub, err := sealDoc.PublicKeyBytes()
	if err != nil {
		return nil, err
	}

	sealEntry, err := fc.EntryInclusionProof(sr.Idx)
	if err != nil {
		return nil, err
	}
	attIdx, attSubmitted, attOK, err := findAttestationIndex(fc, att)
	if err != nil {
		return nil, err
	}
	if !attOK {
		return nil, fmt.Errorf("verify: attestation not in log")
	}
	attEntry, err := fc.EntryInclusionProof(attIdx)
	if err != nil {
		return nil, err
	}
	attempts, err := fc.Attempts(att.SealHash)
	if err != nil {
		return nil, err
	}
	latest, err := fc.LatestCheckpoint()
	if err != nil {
		return nil, err
	}
	var consistency *logfetch.ConsistencyResponse
	if attEntry.Checkpoint.TreeSize < latest.Checkpoint.TreeSize {
		consistency, err = fc.Consistency(attEntry.Checkpoint.TreeSize, latest.Checkpoint.TreeSize)
		if err != nil {
			return nil, err
		}
	}
	sealDoc.InclusionProof = &sealEntry.InclusionProof
	sealDoc.Checkpoint = &sealEntry.Checkpoint

	return &material{
		pub: pub, logPub: latest.LogPublicKey,
		sealDoc: sealDoc, att: att,
		sealProof: &sealEntry.InclusionProof, sealCP: &sealEntry.Checkpoint,
		attProof: &attEntry.InclusionProof, attCP: &attEntry.Checkpoint,
		attempts: attempts, latestCP: &latest.Checkpoint, consistency: consistency,
		sealSubmitted: sr.SubmittedAt, attSubmitted: attSubmitted,
	}, nil
}

func findAttestationIndex(fc *logfetch.Client, att *attestation.Document) (idx int64, submitted int64, ok bool, err error) {
	attempts, err := fc.Attempts(att.SealHash)
	if err != nil {
		return 0, 0, false, err
	}
	for _, a := range attempts {
		if a.ResultDigest == att.ResultDigest {
			return a.Idx, a.SubmittedAt, true, nil
		}
	}
	return 0, 0, false, nil
}
