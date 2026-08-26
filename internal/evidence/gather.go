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

package evidence

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/GautamTalksDev/plimsoll/internal/attestation"
	"github.com/GautamTalksDev/plimsoll/internal/canonical"
	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/logfetch"
	"github.com/GautamTalksDev/plimsoll/internal/seal"
	"github.com/GautamTalksDev/plimsoll/internal/sealfile"
	"github.com/GautamTalksDev/plimsoll/internal/verify"
)

// Options configures evidence pack generation.
type Options struct {
	SealRef            string
	LogURL             string
	LocalLog           *log.Log
	LogPub             ed25519.PublicKey
	BrowserVerifierURL string
	AttestDir          string
}

// Build assembles a self-contained evidence pack for one seal.
func Build(opt Options) (*Pack, error) {
	sealHash, _, err := resolveSealRef(opt.SealRef)
	if err != nil {
		return nil, err
	}
	if opt.AttestDir == "" {
		if fi, statErr := os.Stat(opt.SealRef); statErr == nil && !fi.IsDir() {
			opt.AttestDir = filepath.Dir(opt.SealRef)
		}
	}
	src, err := openSource(opt)
	if err != nil {
		return nil, err
	}
	defer src.close()

	rec, sealDoc, err := src.seal(sealHash)
	if err != nil {
		return nil, err
	}
	yamlText, err := preregYAML(sealDoc)
	if err != nil {
		return nil, err
	}
	sealProof, sealCP, err := src.inclusion(rec.Idx)
	if err != nil {
		return nil, err
	}
	attempts, err := src.attempts(sealHash)
	if err != nil {
		return nil, err
	}
	localAtts, _ := loadLocalAttestations(opt.AttestDir, sealHash)

	latestCP, logPub, err := src.latestCheckpoint()
	if err != nil {
		return nil, err
	}
	if len(logPub) == 0 && len(opt.LogPub) > 0 {
		logPub = opt.LogPub
	}
	generatedAt := latestCP.Timestamp
	if generatedAt == 0 {
		generatedAt = rec.SubmittedAt
	}

	browserURL := opt.BrowserVerifierURL
	if browserURL == "" {
		browserURL = verify.DefaultVerifierURL
	} else if !strings.HasPrefix(browserURL, "http") {
		browserURL = verify.DefaultVerifierURL
	}
	verifyBase := browserURL
	if opt.LogURL != "" && !strings.Contains(browserURL, "/verify") {
		verifyBase = strings.TrimRight(opt.LogURL, "/") + "/verify"
	}

	var attemptRecords []AttemptRecord
	for _, a := range attempts {
		doc, attJSON, err := src.attestationDoc(a, localAtts)
		if err != nil {
			return nil, fmt.Errorf("attempt %d: %w", a.AttemptNo, err)
		}
		attProof, attCP, err := src.inclusion(a.Idx)
		if err != nil {
			return nil, err
		}
		vopt := verify.Options{LocalLog: src.localLog(), LogPub: logPub}
		if src.http != nil {
			vopt.Fetch = src.http
			vopt.LogURL = opt.LogURL
		}
		report, err := verify.RunDocument(doc, vopt)
		if err != nil {
			return nil, fmt.Errorf("verify attempt %d: %w", a.AttemptNo, err)
		}
		attemptRecords = append(attemptRecords, AttemptRecord{
			AttemptNo:    a.AttemptNo,
			SubmittedAt:  a.SubmittedAt,
			Verdict:      strings.ToUpper(a.Verdict),
			ResultDigest: a.ResultDigest,
			Attestation:  attJSON,
			Inclusion: InclusionRecord{
				LogIndex: a.Idx, SubmittedAt: a.SubmittedAt,
				Proof: attProof, Checkpoint: attCP,
			},
			Verification: *report,
			VerifyURL:    verify.VerifyURL(verifyBase, opt.LogURL, a.ResultDigest),
		})
	}

	chain, err := buildSupersedeChain(src, sealHash)
	if err != nil {
		return nil, err
	}

	return &Pack{
		Version:            Version,
		GeneratedAt:        generatedAt,
		LogURL:             opt.LogURL,
		LogPublicKey:       base64.StdEncoding.EncodeToString(logPub),
		BrowserVerifierURL: browserURL,
		VerifyURL:          verify.VerifyURL(verifyBase, opt.LogURL, ""),
		SealHash:           sealHash,
		Preregistration: Preregistration{
			YAML: yamlText, SealDocument: sealDoc,
		},
		SealInclusion: InclusionRecord{
			LogIndex: rec.Idx, SubmittedAt: rec.SubmittedAt,
			Proof: sealProof, Checkpoint: sealCP,
		},
		Attempts:       attemptRecords,
		SupersedeChain: chain,
		Instructions:   Instructions(opt.LogURL, verifyBase),
	}, nil
}

func resolveSealRef(ref string) (hash string, doc *sealfile.Document, err error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", nil, fmt.Errorf("evidence: seal reference required")
	}
	if strings.HasPrefix(ref, "sha256:") {
		return ref, nil, nil
	}
	if fi, statErr := os.Stat(ref); statErr == nil && !fi.IsDir() {
		doc, err = sealfile.Read(ref)
		if err != nil {
			return "", nil, err
		}
		if doc.SealHash == "" {
			return "", nil, fmt.Errorf("evidence: seal file missing seal_hash")
		}
		return doc.SealHash, doc, nil
	}
	if !strings.Contains(ref, ":") {
		ref = "sha256:" + ref
	}
	return ref, nil, nil
}

func preregYAML(doc *sealfile.Document) (string, error) {
	if doc == nil || doc.Seal == nil || doc.Seal.Seal == nil {
		return "", fmt.Errorf("evidence: missing seal document")
	}
	s := doc.Seal.Seal
	b, err := yaml.Marshal(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func loadLocalAttestations(dir, sealHash string) ([]*attestation.Document, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []*attestation.Document
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".attest.json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		doc, err := verify.LoadAttestation(path)
		if err != nil {
			continue
		}
		if doc.SealHash == sealHash {
			out = append(out, doc)
		}
	}
	return out, nil
}

func attestationFromLog(canonical []byte, attempt log.Attempt, locals []*attestation.Document) (*attestation.Document, json.RawMessage, error) {
	doc, err := documentFromLogCanonical(canonical, attempt.ResultDigest)
	if err != nil {
		return nil, nil, err
	}
	for _, local := range locals {
		if local.ResultDigest == attempt.ResultDigest {
			doc.Signature = local.Signature
			break
		}
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, nil, err
	}
	return doc, raw, nil
}

func documentFromLogCanonical(b []byte, resultDigest string) (*attestation.Document, error) {
	var doc attestation.Document
	if err := canonical.DecodeCanonical(b, &doc); err != nil {
		if err2 := json.Unmarshal(b, &doc); err2 != nil {
			return nil, fmt.Errorf("evidence: parse attestation canonical: %w", err)
		}
	}
	doc.ResultDigest = resultDigest
	return &doc, nil
}

type source struct {
	http *logfetch.Client
	l    *log.Log
	pub  ed25519.PublicKey
}

func (s *source) close() {
	if s.l != nil {
		_ = s.l.Close()
	}
}

func (s *source) localLog() *log.Log {
	return s.l
}

func openSource(opt Options) (*source, error) {
	if opt.LocalLog != nil {
		return &source{l: opt.LocalLog, pub: opt.LogPub}, nil
	}
	if opt.LogURL == "" {
		return nil, fmt.Errorf("evidence: provide --log URL or --log-db path")
	}
	fc := logfetch.New(opt.LogURL, nil)
	latest, err := fc.LatestCheckpoint()
	if err != nil {
		return nil, err
	}
	return &source{http: fc, pub: latest.LogPublicKey}, nil
}

func (s *source) seal(sealHash string) (log.SealRecord, *sealfile.Document, error) {
	if s.l != nil {
		rec, ok, err := s.l.SealByHash(sealHash)
		if err != nil {
			return log.SealRecord{}, nil, err
		}
		if !ok {
			return log.SealRecord{}, nil, fmt.Errorf("evidence: seal %q not in log", sealHash)
		}
		doc, err := sealDocFromRecord(rec)
		return rec, doc, err
	}
	sr, err := s.http.Seal(sealHash)
	if err != nil {
		return log.SealRecord{}, nil, err
	}
	rec := sealRecordFromHTTP(sr)
	doc, err := sealDocFromRecord(rec)
	return rec, doc, err
}

func sealRecordFromHTTP(sr *logfetch.SealResponse) log.SealRecord {
	return log.SealRecord{
		Idx: sr.Idx, SealHash: sr.SealHash, Canonical: sr.Canonical,
		SubmittedAt: sr.SubmittedAt, Supersedes: sr.Supersedes,
		LeafHash: sr.LeafHash, Signature: sr.Signature, PublicKey: sr.PublicKey,
	}
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
		SealHash: r.SealHash, PublicKey: r.PublicKey,
		Seal: &seal.SignedSeal{Seal: &s, Signature: sig},
	}
	idx := r.Idx
	doc.LogIndex = &idx
	return doc, nil
}

func (s *source) attempts(sealHash string) ([]log.Attempt, error) {
	if s.l != nil {
		return s.l.AttemptsForSeal(sealHash)
	}
	return s.http.Attempts(sealHash)
}

func (s *source) inclusion(idx int64) (sealfile.StoredInclusionProof, log.Checkpoint, error) {
	if s.l != nil {
		proof, err := s.l.InclusionProof(idx)
		if err != nil {
			return sealfile.StoredInclusionProof{}, log.Checkpoint{}, err
		}
		cp, err := s.l.CheckpointAt(proof.TreeSize)
		if err != nil {
			cp, err = s.l.LatestCheckpoint()
			if err != nil {
				return sealfile.StoredInclusionProof{}, log.Checkpoint{}, err
			}
		}
		return sealfile.StoreProof(proof), cp, nil
	}
	entry, err := s.http.EntryInclusionProof(idx)
	if err != nil {
		return sealfile.StoredInclusionProof{}, log.Checkpoint{}, err
	}
	return entry.InclusionProof, entry.Checkpoint, nil
}

func (s *source) attestationDoc(a log.Attempt, locals []*attestation.Document) (*attestation.Document, json.RawMessage, error) {
	var canonical []byte
	if s.l != nil {
		b, err := s.l.CanonicalAt(a.Idx)
		if err != nil {
			return nil, nil, err
		}
		canonical = b
	} else {
		entry, err := s.http.EntryAt(a.Idx)
		if err != nil {
			return nil, nil, err
		}
		canonical, err = base64.StdEncoding.DecodeString(entry.CanonicalB64)
		if err != nil {
			return nil, nil, err
		}
	}
	return attestationFromLog(canonical, a, locals)
}

func (s *source) latestCheckpoint() (log.Checkpoint, []byte, error) {
	if s.l != nil {
		cp, err := s.l.LatestCheckpoint()
		if err != nil {
			return log.Checkpoint{}, s.pub, err
		}
		return cp, s.pub, nil
	}
	latest, err := s.http.LatestCheckpoint()
	if err != nil {
		return log.Checkpoint{}, nil, err
	}
	return latest.Checkpoint, latest.LogPublicKey, nil
}
