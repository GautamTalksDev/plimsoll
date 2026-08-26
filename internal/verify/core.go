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

package verify

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/GautamTalksDev/plimsoll/internal/attestation"
	"github.com/GautamTalksDev/plimsoll/internal/decide"
	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/logfetch"
	"github.com/GautamTalksDev/plimsoll/internal/seal"
	"github.com/GautamTalksDev/plimsoll/internal/sealfile"
)

const BundleVersion = "plimsoll-verify-bundle-v1"

// Bundle holds offline verification artifacts.
type Bundle struct {
	Version                   string                        `json:"version"`
	LogPublicKey              string                        `json:"log_public_key"`
	Seal                      sealfile.Document             `json:"seal"`
	Attestation               attestation.Document          `json:"attestation"`
	SealInclusionProof        sealfile.StoredInclusionProof `json:"seal_inclusion_proof"`
	SealCheckpoint            checkpointJSON                `json:"seal_checkpoint"`
	AttestationInclusionProof sealfile.StoredInclusionProof `json:"attestation_inclusion_proof"`
	AttestationCheckpoint     checkpointJSON                `json:"attestation_checkpoint"`
	Attempts                  []log.Attempt                 `json:"attempts"`
	LatestCheckpoint          *checkpointJSON               `json:"latest_checkpoint,omitempty"`
	Consistency               *consistencyJSON              `json:"consistency,omitempty"`
}

type checkpointJSON struct {
	TreeSize  int64  `json:"tree_size"`
	RootHash  string `json:"root_hash"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

type consistencyJSON struct {
	OldSize   int64    `json:"old_size"`
	NewSize   int64    `json:"new_size"`
	OldRoot   string   `json:"old_root"`
	NewRoot   string   `json:"new_root"`
	AuditPath []string `json:"audit_path"`
}

func cpToJSON(cp log.Checkpoint) checkpointJSON {
	return checkpointJSON{
		TreeSize: cp.TreeSize, RootHash: cp.RootHash,
		Timestamp: cp.Timestamp, Signature: cp.Signature,
	}
}

// CheckpointExport serializes a signed checkpoint for browser/offline artifacts.
func CheckpointExport(cp log.Checkpoint) checkpointJSON { return cpToJSON(cp) }

// ConsistencyExport serializes a Merkle consistency proof for browser/offline artifacts.
func ConsistencyExport(cp log.ConsistencyProof) consistencyJSON {
	audit := make([]string, len(cp.AuditPath))
	for i, h := range cp.AuditPath {
		audit[i] = fmt.Sprintf("%x", h)
	}
	return consistencyJSON{
		OldSize: cp.OldSize, NewSize: cp.NewSize,
		OldRoot: fmt.Sprintf("%x", cp.OldRoot),
		NewRoot: fmt.Sprintf("%x", cp.NewRoot),
		AuditPath: audit,
	}
}

func cpFromJSON(j checkpointJSON) log.Checkpoint {
	return log.Checkpoint{
		TreeSize: j.TreeSize, RootHash: j.RootHash,
		Timestamp: j.Timestamp, Signature: j.Signature,
	}
}

const (
	VerdictVerified            = "VERIFIED"
	VerdictVerifiedDisclosures = "VERIFIED WITH DISCLOSURES"
	VerdictNotVerified         = "NOT VERIFIED"
)

// Check is one verification step V1–V9.
type Check struct {
	ID     string `json:"id"`
	Pass   bool   `json:"pass"`
	Reason string `json:"reason"`
}

// AttemptDisclosure is attempt metadata for V8.
type AttemptDisclosure struct {
	AttemptNo int    `json:"attempt_no"`
	Verdict   string `json:"verdict"`
}

// Disclosure summarizes multi-attempt and supersede context.
type Disclosure struct {
	AttemptNo       int                 `json:"attempt_no"`
	TotalAttempts   int                 `json:"total_attempts"`
	Attempts        []AttemptDisclosure `json:"attempts"`
	Supersedes      string              `json:"supersedes,omitempty"`
	SupersedeReason string              `json:"supersede_reason,omitempty"`
}

// Report is the full verification outcome.
type Report struct {
	Verdict     string                `json:"verdict"`
	Checks      []Check               `json:"checks"`
	Disclosure  *Disclosure           `json:"disclosure,omitempty"`
	Attestation *attestation.Document `json:"-"`
}

// Options configures verification.
type Options struct {
	Offline    bool
	LogURL     string
	BundlePath string
	Fetch      *logfetch.Client
	LocalLog   *log.Log
	LogPub     ed25519.PublicKey
	SkipV9     bool
}

type material struct {
	pub           ed25519.PublicKey
	logPub        ed25519.PublicKey
	sealDoc       *sealfile.Document
	att           *attestation.Document
	sealProof     *sealfile.StoredInclusionProof
	sealCP        *log.Checkpoint
	attProof      *sealfile.StoredInclusionProof
	attCP         *log.Checkpoint
	attempts      []log.Attempt
	latestCP      *log.Checkpoint
	consistency   *logfetch.ConsistencyResponse
	sealSubmitted int64
	attSubmitted  int64
}

func buildReport(m *material, opt Options) *Report {
	checks := make([]Check, 0, 9)
	add := func(id string, pass bool, reason string) {
		checks = append(checks, Check{ID: id, Pass: pass, Reason: reason})
	}

	if err := attestation.Verify(m.pub, m.att); err != nil {
		add("V1", false, err.Error())
	} else {
		add("V1", true, "attestation signature valid against stated public key")
	}

	if err := seal.VerifySignature(m.pub, m.sealDoc.Seal); err != nil {
		add("V2", false, err.Error())
	} else {
		add("V2", true, "seal signature valid")
	}

	sealTS, v3ok, v3reason := checkInclusion(m.logPub, m.sealProof, m.sealCP)
	if v3ok {
		add("V3", true, fmt.Sprintf("seal included in log at tree_size %d; timestamp %d", m.sealProof.TreeSize, sealTS))
	} else {
		add("V3", false, v3reason)
	}

	attTS, v4ok, v4reason := checkInclusion(m.logPub, m.attProof, m.attCP)
	if v4ok {
		add("V4", true, fmt.Sprintf("attestation included in log at tree_size %d; timestamp %d", m.attProof.TreeSize, attTS))
	} else {
		add("V4", false, v4reason)
	}

	if v3ok && v4ok && m.sealProof != nil && m.attProof != nil {
		if m.sealProof.Index >= m.attProof.Index {
			add("V5", false, fmt.Sprintf("seal log index %d must precede attestation index %d", m.sealProof.Index, m.attProof.Index))
		} else if m.sealSubmitted > 0 && m.attSubmitted > 0 && m.sealSubmitted > m.attSubmitted {
			add("V5", false, fmt.Sprintf("seal submitted_at %d must not follow attestation submitted_at %d", m.sealSubmitted, m.attSubmitted))
		} else {
			add("V5", true, fmt.Sprintf("seal precedes attestation in log (index %d < %d)", m.sealProof.Index, m.attProof.Index))
		}
	} else if m.sealSubmitted > 0 && m.attSubmitted > 0 {
		if m.sealSubmitted < m.attSubmitted {
			add("V5", true, fmt.Sprintf("seal submitted_at %d precedes attestation submitted_at %d", m.sealSubmitted, m.attSubmitted))
		} else {
			add("V5", false, "seal must be logged before attestation")
		}
	} else {
		add("V5", false, "cannot compare seal and attestation ordering")
	}

	v6ok, v6reason := checkDataset(m.sealDoc.Seal.Seal, m.att)
	add("V6", v6ok, v6reason)

	replayed, err := decide.ReplayVerdict(m.att.Expression, m.att.Terms)
	if err != nil {
		add("V7", false, err.Error())
	} else if strings.EqualFold(replayed, m.att.Verdict) {
		add("V7", true, fmt.Sprintf("replayed verdict %s matches recorded %s", replayed, m.att.Verdict))
	} else {
		add("V7", false, fmt.Sprintf("replayed %s != recorded %s", replayed, m.att.Verdict))
	}

	disc := buildDisclosure(m)
	add("V8", true, formatDisclosure(disc))

	if opt.SkipV9 || opt.Offline {
		add("V9", true, "skipped (--offline)")
	} else if m.latestCP == nil {
		add("V9", false, "no latest checkpoint from log")
	} else if !log.VerifyCheckpoint(m.logPub, *m.latestCP) {
		add("V9", false, "latest checkpoint signature invalid")
	} else if m.attCP != nil && m.attCP.TreeSize == m.latestCP.TreeSize && m.attCP.RootHash == m.latestCP.RootHash {
		add("V9", true, fmt.Sprintf("proof checkpoint is the latest published tree_size %d", m.latestCP.TreeSize))
	} else if m.consistency == nil {
		add("V9", false, "missing consistency proof to latest checkpoint")
	} else {
		latestRoot, err := hex.DecodeString(m.latestCP.RootHash)
		if err != nil {
			add("V9", false, err.Error())
		} else if !bytesEqual(m.consistency.NewRoot, latestRoot) {
			add("V9", false, "consistency proof new root does not match latest checkpoint")
		} else if log.VerifyConsistency(int(m.consistency.OldSize), int(m.consistency.NewSize), m.consistency.OldRoot, m.consistency.NewRoot, m.consistency.AuditPath) {
			add("V9", true, fmt.Sprintf("checkpoint tree_size %d consistent with latest %d", m.attCP.TreeSize, m.latestCP.TreeSize))
		} else {
			add("V9", false, "Merkle consistency proof invalid")
		}
	}

	corePass := true
	for _, c := range checks {
		if c.ID == "V8" {
			continue
		}
		if c.ID == "V9" && strings.HasPrefix(c.Reason, "skipped") {
			continue
		}
		if !c.Pass {
			corePass = false
			break
		}
	}

	verdict := VerdictNotVerified
	if corePass {
		if disc.TotalAttempts > 1 || disc.Supersedes != "" {
			verdict = VerdictVerifiedDisclosures
		} else {
			verdict = VerdictVerified
		}
	}

	return &Report{Verdict: verdict, Checks: checks, Disclosure: disc, Attestation: m.att}
}

func checkDataset(s *seal.Seal, att *attestation.Document) (bool, string) {
	if s == nil || att == nil {
		return false, "missing seal or attestation"
	}
	hash, err := s.CanonicalHash()
	if err != nil {
		return false, err.Error()
	}
	if hash != att.SealHash {
		return false, fmt.Sprintf("attestation seal_hash %q != seal canonical hash %q", att.SealHash, hash)
	}
	if att.NEvaluated != s.Dataset.N {
		return false, fmt.Sprintf("n_evaluated %d != seal dataset.n %d", att.NEvaluated, s.Dataset.N)
	}
	if att.Adapter != s.Harness.Tool {
		return false, fmt.Sprintf("adapter %q != sealed harness %q", att.Adapter, s.Harness.Tool)
	}
	if att.AdapterVersion != s.Harness.Version {
		return false, "adapter version mismatch"
	}
	return true, fmt.Sprintf("seal dataset sha256 %s with n=%d matches attestation binding", s.Dataset.SHA256, s.Dataset.N)
}

func checkInclusion(logPub ed25519.PublicKey, proof *sealfile.StoredInclusionProof, cp *log.Checkpoint) (timestamp int64, ok bool, reason string) {
	if proof == nil || cp == nil {
		return 0, false, "missing inclusion proof or checkpoint"
	}
	if len(logPub) != ed25519.PublicKeySize {
		return 0, false, "missing log public key"
	}
	if !log.VerifyCheckpoint(logPub, *cp) {
		return 0, false, "checkpoint signature invalid"
	}
	leaf, err := decodeHex(proof.LeafHash)
	if err != nil {
		return 0, false, err.Error()
	}
	root, err := decodeHex(proof.RootHash)
	if err != nil {
		return 0, false, err.Error()
	}
	if cp.RootHash != proof.RootHash && cp.RootHash != hex.EncodeToString(root) {
		return 0, false, "proof root does not match signed checkpoint"
	}
	path := make([][]byte, len(proof.AuditPath))
	for i, h := range proof.AuditPath {
		path[i], err = decodeHex(h)
		if err != nil {
			return 0, false, err.Error()
		}
	}
	if !log.VerifyInclusion(int(proof.Index), int(proof.TreeSize), leaf, path, root) {
		return 0, false, "Merkle inclusion proof invalid"
	}
	return cp.Timestamp, true, ""
}

func buildDisclosure(m *material) *Disclosure {
	d := &Disclosure{Attempts: []AttemptDisclosure{}}
	for _, a := range m.attempts {
		d.Attempts = append(d.Attempts, AttemptDisclosure{
			AttemptNo: a.AttemptNo,
			Verdict:   strings.ToUpper(a.Verdict),
		})
	}
	d.TotalAttempts = len(m.attempts)
	for _, a := range m.attempts {
		if a.ResultDigest == m.att.ResultDigest {
			d.AttemptNo = a.AttemptNo
			break
		}
	}
	if m.sealDoc.Seal != nil && m.sealDoc.Seal.Seal != nil && m.sealDoc.Seal.Seal.Supersedes != nil {
		d.Supersedes = m.sealDoc.Seal.Seal.Supersedes.SealHash
		d.SupersedeReason = m.sealDoc.Seal.Seal.Supersedes.Reason
	}
	return d
}

func formatDisclosure(d *Disclosure) string {
	var b strings.Builder
	fmt.Fprintf(&b, "attempt %d of %d", d.AttemptNo, d.TotalAttempts)
	if d.TotalAttempts > 0 {
		b.WriteString("; verdicts:")
		for _, a := range d.Attempts {
			fmt.Fprintf(&b, " #%d=%s", a.AttemptNo, a.Verdict)
		}
	}
	if d.Supersedes != "" {
		fmt.Fprintf(&b, "; supersedes %s", d.Supersedes)
		if d.SupersedeReason != "" {
			fmt.Fprintf(&b, " (%s)", d.SupersedeReason)
		}
	}
	return b.String()
}

func decodeHex(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.ToLower(s), "sha256:")
	return hex.DecodeString(s)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
