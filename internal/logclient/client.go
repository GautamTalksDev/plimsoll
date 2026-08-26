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

package logclient

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/GautamTalksDev/plimsoll/internal/attestation"
	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/payload"
	"github.com/GautamTalksDev/plimsoll/internal/seal"
	"github.com/GautamTalksDev/plimsoll/internal/sealfile"
)

// Client appends seals and attestations to a PLIMSOLL log.
type Client struct {
	log    *log.Log
	http   *http.Client
	base   string
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	record func([]byte) // test hook records outbound payloads
}

// OpenSQLite opens a local SQLite log (no network).
func OpenSQLite(path string, priv ed25519.PrivateKey) (*Client, error) {
	l, err := log.Open(path)
	if err != nil {
		return nil, err
	}
	return &Client{log: l, priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}

// NewHTTP creates a client that POSTs to baseURL (e.g. http://127.0.0.1:8080).
func NewHTTP(baseURL string, priv ed25519.PrivateKey, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{
		base: strings.TrimRight(baseURL, "/"),
		http: hc,
		priv: priv,
		pub:  priv.Public().(ed25519.PublicKey),
	}
}

func (c *Client) Close() error {
	if c.log != nil {
		return c.log.Close()
	}
	return nil
}

// PublicKey returns the log operator Ed25519 public key for this client.
func (c *Client) PublicKey() ed25519.PublicKey { return c.pub }

// Log returns the underlying SQLite log when present.
func (c *Client) Log() *log.Log { return c.log }

// SetRecordHook records exact outbound payload bytes in tests.
func (c *Client) SetRecordHook(fn func([]byte)) { c.record = fn }

type PublishSealResult struct {
	Index          int64
	InclusionProof sealfile.StoredInclusionProof
	Checkpoint     log.Checkpoint
	Outbound       []byte
	// Pending is true when the log accepted the submit (HTTP 202) but has not
	// yet appended. Index/proof/checkpoint are unset until the client awaits.
	Pending bool
	Note    string
}

// PublishSeal appends a signed seal to the log and returns proofs.
func (c *Client) PublishSeal(ss *seal.SignedSeal, sealHash string, pub ed25519.PublicKey) (*PublishSealResult, error) {
	canonical, err := ss.Seal.ForSign().CanonicalBytes()
	if err != nil {
		return nil, err
	}
	supersedes := ""
	if ss.Seal.Supersedes != nil {
		supersedes = ss.Seal.Supersedes.SealHash
	}
	body := map[string]any{
		"seal_hash":      sealHash,
		"canonical_b64":  base64.StdEncoding.EncodeToString(canonical),
		"submitter_id":   ss.Seal.Subject.Name,
		"submitted_at":   time.Now().Unix(),
		"supersedes":     supersedes,
		"signature_b64":  base64.StdEncoding.EncodeToString(ss.Signature),
		"public_key_b64": base64.StdEncoding.EncodeToString(pub),
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	if err := payload.AssertSealPublish(raw); err != nil {
		return nil, err
	}
	if c.record != nil {
		c.record(raw)
	}
	if c.log != nil {
		return c.publishSealLocal(ss, sealHash, canonical, supersedes)
	}
	return c.publishSealHTTP(raw)
}

func (c *Client) publishSealLocal(ss *seal.SignedSeal, sealHash string, canonical []byte, supersedes string) (*PublishSealResult, error) {
	idx, err := c.log.AppendSeal(log.SealInput{
		SealHash:    sealHash,
		Canonical:   canonical,
		SubmitterID: ss.Seal.Subject.Name,
		Supersedes:  supersedes,
		Signature:   base64.StdEncoding.EncodeToString(ss.Signature),
		PublicKey:   base64.StdEncoding.EncodeToString(c.pub),
	})
	if err != nil {
		return nil, err
	}
	proof, err := c.log.InclusionProof(idx)
	if err != nil {
		return nil, err
	}
	cp, err := c.log.SignCheckpoint(c.priv)
	if err != nil {
		return nil, err
	}
	stored := sealfile.StoreProof(proof)
	return &PublishSealResult{Index: idx, InclusionProof: stored, Checkpoint: cp, Outbound: nil}, nil
}

func (c *Client) publishSealHTTP(raw []byte) (*PublishSealResult, error) {
	status, resp, err := c.post("/submit", raw)
	if err != nil {
		return nil, err
	}
	if status == http.StatusAccepted {
		note := parseAcceptedNote(resp)
		return &PublishSealResult{Pending: true, Note: note, Outbound: raw}, nil
	}
	var out struct {
		Index          int64                         `json:"index"`
		InclusionProof sealfile.StoredInclusionProof `json:"inclusion_proof"`
		Checkpoint     log.Checkpoint                `json:"checkpoint"`
	}
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, err
	}
	return &PublishSealResult{
		Index:          out.Index,
		InclusionProof: out.InclusionProof,
		Checkpoint:     out.Checkpoint,
		Outbound:       raw,
	}, nil
}

type PublishAttestResult struct {
	Index            int64
	AttemptNo        int
	PreviousVerdicts []string
	InclusionProof   sealfile.StoredInclusionProof
	Checkpoint       log.Checkpoint
	Outbound         []byte
	Pending          bool
	Note             string
}

// PublishAttestation submits a signed attestation; the log assigns attempt_no.
func (c *Client) PublishAttestation(signed *attestation.Signed) (*PublishAttestResult, error) {
	body := map[string]any{
		"seal_hash":     signed.Document.SealHash,
		"result_digest": signed.Document.ResultDigest,
		"verdict":       signed.Document.Verdict,
		"canonical_b64": base64.StdEncoding.EncodeToString(signed.Canonical),
		"signature_b64": base64.StdEncoding.EncodeToString(signed.Signature),
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	if err := payload.AssertAttestationPublish(raw); err != nil {
		return nil, err
	}
	if c.record != nil {
		c.record(raw)
	}
	if c.log != nil {
		return c.publishAttestLocal(signed, raw)
	}
	return c.publishAttestHTTP(raw)
}

func (c *Client) publishAttestLocal(signed *attestation.Signed, raw []byte) (*PublishAttestResult, error) {
	prev, err := c.log.AttemptsForSeal(signed.Document.SealHash)
	if err != nil {
		return nil, err
	}
	prevVerdicts := make([]string, len(prev))
	for i, a := range prev {
		prevVerdicts[i] = strings.ToUpper(a.Verdict)
	}
	idx, err := c.log.AppendAttestation(log.AttestationInput{
		SealHash:     signed.Document.SealHash,
		ResultDigest: signed.Document.ResultDigest,
		Verdict:      strings.ToLower(signed.Document.Verdict),
		Canonical:    signed.Canonical,
	})
	if err != nil {
		return nil, err
	}
	attempts, err := c.log.AttemptsForSeal(signed.Document.SealHash)
	if err != nil {
		return nil, err
	}
	var attemptNo int
	for _, a := range attempts {
		if a.Idx == idx {
			attemptNo = a.AttemptNo
			break
		}
	}
	proof, err := c.log.InclusionProof(idx)
	if err != nil {
		return nil, err
	}
	cp, err := c.log.SignCheckpoint(c.priv)
	if err != nil {
		return nil, err
	}
	return &PublishAttestResult{
		Index:            idx,
		AttemptNo:        attemptNo,
		PreviousVerdicts: prevVerdicts,
		InclusionProof:   sealfile.StoreProof(proof),
		Checkpoint:       cp,
		Outbound:         raw,
	}, nil
}

func (c *Client) publishAttestHTTP(raw []byte) (*PublishAttestResult, error) {
	status, resp, err := c.post("/submit", raw)
	if err != nil {
		return nil, err
	}
	if status == http.StatusAccepted {
		note := parseAcceptedNote(resp)
		return &PublishAttestResult{Pending: true, Note: note, Outbound: raw}, nil
	}
	var out struct {
		Index            int64                         `json:"index"`
		AttemptNo        int                           `json:"attempt_no"`
		PreviousVerdicts []string                      `json:"previous_verdicts"`
		InclusionProof   sealfile.StoredInclusionProof `json:"inclusion_proof"`
		Checkpoint       log.Checkpoint                `json:"checkpoint"`
	}
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, err
	}
	out.PreviousVerdicts = uppercaseVerdicts(out.PreviousVerdicts)
	return &PublishAttestResult{
		Index:            out.Index,
		AttemptNo:        out.AttemptNo,
		PreviousVerdicts: out.PreviousVerdicts,
		InclusionProof:   out.InclusionProof,
		Checkpoint:       out.Checkpoint,
		Outbound:         raw,
	}, nil
}

func uppercaseVerdicts(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = strings.ToUpper(v)
	}
	return out
}

func parseAcceptedNote(resp []byte) string {
	var raw struct {
		Note string `json:"note"`
	}
	if err := json.Unmarshal(resp, &raw); err != nil {
		return ""
	}
	return raw.Note
}

func (c *Client) post(path string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return res.StatusCode, nil, err
	}
	if res.StatusCode/100 != 2 {
		return res.StatusCode, b, fmt.Errorf("logclient: POST %s: %s", path, string(b))
	}
	return res.StatusCode, b, nil
}
