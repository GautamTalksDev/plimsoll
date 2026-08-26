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

package logfetch

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/sealfile"
)

// Client reads from any PLIMSOLL transparency log HTTP endpoint.
type Client struct {
	Base string
	HTTP *http.Client
}

// New returns a client for baseURL (e.g. http://127.0.0.1:8080).
func New(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{
		Base: strings.TrimRight(baseURL, "/"),
		HTTP: hc,
	}
}

// LatestCheckpointResponse is the signed tree head from the log.
type LatestCheckpointResponse struct {
	Checkpoint   log.Checkpoint
	LogPublicKey []byte
}

// LatestCheckpoint fetches the newest signed checkpoint.
func (c *Client) LatestCheckpoint() (*LatestCheckpointResponse, error) {
	b, err := c.get("/checkpoint")
	if err != nil {
		b, err = c.get("/v1/checkpoints/latest")
		if err != nil {
			return nil, err
		}
		return parseNestedCheckpoint(b)
	}
	return parseFlatCheckpoint(b)
}

func parseFlatCheckpoint(b []byte) (*LatestCheckpointResponse, error) {
	var raw struct {
		TreeSize     int64  `json:"tree_size"`
		RootHash     string `json:"root_hash"`
		Timestamp    int64  `json:"timestamp"`
		Signature    string `json:"signature"`
		LogPublicKey string `json:"log_public_key"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	pub, err := base64.StdEncoding.DecodeString(raw.LogPublicKey)
	if err != nil {
		return nil, err
	}
	return &LatestCheckpointResponse{
		Checkpoint: log.Checkpoint{
			TreeSize: raw.TreeSize, RootHash: raw.RootHash,
			Timestamp: raw.Timestamp, Signature: raw.Signature,
		},
		LogPublicKey: pub,
	}, nil
}

func parseNestedCheckpoint(b []byte) (*LatestCheckpointResponse, error) {
	var raw struct {
		Checkpoint struct {
			TreeSize  int64  `json:"tree_size"`
			RootHash  string `json:"root_hash"`
			Timestamp int64  `json:"timestamp"`
			Signature string `json:"signature"`
		} `json:"checkpoint"`
		LogPublicKey string `json:"log_public_key"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	pub, err := base64.StdEncoding.DecodeString(raw.LogPublicKey)
	if err != nil {
		return nil, err
	}
	return &LatestCheckpointResponse{
		Checkpoint: log.Checkpoint{
			TreeSize: raw.Checkpoint.TreeSize, RootHash: raw.Checkpoint.RootHash,
			Timestamp: raw.Checkpoint.Timestamp, Signature: raw.Checkpoint.Signature,
		},
		LogPublicKey: pub,
	}, nil
}

// EntryProofResponse bundles an inclusion proof and signing checkpoint.
type EntryProofResponse struct {
	InclusionProof sealfile.StoredInclusionProof
	Checkpoint     log.Checkpoint
	LogPublicKey   []byte
}

// EntryInclusionProof fetches a Merkle inclusion proof for log index idx.
func (c *Client) EntryInclusionProof(idx int64) (*EntryProofResponse, error) {
	b, err := c.get(fmt.Sprintf("/proof/inclusion?idx=%d", idx))
	if err != nil {
		b, err = c.get(fmt.Sprintf("/v1/entries/%d/inclusion-proof", idx))
		if err != nil {
			return nil, err
		}
	}
	return parseInclusionProof(b)
}

func parseInclusionProof(b []byte) (*EntryProofResponse, error) {
	var raw struct {
		InclusionProof sealfile.StoredInclusionProof `json:"inclusion_proof"`
		Checkpoint     jsonCheckpoint                `json:"checkpoint"`
		LogPublicKey   string                        `json:"log_public_key"`
		TreeSize       int64                         `json:"tree_size"`
		RootHash       string                        `json:"root_hash"`
		Timestamp      int64                         `json:"timestamp"`
		Signature      string                        `json:"signature"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	cp := raw.Checkpoint.toCheckpoint()
	if cp.TreeSize == 0 && raw.TreeSize > 0 {
		cp = log.Checkpoint{TreeSize: raw.TreeSize, RootHash: raw.RootHash, Timestamp: raw.Timestamp, Signature: raw.Signature}
	}
	pub, err := base64.StdEncoding.DecodeString(raw.LogPublicKey)
	if err != nil {
		return nil, err
	}
	return &EntryProofResponse{InclusionProof: raw.InclusionProof, Checkpoint: cp, LogPublicKey: pub}, nil
}

type jsonCheckpoint struct {
	TreeSize  int64  `json:"tree_size"`
	RootHash  string `json:"root_hash"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

func (j jsonCheckpoint) toCheckpoint() log.Checkpoint {
	return log.Checkpoint{TreeSize: j.TreeSize, RootHash: j.RootHash, Timestamp: j.Timestamp, Signature: j.Signature}
}

// SealResponse is seal metadata served by the log.
type SealResponse struct {
	Idx         int64
	SealHash    string
	Canonical   []byte
	Signature   string
	PublicKey   string
	SubmittedAt int64
	Supersedes  string
	LeafHash    string
}

// Seal fetches a seal row by seal_hash.
func (c *Client) Seal(sealHash string) (*SealResponse, error) {
	b, err := c.get("/seal/" + urlPath(sealHash))
	if err != nil {
		b, err = c.get("/v1/seal?seal_hash=" + urlQuery(sealHash))
		if err != nil {
			return nil, err
		}
		var legacy struct {
			Seal struct {
				Idx          int64  `json:"index"`
				SealHash     string `json:"seal_hash"`
				CanonicalB64 string `json:"canonical_b64"`
				Signature    string `json:"signature_b64"`
				PublicKey    string `json:"public_key_b64"`
				SubmittedAt  int64  `json:"submitted_at"`
				Supersedes   string `json:"supersedes"`
				LeafHash     string `json:"leaf_hash"`
			} `json:"seal"`
		}
		if err := json.Unmarshal(b, &legacy); err != nil {
			return nil, err
		}
		canonical, err := base64.StdEncoding.DecodeString(legacy.Seal.CanonicalB64)
		if err != nil {
			return nil, err
		}
		return &SealResponse{
			Idx: legacy.Seal.Idx, SealHash: legacy.Seal.SealHash, Canonical: canonical,
			Signature: legacy.Seal.Signature, PublicKey: legacy.Seal.PublicKey,
			SubmittedAt: legacy.Seal.SubmittedAt, Supersedes: legacy.Seal.Supersedes,
			LeafHash: legacy.Seal.LeafHash,
		}, nil
	}
	var raw struct {
		Seal struct {
			Idx          int64  `json:"index"`
			SealHash     string `json:"seal_hash"`
			CanonicalB64 string `json:"canonical_b64"`
			Signature    string `json:"signature_b64"`
			PublicKey    string `json:"public_key_b64"`
			SubmittedAt  int64  `json:"submitted_at"`
			Supersedes   string `json:"supersedes"`
			LeafHash     string `json:"leaf_hash"`
		} `json:"seal"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	canonical, err := base64.StdEncoding.DecodeString(raw.Seal.CanonicalB64)
	if err != nil {
		return nil, err
	}
	return &SealResponse{
		Idx: raw.Seal.Idx, SealHash: raw.Seal.SealHash, Canonical: canonical,
		Signature: raw.Seal.Signature, PublicKey: raw.Seal.PublicKey,
		SubmittedAt: raw.Seal.SubmittedAt, Supersedes: raw.Seal.Supersedes,
		LeafHash: raw.Seal.LeafHash,
	}, nil
}

// EntryAt fetches one log entry by global Merkle index.
func (c *Client) EntryAt(idx int64) (*log.Entry, error) {
	b, err := c.get(fmt.Sprintf("/entries?from=%d&to=%d", idx, idx+1))
	if err != nil {
		return nil, err
	}
	var raw struct {
		Entries []log.Entry `json:"entries"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	if len(raw.Entries) == 0 {
		return nil, fmt.Errorf("logfetch: entry %d not found", idx)
	}
	return &raw.Entries[0], nil
}

// Attempts lists attestation attempts for a seal.
func (c *Client) Attempts(sealHash string) ([]log.Attempt, error) {
	b, err := c.get("/seal/" + urlPath(sealHash))
	if err == nil {
		var raw struct {
			Attempts []log.Attempt `json:"attempts"`
		}
		if err := json.Unmarshal(b, &raw); err != nil {
			return nil, err
		}
		return raw.Attempts, nil
	}
	b, err = c.get("/v1/attempts?seal_hash=" + urlQuery(sealHash))
	if err != nil {
		return nil, err
	}
	var raw struct {
		Attempts []log.Attempt `json:"attempts"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	return raw.Attempts, nil
}

// ConsistencyResponse is a Merkle consistency proof between tree sizes.
type ConsistencyResponse struct {
	OldSize   int64
	NewSize   int64
	OldRoot   []byte
	NewRoot   []byte
	AuditPath [][]byte
}

// Consistency fetches a consistency proof from oldSize to newSize.
func (c *Client) Consistency(from, to int64) (*ConsistencyResponse, error) {
	b, err := c.get(fmt.Sprintf("/proof/consistency?old=%d&new=%d", from, to))
	if err != nil {
		b, err = c.get(fmt.Sprintf("/v1/consistency?from=%d&to=%d", from, to))
		if err != nil {
			return nil, err
		}
	}
	return parseConsistency(b)
}

func parseConsistency(b []byte) (*ConsistencyResponse, error) {
	var raw struct {
		OldSize   int64    `json:"old_size"`
		NewSize   int64    `json:"new_size"`
		OldRoot   string   `json:"old_root"`
		NewRoot   string   `json:"new_root"`
		AuditPath []string `json:"audit_path"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	oldRoot, err := hex.DecodeString(raw.OldRoot)
	if err != nil {
		return nil, err
	}
	newRoot, err := hex.DecodeString(raw.NewRoot)
	if err != nil {
		return nil, err
	}
	audit := make([][]byte, len(raw.AuditPath))
	for i, h := range raw.AuditPath {
		audit[i], err = hex.DecodeString(h)
		if err != nil {
			return nil, err
		}
	}
	return &ConsistencyResponse{
		OldSize: raw.OldSize, NewSize: raw.NewSize,
		OldRoot: oldRoot, NewRoot: newRoot, AuditPath: audit,
	}, nil
}

func (c *Client) get(path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.Base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode/100 != 2 {
		return nil, fmt.Errorf("logfetch: GET %s: %s", path, string(b))
	}
	return b, nil
}

func urlQuery(s string) string {
	return strings.ReplaceAll(s, ":", "%3A")
}

func urlPath(s string) string {
	return strings.ReplaceAll(s, ":", "%3A")
}
