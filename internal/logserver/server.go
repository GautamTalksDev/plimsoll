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

package logserver

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/sealfile"
)

// Server exposes a read-only PLIMSOLL transparency log over HTTP.
type Server struct {
	Log       *log.Log
	PublicKey ed25519.PublicKey
	mux       *http.ServeMux
}

// New creates an HTTP handler for log read APIs.
func New(l *log.Log, pub ed25519.PublicKey) *Server {
	s := &Server{Log: l, PublicKey: pub, mux: http.NewServeMux()}
	s.mux.HandleFunc("/v1/checkpoints/latest", s.handleLatestCheckpoint)
	s.mux.HandleFunc("/v1/entries/", s.handleEntryProof)
	s.mux.HandleFunc("/v1/seal", s.handleSealByHash)
	s.mux.HandleFunc("/v1/attempts", s.handleAttempts)
	s.MountConsistency()
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

type checkpointJSON struct {
	TreeSize  int64  `json:"tree_size"`
	RootHash  string `json:"root_hash"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

func (s *Server) handleLatestCheckpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cp, err := s.Log.LatestCheckpoint()
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{
		"checkpoint":    toCheckpointJSON(cp),
		"log_public_key": base64.StdEncoding.EncodeToString(s.PublicKey),
	})
}

func (s *Server) handleEntryProof(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/v1/entries/")
	rest = strings.TrimSuffix(rest, "/inclusion-proof")
	idx, err := parseIndex(rest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	proof, err := s.Log.InclusionProof(idx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	cp, err := s.Log.CheckpointAt(proof.TreeSize)
	if err != nil {
		cp, err = s.Log.LatestCheckpoint()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, map[string]any{
		"inclusion_proof": sealfile.StoreProof(proof),
		"checkpoint":      toCheckpointJSON(cp),
		"log_public_key":  base64.StdEncoding.EncodeToString(s.PublicKey),
	})
}

func (s *Server) handleSealByHash(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sealHash := r.URL.Query().Get("seal_hash")
	if sealHash == "" {
		http.Error(w, "missing seal_hash", http.StatusBadRequest)
		return
	}
	rec, ok, err := s.Log.SealByHash(sealHash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{
		"seal": map[string]any{
			"index":           rec.Idx,
			"seal_hash":       rec.SealHash,
			"canonical_b64":   base64.StdEncoding.EncodeToString(rec.Canonical),
			"signature_b64":   rec.Signature,
			"public_key_b64":  rec.PublicKey,
			"submitted_at":    rec.SubmittedAt,
			"supersedes":      rec.Supersedes,
			"leaf_hash":       rec.LeafHash,
		},
	})
}

func (s *Server) handleAttempts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sealHash := r.URL.Query().Get("seal_hash")
	if sealHash == "" {
		http.Error(w, "missing seal_hash", http.StatusBadRequest)
		return
	}
	attempts, err := s.Log.AttemptsForSeal(sealHash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"attempts": attempts})
}

func toCheckpointJSON(cp log.Checkpoint) checkpointJSON {
	return checkpointJSON{
		TreeSize:  cp.TreeSize,
		RootHash:  cp.RootHash,
		Timestamp: cp.Timestamp,
		Signature: cp.Signature,
	}
}

func parseIndex(s string) (int64, error) {
	return strconv.ParseInt(strings.TrimSpace(s), 10, 64)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// ConsistencyProofHandler serves GET /v1/consistency?from=&to=
func (s *Server) MountConsistency() {
	s.mux.HandleFunc("/v1/consistency", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		from := parseQueryInt(r, "from")
		to := parseQueryInt(r, "to")
		if from < 0 || to < from {
			http.Error(w, "bad range", http.StatusBadRequest)
			return
		}
		cp, err := s.Log.ConsistencyProof(from, to)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		audit := make([]string, len(cp.AuditPath))
		for i, h := range cp.AuditPath {
			audit[i] = hex.EncodeToString(h)
		}
		writeJSON(w, map[string]any{
			"old_size":   from,
			"new_size":   to,
			"old_root":   hex.EncodeToString(cp.OldRoot),
			"new_root":   hex.EncodeToString(cp.NewRoot),
			"audit_path": audit,
		})
	})
}

func parseQueryInt(r *http.Request, key string) int64 {
	v := r.URL.Query().Get(key)
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return -1
	}
	return n
}
