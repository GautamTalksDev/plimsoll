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

package logd

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/GautamTalksDev/plimsoll/internal/sealfile"
)

func (s *Server) mountLegacyV1() {
	s.mux.HandleFunc("/v1/checkpoints/latest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cp, err := s.cfg.Log.LatestCheckpoint()
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]any{"checkpoint": cpJSON(cp), "log_public_key": s.logPubB64()})
	})
	s.mux.HandleFunc("/v1/entries/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/v1/entries/")
		rest = strings.TrimSuffix(rest, "/inclusion-proof")
		var idx int64
		for _, c := range rest {
			if c < '0' || c > '9' {
				http.Error(w, "bad index", http.StatusBadRequest)
				return
			}
			idx = idx*10 + int64(c-'0')
		}
		proof, err := s.cfg.Log.InclusionProof(idx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		cp, err := s.cfg.Log.CheckpointAt(proof.TreeSize)
		if err != nil {
			cp, _ = s.cfg.Log.LatestCheckpoint()
		}
		writeJSON(w, map[string]any{
			"inclusion_proof": storeProof(proof),
			"checkpoint":      cpJSON(cp),
			"log_public_key":  s.logPubB64(),
		})
	})
	s.mux.HandleFunc("/v1/seal", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		hash := r.URL.Query().Get("seal_hash")
		s.serveSealJSON(w, hash)
	})
	s.mux.HandleFunc("/v1/attempts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		hash := r.URL.Query().Get("seal_hash")
		attempts, err := s.cfg.Log.AttemptsForSeal(hash)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"attempts": attempts})
	})
	s.mux.HandleFunc("/v1/consistency", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		from := parseIntQuery(r, "from", -1)
		to := parseIntQuery(r, "to", -1)
		if from < 0 || to < from {
			http.Error(w, "bad range", http.StatusBadRequest)
			return
		}
		cp, err := s.cfg.Log.ConsistencyProof(from, to)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		audit := make([]string, len(cp.AuditPath))
		for i, h := range cp.AuditPath {
			audit[i] = hex.EncodeToString(h)
		}
		writeJSON(w, map[string]any{
			"old_size": from, "new_size": to,
			"old_root": hex.EncodeToString(cp.OldRoot),
			"new_root": hex.EncodeToString(cp.NewRoot),
			"audit_path": audit,
		})
	})
	s.mux.HandleFunc("/v1/seals", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleSubmit(w, r)
	})
	s.mux.HandleFunc("/v1/attestations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleSubmit(w, r)
	})
}

// SealIndex returns global log index for a seal hash (for verify/logfetch).
func (s *Server) SealIndex(sealHash string) (int64, error) {
	rec, ok, err := s.cfg.Log.SealByHash(sealHash)
	if err != nil || !ok {
		return -1, fmt.Errorf("seal not found")
	}
	return rec.Idx, nil
}

// StoredProof converts inclusion proof for API consumers.
func StoredProof(p sealfile.StoredInclusionProof) sealfile.StoredInclusionProof { return p }
