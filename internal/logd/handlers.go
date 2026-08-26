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

package logd

import (
	"encoding/hex"
	"net/http"
)

func (s *Server) handleCheckpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.limit(w, r, false) {
		return
	}
	cp, err := s.cfg.Log.LatestCheckpoint()
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{
		"tree_size":      cp.TreeSize,
		"root_hash":      cp.RootHash,
		"timestamp":      cp.Timestamp,
		"signature":      cp.Signature,
		"log_public_key": s.logPubB64(),
	})
}

func (s *Server) handleEntries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.limit(w, r, false) {
		return
	}
	size, err := s.cfg.Log.Size()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	from := parseIntQuery(r, "from", 0)
	to := parseIntQuery(r, "to", size)
	if to <= 0 || to > size {
		to = size
	}
	entries, err := s.cfg.Log.Entries(from, to)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{
		"from": from, "to": to, "tree_size": size, "entries": entries,
	})
}

func (s *Server) handleInclusionProof(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.limit(w, r, false) {
		return
	}
	idx := parseIntQuery(r, "idx", -1)
	if idx < 0 {
		http.Error(w, "idx required", http.StatusBadRequest)
		return
	}
	proof, err := s.cfg.Log.InclusionProof(idx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	cp, err := s.cfg.Log.CheckpointAt(proof.TreeSize)
	if err != nil {
		cp, err = s.cfg.Log.LatestCheckpoint()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, map[string]any{
		"inclusion_proof": storeProof(proof),
		"checkpoint":      cpJSON(cp),
		"log_public_key":  s.logPubB64(),
	})
}

func (s *Server) handleConsistencyProof(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.limit(w, r, false) {
		return
	}
	oldSize := parseIntQuery(r, "old", -1)
	newSize := parseIntQuery(r, "new", -1)
	if oldSize < 0 {
		oldSize = parseIntQuery(r, "from", -1)
	}
	if newSize < 0 {
		newSize = parseIntQuery(r, "to", -1)
	}
	if oldSize < 0 || newSize < oldSize {
		http.Error(w, "old and new required", http.StatusBadRequest)
		return
	}
	cp, err := s.cfg.Log.ConsistencyProof(oldSize, newSize)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	audit := make([]string, len(cp.AuditPath))
	for i, h := range cp.AuditPath {
		audit[i] = hex.EncodeToString(h)
	}
	writeJSON(w, map[string]any{
		"old_size":       cp.OldSize,
		"new_size":       cp.NewSize,
		"old_root":       hex.EncodeToString(cp.OldRoot),
		"new_root":       hex.EncodeToString(cp.NewRoot),
		"audit_path":     audit,
		"log_public_key": s.logPubB64(),
	})
}
