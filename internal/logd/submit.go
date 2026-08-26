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
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/GautamTalksDev/plimsoll/internal/badge"
	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/payload"
)

func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if !s.limit(w, r, true) {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	kind, err := payload.AssertSubmit(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	switch kind {
	case payload.SubmitSeal:
		s.submitSeal(w, body)
	case payload.SubmitAttestation:
		s.submitAttestation(w, body)
	default:
		http.Error(w, "unrecognized submit payload", http.StatusBadRequest)
	}
}

func (s *Server) submitSeal(w http.ResponseWriter, raw []byte) {
	var in struct {
		SealHash     string `json:"seal_hash"`
		CanonicalB64 string `json:"canonical_b64"`
		SubmitterID  string `json:"submitter_id"`
		SubmittedAt  int64  `json:"submitted_at"`
		Supersedes   string `json:"supersedes"`
		SignatureB64 string `json:"signature_b64"`
		PublicKeyB64 string `json:"public_key_b64"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	canonical, err := base64.StdEncoding.DecodeString(in.CanonicalB64)
	if err != nil {
		http.Error(w, "invalid canonical_b64", http.StatusBadRequest)
		return
	}
	idx, err := s.cfg.Log.AppendSeal(log.SealInput{
		SealHash: in.SealHash, Canonical: canonical, SubmitterID: in.SubmitterID,
		SubmittedAt: in.SubmittedAt, Supersedes: in.Supersedes,
		Signature: in.SignatureB64, PublicKey: in.PublicKeyB64,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	s.writeSubmitResponse(w, idx, 0, nil)
}

func (s *Server) submitAttestation(w http.ResponseWriter, raw []byte) {
	var in struct {
		SealHash     string `json:"seal_hash"`
		ResultDigest string `json:"result_digest"`
		Verdict      string `json:"verdict"`
		CanonicalB64 string `json:"canonical_b64"`
		SignatureB64 string `json:"signature_b64"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	canonical, err := base64.StdEncoding.DecodeString(in.CanonicalB64)
	if err != nil {
		http.Error(w, "invalid canonical_b64", http.StatusBadRequest)
		return
	}
	prev, _ := s.cfg.Log.AttemptsForSeal(in.SealHash)
	prevVerdicts := make([]string, len(prev))
	for i, a := range prev {
		prevVerdicts[i] = strings.ToUpper(a.Verdict)
	}
	idx, err := s.cfg.Log.AppendAttestation(log.AttestationInput{
		SealHash: in.SealHash, ResultDigest: in.ResultDigest,
		Verdict: strings.ToLower(in.Verdict), Canonical: canonical,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	attempts, err := s.cfg.Log.AttemptsForSeal(in.SealHash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var attemptNo int
	for _, a := range attempts {
		if a.Idx == idx {
			attemptNo = a.AttemptNo
			break
		}
	}
	s.writeSubmitResponse(w, idx, attemptNo, prevVerdicts)
}

func (s *Server) writeSubmitResponse(w http.ResponseWriter, idx int64, attemptNo int, prev []string) {
	proof, err := s.cfg.Log.InclusionProof(idx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cp, err := s.cfg.Log.SignCheckpoint(s.cfg.PrivKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := map[string]any{
		"index":           idx,
		"inclusion_proof": storeProof(proof),
		"checkpoint":      cpJSON(cp),
		"log_public_key":  s.logPubB64(),
	}
	if attemptNo > 0 {
		out["attempt_no"] = attemptNo
		out["previous_verdicts"] = prev
	}
	writeJSON(w, out)
}

func (s *Server) handleSealPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.limit(w, r, false) {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/seal/")
	rest = strings.Trim(rest, "/")
	if rest == "" {
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(rest, "/badge.svg") {
		hash := strings.TrimSuffix(rest, "/badge.svg")
		hash = strings.Trim(hash, "/")
		s.serveBadge(w, r, hash)
		return
	}
	sealHash, err := decodeSealHash(rest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if wantsHTML(r) && s.cfg.Site != nil {
		s.cfg.Site.ServeSeal(w, r, sealHash)
		return
	}
	s.serveSealJSON(w, sealHash)
}

func (s *Server) serveSealJSON(w http.ResponseWriter, sealHash string) {
	rec, ok, err := s.cfg.Log.SealByHash(sealHash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	attempts, err := s.cfg.Log.AttemptsForSeal(sealHash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"seal":           sealRecordJSON(rec),
		"attempts":       attempts,
		"log_public_key": s.logPubB64(),
	})
}

func (s *Server) serveBadge(w http.ResponseWriter, r *http.Request, sealHash string) {
	sealHash, err := decodeSealHash(sealHash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, ok, err := s.cfg.Log.SealByHash(sealHash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	attempts, err := s.cfg.Log.AttemptsForSeal(sealHash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	style := badge.StyleForAttempts(attempts)
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300, s-maxage=600")
	_, _ = w.Write(badge.SVG(style)) //nolint:gosec // G705 -- SVG escapes labels; colors are fixed constants
}
