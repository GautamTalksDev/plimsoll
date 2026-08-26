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

// Package staticlog writes a log.sqlite as a deterministic static file tree
// that serves the SPEC-PREREG / logd read API from a CDN.
package staticlog

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/GautamTalksDev/plimsoll/internal/badge"
	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/sealfile"
	"github.com/GautamTalksDev/plimsoll/internal/site"
)

const pageSize = 100

// Config is a static-tree generation run. All timestamps in output come from
// log records and checkpoints; the generator does not read the wall clock.
type Config struct {
	Log       *log.Log
	OutDir    string
	PublicKey ed25519.PublicKey
	BaseURL   string
	SpecPath  string
	// WASMPath, if set and readable, is copied to OutDir/verify/.
	WASMPath string
}

// Generate writes a complete static log tree. Running twice on the same DB
// produces identical bytes for every file.
func Generate(cfg Config) error {
	if cfg.Log == nil {
		return fmt.Errorf("staticlog: log is required")
	}
	if cfg.OutDir == "" {
		return fmt.Errorf("staticlog: out dir is required")
	}
	if len(cfg.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("staticlog: invalid ed25519 public key size")
	}
	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		return err
	}

	size, err := cfg.Log.Size()
	if err != nil {
		return err
	}
	var latest log.Checkpoint
	if size > 0 {
		latest, err = cfg.Log.LatestCheckpoint()
		if err != nil {
			return fmt.Errorf("staticlog: log has entries but no checkpoint: %w", err)
		}
	}

	pubB64 := base64.StdEncoding.EncodeToString(cfg.PublicKey)
	if err := writeKey(cfg.OutDir, cfg.PublicKey); err != nil {
		return err
	}
	if err := writeHeaders(cfg.OutDir); err != nil {
		return err
	}
	if err := writeRedirects(cfg.OutDir); err != nil {
		return err
	}
	if size > 0 {
		if err := writeJSON(filepath.Join(cfg.OutDir, "checkpoint"), checkpointFile{
			TreeSize: latest.TreeSize, RootHash: latest.RootHash,
			Timestamp: latest.Timestamp, Signature: latest.Signature,
			LogPublicKey: pubB64,
		}); err != nil {
			return err
		}
	}
	if err := writeCheckpoints(cfg, pubB64); err != nil {
		return err
	}
	if err := writeEntries(cfg, size); err != nil {
		return err
	}
	if err := writeInclusion(cfg, size, latest, pubB64); err != nil {
		return err
	}
	if err := writeConsistency(cfg, size, pubB64); err != nil {
		return err
	}
	if err := writeSeals(cfg, pubB64); err != nil {
		return err
	}
	if err := writeSite(cfg); err != nil {
		return err
	}
	return copyVerify(cfg)
}

func writeCheckpoints(cfg Config, pubB64 string) error {
	cps, err := cfg.Log.Checkpoints()
	if err != nil {
		return err
	}
	dir := filepath.Join(cfg.OutDir, "checkpoints")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, cp := range cps {
		name := strconv.FormatInt(cp.TreeSize, 10)
		if err := writeJSON(filepath.Join(dir, name), checkpointFile{
			TreeSize: cp.TreeSize, RootHash: cp.RootHash,
			Timestamp: cp.Timestamp, Signature: cp.Signature,
			LogPublicKey: pubB64,
		}); err != nil {
			return err
		}
	}
	return nil
}

func writeEntries(cfg Config, size int64) error {
	dir := filepath.Join(cfg.OutDir, "entries")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	entries, err := cfg.Log.Entries(0, size)
	if err != nil {
		return err
	}
	if entries == nil {
		entries = []log.Entry{}
	}
	for _, e := range entries {
		if err := writeJSON(filepath.Join(dir, strconv.FormatInt(e.Index, 10)), e); err != nil {
			return err
		}
	}
	nPages := 1
	if size > 0 {
		nPages = int((size + pageSize - 1) / pageSize)
	}
	for page := 0; page < nPages; page++ {
		from := int64(page * pageSize)
		to := from + pageSize
		if to > size {
			to = size
		}
		if from > size {
			from = size
		}
		var slice []log.Entry
		if from < int64(len(entries)) {
			end := to
			if end > int64(len(entries)) {
				end = int64(len(entries))
			}
			slice = entries[from:end]
		}
		if slice == nil {
			slice = []log.Entry{}
		}
		body := entriesPage{
			From: from, To: to, TreeSize: size,
			Page: page, PageSize: pageSize, Entries: slice,
		}
		if page+1 < nPages {
			body.Next = "/entries/index-" + strconv.Itoa(page+1) + ".json"
		}
		name := "index.json"
		if page > 0 {
			name = "index-" + strconv.Itoa(page) + ".json"
		}
		if err := writeJSON(filepath.Join(dir, name), body); err != nil {
			return err
		}
	}
	return nil
}

func writeInclusion(cfg Config, size int64, latest log.Checkpoint, pubB64 string) error {
	if size == 0 {
		return nil
	}
	dir := filepath.Join(cfg.OutDir, "proof", "inclusion")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	cp := checkpointBare{
		TreeSize: latest.TreeSize, RootHash: latest.RootHash,
		Timestamp: latest.Timestamp, Signature: latest.Signature,
	}
	for i := int64(0); i < size; i++ {
		p, err := cfg.Log.InclusionProof(i)
		if err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(dir, strconv.FormatInt(i, 10)), inclusionFile{
			InclusionProof: sealfile.StoreProof(p),
			Checkpoint:     cp,
			LogPublicKey:   pubB64,
		}); err != nil {
			return err
		}
	}
	return nil
}

func writeConsistency(cfg Config, size int64, pubB64 string) error {
	if size == 0 {
		return nil
	}
	cps, err := cfg.Log.Checkpoints()
	if err != nil {
		return err
	}
	dir := filepath.Join(cfg.OutDir, "proof", "consistency")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, cp := range cps {
		if cp.TreeSize >= size {
			continue
		}
		proof, err := cfg.Log.ConsistencyProof(cp.TreeSize, size)
		if err != nil {
			return err
		}
		audit := make([]string, len(proof.AuditPath))
		for i, h := range proof.AuditPath {
			audit[i] = hex.EncodeToString(h)
		}
		name := strconv.FormatInt(cp.TreeSize, 10) + "-" + strconv.FormatInt(size, 10)
		if err := writeJSON(filepath.Join(dir, name), consistencyFile{
			OldSize: proof.OldSize, NewSize: proof.NewSize,
			OldRoot:   hex.EncodeToString(proof.OldRoot),
			NewRoot:   hex.EncodeToString(proof.NewRoot),
			AuditPath: audit, LogPublicKey: pubB64,
		}); err != nil {
			return err
		}
	}
	return nil
}

func writeSeals(cfg Config, pubB64 string) error {
	seals, err := cfg.Log.AllSeals()
	if err != nil {
		return err
	}
	for _, rec := range seals {
		attempts, err := cfg.Log.AttemptsForSeal(rec.SealHash)
		if err != nil {
			return err
		}
		if attempts == nil {
			attempts = []log.Attempt{}
		}
		dir := filepath.Join(cfg.OutDir, "seal", site.SealDir(rec.SealHash))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(dir, "index.json"), sealFile{
			Seal: sealJSON{
				Index: rec.Idx, SealHash: rec.SealHash,
				CanonicalB64: base64.StdEncoding.EncodeToString(rec.Canonical),
				SignatureB64: rec.Signature, PublicKeyB64: rec.PublicKey,
				SubmitterID: rec.SubmitterID, SubmittedAt: rec.SubmittedAt,
				Supersedes: rec.Supersedes, LeafHash: rec.LeafHash,
			},
			Attempts:     attempts,
			LogPublicKey: pubB64,
		}); err != nil {
			return err
		}
		style := badge.StyleForAttempts(attempts)
		if err := os.WriteFile(filepath.Join(dir, "badge.svg"), badge.SVG(style), 0o644); err != nil { //nolint:gosec // G306 -- public badge
			return err
		}
	}
	return nil
}

func writeSite(cfg Config) error {
	r, err := site.New(cfg.Log, cfg.PublicKey, cfg.SpecPath, cfg.BaseURL)
	if err != nil {
		return err
	}
	home, err := r.Render(r.HomePage())
	if err != nil {
		return err
	}
	if err := writeBytes(filepath.Join(cfg.OutDir, "index.html"), home); err != nil {
		return err
	}
	sealsData, err := r.SealsPage()
	if err != nil {
		return err
	}
	sealsHTML, err := r.Render(sealsData)
	if err != nil {
		return err
	}
	if err := writeBytes(filepath.Join(cfg.OutDir, "seals", "index.html"), sealsHTML); err != nil {
		return err
	}
	if cfg.SpecPath != "" {
		if specData, err := r.SpecPage(); err == nil {
			specHTML, err := r.Render(specData)
			if err != nil {
				return err
			}
			if err := writeBytes(filepath.Join(cfg.OutDir, "spec", "index.html"), specHTML); err != nil {
				return err
			}
		}
	}
	runHTML, err := r.Render(r.RunPage())
	if err != nil {
		return err
	}
	if err := writeBytes(filepath.Join(cfg.OutDir, "run-your-own", "index.html"), runHTML); err != nil {
		return err
	}
	seals, err := cfg.Log.AllSeals()
	if err != nil {
		return err
	}
	for _, rec := range seals {
		data, err := r.SealPage(rec.SealHash)
		if err != nil {
			return err
		}
		html, err := r.Render(data)
		if err != nil {
			return err
		}
		if err := writeBytes(filepath.Join(cfg.OutDir, "seal", site.SealDir(rec.SealHash), "index.html"), html); err != nil {
			return err
		}
	}
	return nil
}

func copyVerify(cfg Config) error {
	dst := filepath.Join(cfg.OutDir, "verify")
	if err := site.CopyVerify(dst); err != nil {
		return err
	}
	wasm := cfg.WASMPath
	if wasm == "" && cfg.SpecPath != "" {
		wasm = filepath.Join(filepath.Dir(cfg.SpecPath), "internal", "site", "verify", "plimsoll_verify.wasm")
	}
	if wasm == "" {
		return nil
	}
	b, err := os.ReadFile(wasm) //nolint:gosec // G304 -- operator-supplied wasm path
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return writeBytes(filepath.Join(dst, "plimsoll_verify.wasm"), b)
}

func writeJSON(path string, v any) error {
	b, err := marshalJSON(v)
	if err != nil {
		return err
	}
	return writeBytes(path, b)
}

func marshalJSON(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')
	return b, nil
}

func writeBytes(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644) //nolint:gosec // G306 -- public static log
}
