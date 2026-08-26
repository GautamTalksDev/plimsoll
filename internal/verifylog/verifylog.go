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

// Package verifylog replays a cloned plimsoll-log SQLite database and checks
// that every committed checkpoint matches a recomputed Merkle root and that
// every checkpoint signature verifies against the published public key.
package verifylog

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/GautamTalksDev/plimsoll/internal/log"
)

const (
	defaultDBRel  = "log.sqlite"
	defaultKeyRel = "keys/log-public.pem"
)

// Result is a successful offline log replay.
type Result struct {
	Leaves      int64  `json:"leaves"`
	Checkpoints int    `json:"checkpoints"`
	KeyPath     string `json:"key_path"`
	DBPath      string `json:"db_path"`
}

// Options configures VerifyDir.
type Options struct {
	// KeyPath overrides keys/log-public.pem under Dir.
	KeyPath string
	// DBPath overrides log.sqlite under Dir.
	DBPath string
}

// VerifyDir opens Dir as a plimsoll-log clone: log.sqlite plus the published
// Ed25519 public key. It recomputes every leaf from canonical bytes, rebuilds
// Merkle roots for each stored checkpoint size, and verifies each signature.
func VerifyDir(dir string, opt Options) (*Result, error) {
	if dir == "" {
		return nil, fmt.Errorf("verifylog: --dir is required")
	}
	dbPath := opt.DBPath
	if dbPath == "" {
		dbPath = filepath.Join(dir, defaultDBRel)
	}
	keyPath := opt.KeyPath
	if keyPath == "" {
		keyPath = filepath.Join(dir, defaultKeyRel)
	}

	pub, err := LoadPublicKey(keyPath)
	if err != nil {
		return nil, err
	}
	l, err := log.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("verifylog: open %s: %w", dbPath, err)
	}
	defer func() { _ = l.Close() }()

	if err := Verify(l, pub); err != nil {
		return nil, err
	}
	size, err := l.Size()
	if err != nil {
		return nil, err
	}
	cps, err := l.AllCheckpoints()
	if err != nil {
		return nil, err
	}
	return &Result{
		Leaves:      size,
		Checkpoints: len(cps),
		KeyPath:     keyPath,
		DBPath:      dbPath,
	}, nil
}

// Verify replays l against pub: leaf hashes, roots, and checkpoint signatures.
func Verify(l *log.Log, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("verifylog: invalid log public key size")
	}
	size, err := l.Size()
	if err != nil {
		return err
	}
	entries, err := l.Entries(0, size)
	if err != nil {
		return fmt.Errorf("verifylog: entries: %w", err)
	}
	if int64(len(entries)) != size {
		return fmt.Errorf("verifylog: entry count %d != size %d", len(entries), size)
	}

	leaves := make([][]byte, 0, len(entries))
	for i, e := range entries {
		if e.Index != int64(i) {
			return fmt.Errorf("verifylog: leaf index gap: got %d want %d", e.Index, i)
		}
		canonical, err := base64.StdEncoding.DecodeString(e.CanonicalB64)
		if err != nil {
			return fmt.Errorf("verifylog: entry %d canonical: %w", e.Index, err)
		}
		got := log.LeafHash(canonical)
		wantHex := hex.EncodeToString(got)
		if e.LeafHash != wantHex {
			return fmt.Errorf("verifylog: entry %d leaf_hash mismatch: stored %s recomputed %s",
				e.Index, e.LeafHash, wantHex)
		}
		leaves = append(leaves, got)
	}

	cps, err := l.AllCheckpoints()
	if err != nil {
		return err
	}
	if size == 0 {
		if len(cps) == 0 {
			return nil
		}
		// Empty tree may still carry a size-0 signed head.
	}
	if size > 0 && len(cps) == 0 {
		return fmt.Errorf("verifylog: log has %d leaves but no checkpoints", size)
	}

	var maxSize int64
	for _, cp := range cps {
		if cp.TreeSize < 0 || cp.TreeSize > size {
			return fmt.Errorf("verifylog: checkpoint tree_size %d out of range (size %d)", cp.TreeSize, size)
		}
		root := hex.EncodeToString(log.MerkleRoot(leaves[:cp.TreeSize]))
		if cp.RootHash != root {
			return fmt.Errorf("verifylog: checkpoint tree_size %d root mismatch: stored %s recomputed %s",
				cp.TreeSize, cp.RootHash, root)
		}
		if !log.VerifyCheckpoint(pub, cp) {
			return fmt.Errorf("verifylog: checkpoint tree_size %d signature invalid", cp.TreeSize)
		}
		if cp.TreeSize > maxSize {
			maxSize = cp.TreeSize
		}
	}
	if size > 0 && maxSize != size {
		return fmt.Errorf("verifylog: latest checkpoint covers tree_size %d but log has %d leaves", maxSize, size)
	}
	return nil
}

// LoadPublicKey loads an Ed25519 public key from a PKIX PEM file (or raw 32 bytes).
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304 -- operator-supplied key path
	if err != nil {
		return nil, fmt.Errorf("verifylog: read key %s: %w", path, err)
	}
	if len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(append([]byte(nil), b...)), nil
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("verifylog: %s: not a PEM public key", path)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("verifylog: parse %s: %w", path, err)
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("verifylog: %s: not an Ed25519 public key", path)
	}
	return ed, nil
}

// WritePublicKeyPEM writes pub as a PKIX PEM file (mode 0644).
func WritePublicKeyPEM(path string, pub ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o644)
}
