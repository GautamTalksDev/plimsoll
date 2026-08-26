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

package sealfile

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/seal"
)

var safeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// SafeBaseName returns a filesystem-safe basename derived from subject.
func SafeBaseName(subject string) string {
	name := safeName.ReplaceAllString(subject, "_")
	if name == "" {
		return "seal"
	}
	return name
}

// Document is a signed seal artifact written by the CLI.
type Document struct {
	SealHash       string                `json:"seal_hash"`
	PublicKey      string                `json:"public_key"`
	Seal           *seal.SignedSeal      `json:"seal"`
	InclusionProof *StoredInclusionProof `json:"inclusion_proof,omitempty"`
	Checkpoint     *log.Checkpoint       `json:"checkpoint,omitempty"`
	LogIndex       *int64                `json:"log_index,omitempty"`
}

// StoredInclusionProof is a serializable Merkle inclusion proof.
type StoredInclusionProof struct {
	Index     int64    `json:"index"`
	TreeSize  int64    `json:"tree_size"`
	LeafHash  string   `json:"leaf_hash"`
	AuditPath []string `json:"audit_path"`
	RootHash  string   `json:"root_hash"`
}

// Write writes doc to <subject-name>.seal.json in dir.
func Write(dir string, doc *Document) (string, error) {
	if doc == nil || doc.Seal == nil || doc.Seal.Seal == nil {
		return "", fmt.Errorf("sealfile: empty document")
	}
	path := filepath.Join(dir, SafeBaseName(doc.Seal.Seal.Subject.Name)+".seal.json")
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil { //nolint:gosec // G306 -- public seal artifact
		return "", err
	}
	return path, nil
}

// Read loads a seal document from path.
func Read(path string) (*Document, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc Document
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("sealfile: parse: %w", err)
	}
	return &doc, nil
}

// PublicKeyBytes decodes doc.PublicKey.
func (d *Document) PublicKeyBytes() (ed25519.PublicKey, error) {
	if d == nil || d.PublicKey == "" {
		return nil, fmt.Errorf("sealfile: missing public_key")
	}
	b, err := base64.StdEncoding.DecodeString(d.PublicKey)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("sealfile: invalid public key size")
	}
	return ed25519.PublicKey(b), nil
}

// Verify checks the seal signature and optional inclusion proof against pub.
func (d *Document) Verify(pub ed25519.PublicKey) error {
	if err := seal.VerifySignature(pub, d.Seal); err != nil {
		return err
	}
	if d.SealHash == "" {
		return fmt.Errorf("sealfile: missing seal_hash")
	}
	got, err := d.Seal.Seal.CanonicalHash()
	if err != nil {
		return err
	}
	if got != d.SealHash {
		return fmt.Errorf("sealfile: seal_hash mismatch")
	}
	if d.InclusionProof == nil {
		return nil
	}
	return d.verifyInclusion()
}

func (d *Document) verifyInclusion() error {
	p := d.InclusionProof
	leaf, err := decodeHexHash(p.LeafHash)
	if err != nil {
		return err
	}
	root, err := decodeHexHash(p.RootHash)
	if err != nil {
		return err
	}
	path := make([][]byte, len(p.AuditPath))
	for i, h := range p.AuditPath {
		path[i], err = decodeHexHash(h)
		if err != nil {
			return err
		}
	}
	if !log.VerifyInclusion(int(p.Index), int(p.TreeSize), leaf, path, root) {
		return fmt.Errorf("sealfile: inclusion proof failed")
	}
	if d.LogIndex != nil && *d.LogIndex != p.Index {
		return fmt.Errorf("sealfile: log_index mismatch")
	}
	return nil
}

func decodeHexHash(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.ToLower(s), "sha256:")
	if len(s) != 64 {
		return nil, fmt.Errorf("sealfile: invalid hash %q", s)
	}
	return hexDecode(s)
}

func hexDecode(s string) ([]byte, error) {
	dst := make([]byte, len(s)/2)
	for i := 0; i < len(dst); i++ {
		var v byte
		for j := 0; j < 2; j++ {
			c := s[i*2+j]
			switch {
			case c >= '0' && c <= '9':
				v = v<<4 + c - '0'
			case c >= 'a' && c <= 'f':
				v = v<<4 + c - 'a' + 10
			default:
				return nil, fmt.Errorf("sealfile: invalid hex")
			}
		}
		dst[i] = v
	}
	return dst, nil
}

// StoreProof converts a log inclusion proof to stored form.
func StoreProof(p log.InclusionProof) StoredInclusionProof {
	audit := make([]string, len(p.AuditPath))
	for i, h := range p.AuditPath {
		audit[i] = hexEncode(h)
	}
	return StoredInclusionProof{
		Index:     p.Index,
		TreeSize:  p.TreeSize,
		LeafHash:  hexEncode(p.LeafHash),
		AuditPath: audit,
		RootHash:  hexEncode(p.RootHash),
	}
}

func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}
