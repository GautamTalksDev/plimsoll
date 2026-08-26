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

//go:build !js

package log

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SignCheckpoint signs the current tree head with priv and stores it.
// The timestamp is the current Unix time; prefer SignCheckpointAt in tests
// and offline builders that require byte-identical output.
func (l *Log) SignCheckpoint(priv ed25519.PrivateKey) (Checkpoint, error) {
	return l.SignCheckpointAt(priv, time.Now().Unix())
}

// SignCheckpointAt signs the current tree head using the given Unix timestamp.
func (l *Log) SignCheckpointAt(priv ed25519.PrivateKey, timestamp int64) (Checkpoint, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(priv) != ed25519.PrivateKeySize {
		return Checkpoint{}, fmt.Errorf("log: invalid ed25519 private key size")
	}

	leaves, err := l.leafHashesLocked()
	if err != nil {
		return Checkpoint{}, err
	}
	root := hex.EncodeToString(MerkleRoot(leaves))
	size := int64(len(leaves))

	payload := checkpointPayload(size, root, timestamp)
	sig := ed25519.Sign(priv, payload)

	cp := Checkpoint{
		TreeSize:  size,
		RootHash:  root,
		Timestamp: timestamp,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}

	_, err = l.db.Exec(
		`INSERT INTO checkpoints (tree_size, root_hash, timestamp, signature) VALUES (?, ?, ?, ?)`,
		cp.TreeSize, cp.RootHash, cp.Timestamp, cp.Signature,
	)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("log: store checkpoint: %w", err)
	}
	return cp, nil
}

func checkpointPayload(treeSize int64, rootHash string, timestamp int64) []byte {
	var b strings.Builder
	b.WriteString(CheckpointVersion)
	b.WriteByte('\n')
	b.WriteString("tree_size=")
	b.WriteString(strconv.FormatInt(treeSize, 10))
	b.WriteByte('\n')
	b.WriteString("root_hash=")
	b.WriteString(rootHash)
	b.WriteByte('\n')
	b.WriteString("timestamp=")
	b.WriteString(strconv.FormatInt(timestamp, 10))
	b.WriteByte('\n')
	return []byte(b.String())
}
