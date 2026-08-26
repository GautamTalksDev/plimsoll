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
	"database/sql"
	"fmt"
)

// AllCheckpoints returns every stored signed tree head row, ordered by
// tree_size then timestamp. Duplicate sizes (if any) are all included.
func (l *Log) AllCheckpoints() ([]Checkpoint, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rows, err := l.db.Query(`
		SELECT tree_size, root_hash, timestamp, signature
		FROM checkpoints
		ORDER BY tree_size ASC, timestamp ASC`)
	if err != nil {
		return nil, fmt.Errorf("log: list checkpoints: %w", err)
	}
	defer rows.Close()
	var out []Checkpoint
	for rows.Next() {
		var cp Checkpoint
		if err := rows.Scan(&cp.TreeSize, &cp.RootHash, &cp.Timestamp, &cp.Signature); err != nil {
			return nil, fmt.Errorf("log: scan checkpoint: %w", err)
		}
		out = append(out, cp)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if out == nil {
		out = []Checkpoint{}
	}
	return out, nil
}

// Checkpoints returns every stored signed tree head, one per tree_size
// (latest timestamp wins if several exist for the same size), ordered by size.
func (l *Log) Checkpoints() ([]Checkpoint, error) {
	all, err := l.AllCheckpoints()
	if err != nil {
		return nil, err
	}
	bySize := make(map[int64]Checkpoint)
	var order []int64
	for _, cp := range all {
		if _, seen := bySize[cp.TreeSize]; !seen {
			order = append(order, cp.TreeSize)
		}
		bySize[cp.TreeSize] = cp
	}
	out := make([]Checkpoint, 0, len(order))
	for _, sz := range order {
		out = append(out, bySize[sz])
	}
	return out, nil
}

// LatestCheckpoint returns the most recently stored signed tree head.
func (l *Log) LatestCheckpoint() (Checkpoint, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var cp Checkpoint
	err := l.db.QueryRow(`
		SELECT tree_size, root_hash, timestamp, signature
		FROM checkpoints ORDER BY tree_size DESC LIMIT 1`).Scan(
		&cp.TreeSize, &cp.RootHash, &cp.Timestamp, &cp.Signature,
	)
	if err == sql.ErrNoRows {
		return Checkpoint{}, fmt.Errorf("log: no checkpoints")
	}
	if err != nil {
		return Checkpoint{}, fmt.Errorf("log: latest checkpoint: %w", err)
	}
	return cp, nil
}

// CheckpointAt returns a stored checkpoint for an exact tree size, if any.
func (l *Log) CheckpointAt(treeSize int64) (Checkpoint, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var cp Checkpoint
	err := l.db.QueryRow(`
		SELECT tree_size, root_hash, timestamp, signature
		FROM checkpoints WHERE tree_size = ?`, treeSize).Scan(
		&cp.TreeSize, &cp.RootHash, &cp.Timestamp, &cp.Signature,
	)
	if err == sql.ErrNoRows {
		return Checkpoint{}, fmt.Errorf("log: checkpoint size %d not found", treeSize)
	}
	if err != nil {
		return Checkpoint{}, err
	}
	return cp, nil
}

// SealIndex returns the global Merkle index for sealHash, or -1 if absent.
func (l *Log) SealIndex(sealHash string) (int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var idx int64
	err := l.db.QueryRow(`SELECT idx FROM seals WHERE seal_hash = ?`, sealHash).Scan(&idx)
	if err == sql.ErrNoRows {
		return -1, nil
	}
	if err != nil {
		return -1, err
	}
	return idx, nil
}

// AttestationByDigest returns the log index and attempt_no for an attestation.
func (l *Log) AttestationByDigest(sealHash, resultDigest string) (idx int64, attemptNo int, ok bool, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	err = l.db.QueryRow(`
		SELECT idx, attempt_no FROM attestations
		WHERE seal_hash = ? AND result_digest = ?`,
		sealHash, resultDigest).Scan(&idx, &attemptNo)
	if err == sql.ErrNoRows {
		return 0, 0, false, nil
	}
	if err != nil {
		return 0, 0, false, err
	}
	return idx, attemptNo, true, nil
}

// AttestationByAttempt returns attestation row for seal_hash and attempt_no.
func (l *Log) AttestationByAttempt(sealHash string, attemptNo int) (Attempt, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var a Attempt
	err := l.db.QueryRow(`
		SELECT idx, attempt_no, seal_hash, result_digest, verdict, submitted_at, leaf_hash
		FROM attestations WHERE seal_hash = ? AND attempt_no = ?`,
		sealHash, attemptNo).Scan(
		&a.Idx, &a.AttemptNo, &a.SealHash, &a.ResultDigest, &a.Verdict, &a.SubmittedAt, &a.LeafHash,
	)
	if err == sql.ErrNoRows {
		return Attempt{}, false, nil
	}
	if err != nil {
		return Attempt{}, false, err
	}
	return a, true, nil
}
