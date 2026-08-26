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

// SealRecord is a seal row stored in the log.
type SealRecord struct {
	Idx         int64
	SealHash    string
	Canonical   []byte
	SubmitterID string
	SubmittedAt int64
	Supersedes  string
	LeafHash    string
	Signature   string
	PublicKey   string
}

// AllSeals returns every seal row in Merkle-index order.
func (l *Log) AllSeals() ([]SealRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rows, err := l.db.Query(`
		SELECT idx, seal_hash, canonical, submitter_id, submitted_at, supersedes, leaf_hash, signature, public_key
		FROM seals ORDER BY idx ASC`)
	if err != nil {
		return nil, fmt.Errorf("log: all seals: %w", err)
	}
	defer rows.Close()
	var out []SealRecord
	for rows.Next() {
		var r SealRecord
		if err := rows.Scan(&r.Idx, &r.SealHash, &r.Canonical, &r.SubmitterID, &r.SubmittedAt, &r.Supersedes, &r.LeafHash,
			&r.Signature, &r.PublicKey); err != nil {
			return nil, fmt.Errorf("log: scan seal: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SealByHash returns the seal row for sealHash, if present.
func (l *Log) SealByHash(sealHash string) (SealRecord, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var r SealRecord
	err := l.db.QueryRow(`
		SELECT idx, seal_hash, canonical, submitter_id, submitted_at, supersedes, leaf_hash, signature, public_key
		FROM seals WHERE seal_hash = ?`, sealHash).Scan(
		&r.Idx, &r.SealHash, &r.Canonical, &r.SubmitterID, &r.SubmittedAt, &r.Supersedes, &r.LeafHash,
		&r.Signature, &r.PublicKey,
	)
	if err == sql.ErrNoRows {
		return SealRecord{}, false, nil
	}
	if err != nil {
		return SealRecord{}, false, fmt.Errorf("log: seal by hash: %w", err)
	}
	return r, true, nil
}
