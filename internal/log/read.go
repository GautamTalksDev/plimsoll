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

// AttemptsForSeal returns attestations for sealHash ordered by attempt_no.
func (l *Log) AttemptsForSeal(sealHash string) ([]Attempt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	rows, err := l.db.Query(`
		SELECT idx, attempt_no, seal_hash, result_digest, verdict, submitted_at, leaf_hash
		FROM attestations
		WHERE seal_hash = ?
		ORDER BY attempt_no ASC`, sealHash)
	if err != nil {
		return nil, fmt.Errorf("log: attempts for seal: %w", err)
	}
	defer rows.Close()

	var out []Attempt
	for rows.Next() {
		var a Attempt
		if err := rows.Scan(&a.Idx, &a.AttemptNo, &a.SealHash, &a.ResultDigest, &a.Verdict, &a.SubmittedAt, &a.LeafHash); err != nil {
			return nil, fmt.Errorf("log: scan attempt: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CanonicalAt returns the canonical bytes stored at global Merkle index idx.
func (l *Log) CanonicalAt(idx int64) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var b []byte
	err := l.db.QueryRow(`SELECT canonical FROM seals WHERE idx = ?`, idx).Scan(&b)
	if err == nil {
		return b, nil
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("log: seal canonical: %w", err)
	}
	err = l.db.QueryRow(`SELECT canonical FROM attestations WHERE idx = ?`, idx).Scan(&b)
	if err != nil {
		return nil, fmt.Errorf("log: entry %d: %w", idx, err)
	}
	return b, nil
}
