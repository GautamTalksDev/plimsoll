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
	"encoding/base64"
	"fmt"
)

// Entries returns paginated log entries with global indices in [from, to).
// to is exclusive. from must be >= 0.
func (l *Log) Entries(from, to int64) ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	size := l.next
	if from < 0 || from > size || to < from {
		return nil, fmt.Errorf("log: invalid entry range [%d,%d) size %d", from, to, size)
	}
	if to > size {
		to = size
	}
	if from >= to {
		return []Entry{}, nil
	}
	rows, err := l.db.Query(`
		SELECT idx, kind, seal_hash, attempt_no, result_digest, verdict, canonical, leaf_hash, submitted_at FROM (
			SELECT idx, 'seal' AS kind, seal_hash, 0 AS attempt_no, '' AS result_digest, '' AS verdict,
				canonical, leaf_hash, submitted_at FROM seals
			UNION ALL
			SELECT idx, 'attestation' AS kind, seal_hash, attempt_no, result_digest, verdict,
				canonical, leaf_hash, submitted_at FROM attestations
		)
		WHERE idx >= ? AND idx < ?
		ORDER BY idx ASC`, from, to)
	if err != nil {
		return nil, fmt.Errorf("log: entries: %w", err)
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var canonical []byte
		var attemptNo int
		var resultDigest, verdict string
		if err := rows.Scan(&e.Index, &e.Kind, &e.SealHash, &attemptNo, &resultDigest, &verdict,
			&canonical, &e.LeafHash, &e.SubmittedAt); err != nil {
			return nil, err
		}
		e.CanonicalB64 = base64.StdEncoding.EncodeToString(canonical)
		if e.Kind == "attestation" {
			e.AttemptNo = attemptNo
			e.ResultDigest = resultDigest
			e.Verdict = verdict
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// SealSummary is a seal row with attempt summary for directory listings.
type SealSummary struct {
	SealHash        string `json:"seal_hash"`
	SubjectName     string `json:"subject_name"`
	SubmittedAt     int64  `json:"submitted_at"`
	Supersedes      string `json:"supersedes,omitempty"`
	AttemptCount    int    `json:"attempt_count"`
	LatestVerdict   string `json:"latest_verdict,omitempty"`
	LatestAttemptNo int    `json:"latest_attempt_no,omitempty"`
	Index           int64  `json:"index"`
}

// RecentSeals returns the newest seals up to limit, with attempt summaries.
func (l *Log) RecentSeals(limit int) ([]SealSummary, error) {
	if limit <= 0 {
		limit = 50
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	rows, err := l.db.Query(`
		SELECT idx, seal_hash, submitter_id, submitted_at, supersedes
		FROM seals ORDER BY idx DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SealSummary
	for rows.Next() {
		var s SealSummary
		if err := rows.Scan(&s.Index, &s.SealHash, &s.SubjectName, &s.SubmittedAt, &s.Supersedes); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		attempts, err := l.attemptsForSealLocked(out[i].SealHash)
		if err != nil {
			return nil, err
		}
		out[i].AttemptCount = len(attempts)
		if len(attempts) > 0 {
			last := attempts[len(attempts)-1]
			out[i].LatestVerdict = last.Verdict
			out[i].LatestAttemptNo = last.AttemptNo
		}
	}
	return out, nil
}

func (l *Log) attemptsForSealLocked(sealHash string) ([]Attempt, error) {
	rows, err := l.db.Query(`
		SELECT idx, attempt_no, seal_hash, result_digest, verdict, submitted_at, leaf_hash
		FROM attestations WHERE seal_hash = ? ORDER BY attempt_no ASC`, sealHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Attempt
	for rows.Next() {
		var a Attempt
		if err := rows.Scan(&a.Idx, &a.AttemptNo, &a.SealHash, &a.ResultDigest, &a.Verdict, &a.SubmittedAt, &a.LeafHash); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
