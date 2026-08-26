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

package log

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// SealInput is a seal to append. Only digests and metadata are stored.
type SealInput struct {
	SealHash    string
	Canonical   []byte
	SubmitterID string
	SubmittedAt int64 // zero means now
	Supersedes  string
	Signature   string // base64 Ed25519 over canonical seal bytes
	PublicKey   string // base64 Ed25519 public key of seal author
}

// AttestationInput is an attestation to append. AttemptNo must not be set;
// the log assigns it inside a transaction.
type AttestationInput struct {
	SealHash     string
	ResultDigest string
	Verdict      string
	Canonical    []byte
	SubmittedAt  int64 // zero means now
}

// Log is a Merkle append-only log.
type Log struct {
	db   *sql.DB
	mu   sync.Mutex
	next int64 // next global Merkle leaf index
}

// Open opens or creates a SQLite-backed log at path.
func Open(path string) (*Log, error) {
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("log: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	l := &Log{db: db}
	if err := l.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := l.restoreNext(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return l, nil
}

// Close closes the database.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.db == nil {
		return nil
	}
	err := l.db.Close()
	l.db = nil
	return err
}

func (l *Log) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS seals (
  idx INTEGER PRIMARY KEY,
  seal_hash TEXT NOT NULL UNIQUE,
  canonical BLOB NOT NULL,
  submitter_id TEXT NOT NULL,
  submitted_at INTEGER NOT NULL,
  supersedes TEXT NOT NULL DEFAULT '',
  leaf_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attestations (
  idx INTEGER PRIMARY KEY,
  seal_hash TEXT NOT NULL,
  attempt_no INTEGER NOT NULL,
  result_digest TEXT NOT NULL,
  verdict TEXT NOT NULL,
  canonical BLOB NOT NULL,
  submitted_at INTEGER NOT NULL,
  leaf_hash TEXT NOT NULL,
  UNIQUE(seal_hash, attempt_no)
);

CREATE TABLE IF NOT EXISTS checkpoints (
  tree_size INTEGER NOT NULL,
  root_hash TEXT NOT NULL,
  timestamp INTEGER NOT NULL,
  signature TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS seals_no_update
BEFORE UPDATE ON seals
BEGIN
  SELECT RAISE(ABORT, 'seals are append-only: UPDATE forbidden');
END;

CREATE TRIGGER IF NOT EXISTS seals_no_delete
BEFORE DELETE ON seals
BEGIN
  SELECT RAISE(ABORT, 'seals are append-only: DELETE forbidden');
END;

CREATE TRIGGER IF NOT EXISTS attestations_no_update
BEFORE UPDATE ON attestations
BEGIN
  SELECT RAISE(ABORT, 'attestations are append-only: UPDATE forbidden');
END;

CREATE TRIGGER IF NOT EXISTS attestations_no_delete
BEFORE DELETE ON attestations
BEGIN
  SELECT RAISE(ABORT, 'attestations are append-only: DELETE forbidden');
END;
`
	if _, err := l.db.Exec(schema); err != nil {
		return fmt.Errorf("log: migrate: %w", err)
	}
	for _, col := range []struct{ name, typ string }{
		{"signature", "TEXT NOT NULL DEFAULT ''"},
		{"public_key", "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := l.ensureColumn("seals", col.name, col.typ); err != nil {
			return err
		}
	}
	return nil
}

func (l *Log) ensureColumn(table, column, decl string) error {
	rows, err := l.db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return fmt.Errorf("log: pragma table_info %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return rows.Err()
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := l.db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + column + ` ` + decl); err != nil {
		return fmt.Errorf("log: add column %s.%s: %w", table, column, err)
	}
	return nil
}

func (l *Log) restoreNext() error {
	var sealMax, attMax sql.NullInt64
	if err := l.db.QueryRow(`SELECT MAX(idx) FROM seals`).Scan(&sealMax); err != nil {
		return fmt.Errorf("log: max seal idx: %w", err)
	}
	if err := l.db.QueryRow(`SELECT MAX(idx) FROM attestations`).Scan(&attMax); err != nil {
		return fmt.Errorf("log: max attestation idx: %w", err)
	}
	max := int64(-1)
	if sealMax.Valid && sealMax.Int64 > max {
		max = sealMax.Int64
	}
	if attMax.Valid && attMax.Int64 > max {
		max = attMax.Int64
	}
	l.next = max + 1
	return nil
}

// AppendSeal appends a seal and returns its global Merkle index.
func (l *Log) AppendSeal(in SealInput) (int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.appendSealLocked(in)
}

func (l *Log) appendSealLocked(in SealInput) (int64, error) {
	if in.SealHash == "" {
		return 0, fmt.Errorf("log: seal_hash required")
	}
	if len(in.Canonical) == 0 {
		return 0, fmt.Errorf("log: canonical bytes required")
	}
	if in.SubmitterID == "" {
		return 0, fmt.Errorf("log: submitter_id required")
	}
	if in.SubmittedAt == 0 {
		in.SubmittedAt = time.Now().Unix()
	}
	if in.Supersedes == "" {
		in.Supersedes = ""
	}

	idx := l.next
	leafHex := hex.EncodeToString(LeafHash(in.Canonical))

	_, err := l.db.Exec(`INSERT INTO seals (
		idx, seal_hash, canonical, submitter_id, submitted_at, supersedes, leaf_hash, signature, public_key
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		idx, in.SealHash, in.Canonical, in.SubmitterID, in.SubmittedAt, in.Supersedes, leafHex,
		in.Signature, in.PublicKey,
	)
	if err != nil {
		return 0, fmt.Errorf("log: append seal: %w", err)
	}
	l.next++
	return idx, nil
}

// AppendAttestation appends an attestation and returns its global Merkle index.
// attempt_no is assigned by the log inside a transaction; the client cannot set it.
func (l *Log) AppendAttestation(in AttestationInput) (int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.appendAttestationLocked(in)
}

func (l *Log) appendAttestationLocked(in AttestationInput) (int64, error) {
	if in.SealHash == "" {
		return 0, fmt.Errorf("log: seal_hash required")
	}
	if len(in.Canonical) == 0 {
		return 0, fmt.Errorf("log: canonical bytes required")
	}
	if in.ResultDigest == "" {
		return 0, fmt.Errorf("log: result_digest required")
	}
	if in.Verdict == "" {
		return 0, fmt.Errorf("log: verdict required")
	}
	if in.SubmittedAt == 0 {
		in.SubmittedAt = time.Now().Unix()
	}

	tx, err := l.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("log: begin attestation tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var attemptNo int
	err = tx.QueryRow(
		`SELECT COALESCE(MAX(attempt_no), 0) + 1 FROM attestations WHERE seal_hash = ?`,
		in.SealHash,
	).Scan(&attemptNo)
	if err != nil {
		return 0, fmt.Errorf("log: next attempt_no: %w", err)
	}

	idx := l.next
	leafHex := hex.EncodeToString(LeafHash(in.Canonical))

	_, err = tx.Exec(`INSERT INTO attestations (
		idx, seal_hash, attempt_no, result_digest, verdict, canonical, submitted_at, leaf_hash
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		idx, in.SealHash, attemptNo, in.ResultDigest, in.Verdict, in.Canonical, in.SubmittedAt, leafHex,
	)
	if err != nil {
		return 0, fmt.Errorf("log: append attestation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("log: commit attestation: %w", err)
	}
	l.next++
	return idx, nil
}

// Size returns the number of leaves in the Merkle tree.
func (l *Log) Size() (int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.next, nil
}

// RootHash returns the current Merkle root as lowercase hex.
func (l *Log) RootHash() (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	leaves, err := l.leafHashesLocked()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(MerkleRoot(leaves)), nil
}

func (l *Log) leafHashesLocked() ([][]byte, error) {
	rows, err := l.db.Query(`
		SELECT leaf_hash FROM (
			SELECT idx, leaf_hash FROM seals
			UNION ALL
			SELECT idx, leaf_hash FROM attestations
		)
		ORDER BY idx ASC`)
	if err != nil {
		return nil, fmt.Errorf("log: leaf hashes: %w", err)
	}
	defer rows.Close()

	out := make([][]byte, 0, l.next)
	for rows.Next() {
		var hexHash string
		if err := rows.Scan(&hexHash); err != nil {
			return nil, fmt.Errorf("log: scan leaf hash: %w", err)
		}
		b, err := hex.DecodeString(hexHash)
		if err != nil {
			return nil, fmt.Errorf("log: decode leaf hash: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// dbForTest exposes the database for corruption tests.
func (l *Log) dbForTest() *sql.DB { return l.db }
