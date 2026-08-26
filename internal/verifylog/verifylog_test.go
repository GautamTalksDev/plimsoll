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

package verifylog

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/GautamTalksDev/plimsoll/internal/log"
)

func TestVerifyDirOK(t *testing.T) {
	dir, pub, _ := seededClone(t, 8)
	res, err := VerifyDir(dir, Options{})
	if err != nil {
		t.Fatalf("VerifyDir: %v", err)
	}
	if res.Leaves != 8 || res.Checkpoints != 8 {
		t.Fatalf("got leaves=%d checkpoints=%d want 8/8", res.Leaves, res.Checkpoints)
	}
	_ = pub
}

func TestVerifyDirEmpty(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "log.sqlite")
	l, err := log.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePublicKeyPEM(filepath.Join(dir, "keys", "log-public.pem"), pub); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyDir(dir, Options{})
	if err != nil {
		t.Fatalf("empty log: %v", err)
	}
	if res.Leaves != 0 || res.Checkpoints != 0 {
		t.Fatalf("want empty, got %+v", res)
	}
}

func TestVerifyDirTamperedCanonical(t *testing.T) {
	dir, _, _ := seededClone(t, 5)
	dbPath := filepath.Join(dir, "log.sqlite")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DROP TRIGGER IF EXISTS seals_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE seals SET canonical = ? WHERE idx = 0`, []byte("tampered-canonical")); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	_, err = VerifyDir(dir, Options{})
	if err == nil {
		t.Fatal("expected failure after hand-edit")
	}
	if !strings.Contains(err.Error(), "leaf_hash mismatch") && !strings.Contains(err.Error(), "root mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyDirBadSignature(t *testing.T) {
	dir, _, _ := seededClone(t, 3)
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePublicKeyPEM(filepath.Join(dir, "keys", "log-public.pem"), other); err != nil {
		t.Fatal(err)
	}
	_, err = VerifyDir(dir, Options{})
	if err == nil || !strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("want signature invalid, got %v", err)
	}
}

func TestScaffoldEmptyPasses(t *testing.T) {
	scaffold := filepath.Join("..", "..", "scaffold", "plimsoll-log")
	if _, err := os.Stat(filepath.Join(scaffold, "log.sqlite")); err != nil {
		t.Skip("scaffold missing")
	}
	res, err := VerifyDir(scaffold, Options{})
	if err != nil {
		t.Fatalf("scaffold: %v", err)
	}
	if res.Leaves != 0 {
		t.Fatalf("scaffold should be empty, got %d leaves", res.Leaves)
	}
}

func seededClone(t *testing.T, n int) (dir string, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	dir = t.TempDir()
	db := filepath.Join(dir, "log.sqlite")
	l, err := log.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			canon := []byte(fmt.Sprintf("plimsoll-canon-v1\n{\"seal\":%d}", i))
			sum := hex.EncodeToString(log.LeafHash(canon))
			if _, err := l.AppendSeal(log.SealInput{
				SealHash: "sha256:" + sum, Canonical: canon, SubmitterID: "org",
			}); err != nil {
				t.Fatal(err)
			}
		} else {
			canon := []byte(fmt.Sprintf("plimsoll-canon-v1\n{\"att\":%d}", i))
			if _, err := l.AppendAttestation(log.AttestationInput{
				SealHash:     "sha256:" + hex.EncodeToString(log.LeafHash([]byte("plimsoll-canon-v1\n{\"seal\":0}"))),
				ResultDigest: fmt.Sprintf("sha256:%064x", i),
				Verdict:      "pass",
				Canonical:    canon,
			}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := l.SignCheckpointAt(priv, 1_700_000_000+int64(i)); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()
	if err := WritePublicKeyPEM(filepath.Join(dir, "keys", "log-public.pem"), pub); err != nil {
		t.Fatal(err)
	}
	return dir, pub, priv
}
