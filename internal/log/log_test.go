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
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func openTempLog(t *testing.T) *Log {
	t.Helper()
	path := filepath.Join(t.TempDir(), "log.sqlite")
	l, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func testSealCanon(i int) []byte {
	return []byte(fmt.Sprintf("plimsoll-canon-v1\n{\"kind\":\"seal\",\"n\":%d}", i))
}

func testAttCanon(sealHash string, attempt int) []byte {
	return []byte(fmt.Sprintf("plimsoll-canon-v1\n{\"kind\":\"att\",\"seal\":%q,\"attempt\":%d}", sealHash, attempt))
}

func testSealHash(i int) string {
	sum := hex.EncodeToString(LeafHash(testSealCanon(i)))
	return "sha256:" + sum
}

func appendMixed(l *Log, i int) (int64, error) {
	if i%3 == 0 {
		return l.AppendSeal(SealInput{
			SealHash:    testSealHash(i),
			Canonical:   testSealCanon(i),
			SubmitterID: fmt.Sprintf("org-%d", i%11),
		})
	}
	sealIdx := (i / 3) * 3
	sealHash := testSealHash(sealIdx)
	return l.AppendAttestation(AttestationInput{
		SealHash:     sealHash,
		ResultDigest: fmt.Sprintf("sha256:%064x", i),
		Verdict:      "pass",
		Canonical:    testAttCanon(sealHash, i),
	})
}

func TestAppendOnlyTriggersSeals(t *testing.T) {
	l := openTempLog(t)
	idx, err := l.AppendSeal(SealInput{
		SealHash:    testSealHash(0),
		Canonical:   testSealCanon(0),
		SubmitterID: "org-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if idx != 0 {
		t.Fatalf("idx=%d want 0", idx)
	}

	db := l.dbForTest()
	_, err = db.Exec(`UPDATE seals SET submitter_id = 'corrupted' WHERE idx = 0`)
	if err == nil {
		t.Fatal("UPDATE on seals succeeded; trigger failed")
	}
	t.Logf("seals UPDATE blocked: %v", err)

	_, err = db.Exec(`DELETE FROM seals WHERE idx = 0`)
	if err == nil {
		t.Fatal("DELETE on seals succeeded; trigger failed")
	}
	t.Logf("seals DELETE blocked: %v", err)

	var submitter string
	if err := db.QueryRow(`SELECT submitter_id FROM seals WHERE idx = 0`).Scan(&submitter); err != nil {
		t.Fatal(err)
	}
	if submitter != "org-a" {
		t.Fatalf("row corrupted: %q", submitter)
	}
}

func TestAppendOnlyTriggersAttestations(t *testing.T) {
	l := openTempLog(t)
	sealHash := testSealHash(0)
	if _, err := l.AppendSeal(SealInput{
		SealHash:    sealHash,
		Canonical:   testSealCanon(0),
		SubmitterID: "org-a",
	}); err != nil {
		t.Fatal(err)
	}
	idx, err := l.AppendAttestation(AttestationInput{
		SealHash:     sealHash,
		ResultDigest: "sha256:" + strings.Repeat("b", 64),
		Verdict:      "pass",
		Canonical:    testAttCanon(sealHash, 1),
	})
	if err != nil {
		t.Fatal(err)
	}

	db := l.dbForTest()
	_, err = db.Exec(`UPDATE attestations SET verdict = 'corrupted' WHERE idx = ?`, idx)
	if err == nil {
		t.Fatal("UPDATE on attestations succeeded; trigger failed")
	}
	t.Logf("attestations UPDATE blocked: %v", err)

	_, err = db.Exec(`DELETE FROM attestations WHERE idx = ?`, idx)
	if err == nil {
		t.Fatal("DELETE on attestations succeeded; trigger failed")
	}
	t.Logf("attestations DELETE blocked: %v", err)

	var verdict string
	if err := db.QueryRow(`SELECT verdict FROM attestations WHERE idx = ?`, idx).Scan(&verdict); err != nil {
		t.Fatal(err)
	}
	if verdict != "pass" {
		t.Fatalf("row corrupted: %q", verdict)
	}
}

func TestMerkleTenThousandMixed(t *testing.T) {
	l := openTempLog(t)
	const n = 10_000

	for i := 0; i < n; i++ {
		idx, err := appendMixed(l, i)
		if err != nil {
			t.Fatalf("append(%d): %v", i, err)
		}
		if idx != int64(i) {
			t.Fatalf("append(%d): idx=%d", i, idx)
		}
	}

	size, err := l.Size()
	if err != nil {
		t.Fatal(err)
	}
	if size != n {
		t.Fatalf("size=%d want %d", size, n)
	}

	leaves := mustLeafHashes(t, l)
	independentRoot := MerkleRoot(leaves)
	rootHex, err := l.RootHash()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(independentRoot) != rootHex {
		t.Fatalf("root mismatch")
	}

	rng := rand.Reader
	seen := map[int64]bool{}
	for len(seen) < 64 {
		v, err := rand.Int(rng, big.NewInt(n))
		if err != nil {
			t.Fatal(err)
		}
		seen[v.Int64()] = true
	}
	for idx := range seen {
		p, err := l.InclusionProof(idx)
		if err != nil {
			t.Fatalf("InclusionProof(%d): %v", idx, err)
		}
		if !VerifyInclusion(int(p.Index), int(p.TreeSize), p.LeafHash, p.AuditPath, p.RootHash) {
			t.Fatalf("VerifyInclusion failed idx=%d", idx)
		}
		if !VerifyInclusion(int(idx), n, leaves[idx], p.AuditPath, independentRoot) {
			t.Fatalf("independent inclusion failed idx=%d", idx)
		}
	}

	oldSize, newSize := int64(3_000), int64(n)
	cp, err := l.ConsistencyProof(oldSize, newSize)
	if err != nil {
		t.Fatal(err)
	}
	oldRoot := MerkleRoot(leaves[:oldSize])
	if !VerifyConsistency(int(oldSize), int(newSize), oldRoot, independentRoot, cp.AuditPath) {
		t.Fatal("VerifyConsistency failed")
	}

	oldSize = 4096
	cp, err = l.ConsistencyProof(oldSize, newSize)
	if err != nil {
		t.Fatal(err)
	}
	oldRoot = MerkleRoot(leaves[:oldSize])
	if !VerifyConsistency(int(oldSize), int(newSize), oldRoot, independentRoot, cp.AuditPath) {
		t.Fatal("VerifyConsistency failed for power-of-two oldSize")
	}
}

func TestConcurrentAttemptNumbering(t *testing.T) {
	l := openTempLog(t)
	sealHash := "sha256:" + strings.Repeat("c", 64)
	if _, err := l.AppendSeal(SealInput{
		SealHash:    sealHash,
		Canonical:   []byte("plimsoll-canon-v1\n{\"seal\":true}"),
		SubmitterID: "org-concurrent",
	}); err != nil {
		t.Fatal(err)
	}

	const workers = 5
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := l.AppendAttestation(AttestationInput{
				SealHash:     sealHash,
				ResultDigest: fmt.Sprintf("sha256:%064d", i),
				Verdict:      "pass",
				Canonical:    []byte(fmt.Sprintf("plimsoll-canon-v1\n{\"worker\":%d}", i)),
			})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	attempts, err := l.AttemptsForSeal(sealHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != workers {
		t.Fatalf("attempts=%d want %d", len(attempts), workers)
	}
	seen := map[int]bool{}
	for i, a := range attempts {
		if i > 0 && a.AttemptNo <= attempts[i-1].AttemptNo {
			t.Fatalf("not ordered: %v", attempts)
		}
		if a.AttemptNo < 1 || a.AttemptNo > workers {
			t.Fatalf("attempt_no out of range: %d", a.AttemptNo)
		}
		if seen[a.AttemptNo] {
			t.Fatalf("duplicate attempt_no %d", a.AttemptNo)
		}
		seen[a.AttemptNo] = true
	}
	if len(seen) != workers {
		t.Fatalf("gaps in attempt_no: got %v", seen)
	}
}

func TestCheckpointSignVerify(t *testing.T) {
	l := openTempLog(t)
	for i := 0; i < 5; i++ {
		if _, err := appendMixed(l, i); err != nil {
			t.Fatal(err)
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := l.SignCheckpoint(priv)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyCheckpoint(pub, cp) {
		t.Fatal("VerifyCheckpoint failed")
	}
	cp.RootHash = "00" + cp.RootHash[2:]
	if VerifyCheckpoint(pub, cp) {
		t.Fatal("VerifyCheckpoint accepted tampered checkpoint")
	}
}

func TestAttemptsForSealOrder(t *testing.T) {
	l := openTempLog(t)
	sealHash := testSealHash(0)
	if _, err := l.AppendSeal(SealInput{
		SealHash:    sealHash,
		Canonical:   testSealCanon(0),
		SubmitterID: "org",
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := l.AppendAttestation(AttestationInput{
			SealHash:     sealHash,
			ResultDigest: fmt.Sprintf("sha256:%064d", i),
			Verdict:      "pass",
			Canonical:    testAttCanon(sealHash, i+1),
		}); err != nil {
			t.Fatal(err)
		}
	}
	attempts, err := l.AttemptsForSeal(sealHash)
	if err != nil {
		t.Fatal(err)
	}
	for i, a := range attempts {
		if a.AttemptNo != i+1 {
			t.Fatalf("attempt[%d].AttemptNo=%d want %d", i, a.AttemptNo, i+1)
		}
	}
}

func TestRFC6962EmptyRoot(t *testing.T) {
	got := hex.EncodeToString(EmptyRoot())
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Fatalf("EmptyRoot=%s want %s", got, want)
	}
}

func TestLeafDomainSeparation(t *testing.T) {
	entry := []byte("plimsoll-canon-v1\n{}")
	leaf := LeafHash(entry)
	node := NodeHash(leaf, leaf)
	if bytesEqual(leaf, node) {
		t.Fatal("leaf and node hashes must differ (domain separation)")
	}
}

func TestWindowsAMD64Build(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not on PATH")
	}
	cmd := exec.Command("go", "build", "-o", os.DevNull, ".")
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("windows/amd64 build failed: %v\n%s", err, out)
	}
}

func TestNoUpdateDeleteMethodsExist(t *testing.T) {
	var _ interface {
		AppendSeal(SealInput) (int64, error)
		AppendAttestation(AttestationInput) (int64, error)
		InclusionProof(int64) (InclusionProof, error)
		ConsistencyProof(int64, int64) (ConsistencyProof, error)
		SignCheckpoint(ed25519.PrivateKey) (Checkpoint, error)
		AttemptsForSeal(string) ([]Attempt, error)
	} = (*Log)(nil)
}

func TestTriggersExist(t *testing.T) {
	l := openTempLog(t)
	db := l.dbForTest()
	for _, name := range []string{
		"seals_no_update", "seals_no_delete",
		"attestations_no_update", "attestations_no_delete",
	} {
		var got string
		err := db.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='trigger' AND name=?`, name,
		).Scan(&got)
		if err == sql.ErrNoRows {
			t.Fatalf("trigger %s missing", name)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func mustLeafHashes(t *testing.T, l *Log) [][]byte {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	leaves, err := l.leafHashesLocked()
	if err != nil {
		t.Fatal(err)
	}
	return leaves
}
