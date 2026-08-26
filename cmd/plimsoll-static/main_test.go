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

package main_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/logmerkle"
	"github.com/GautamTalksDev/plimsoll/internal/sealfile"
	"github.com/GautamTalksDev/plimsoll/internal/staticlog"
)

func TestPlimsollStatic(t *testing.T) {
	priv, pub := testKey(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "log.sqlite")
	l := buildBigLog(t, dbPath, priv)

	keyPath := filepath.Join(dir, "log-signing.key")
	if err := os.WriteFile(keyPath, []byte(priv), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := filepath.Join(dir, "SPEC-PREREG.md")
	if err := os.WriteFile(spec, []byte("# Spec\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out1 := filepath.Join(dir, "public1")
	out2 := filepath.Join(dir, "public2")

	// Library path (same code the CLI calls).
	cfg := staticlog.Config{
		Log: l, OutDir: out1, PublicKey: pub,
		BaseURL: "https://plimsoll.example.test", SpecPath: spec,
	}
	if err := staticlog.Generate(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.OutDir = out2
	if err := staticlog.Generate(cfg); err != nil {
		t.Fatal(err)
	}
	assertTreesEqual(t, out1, out2)
	assertInclusionProofs(t, out1, l)
	assertXSSInert(t, out1)
	assertNoRowContent(t, out1)

	// CLI binary path.
	bin := filepath.Join(dir, "plimsoll-static")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = filepath.Join(repoRoot(t), "cmd", "plimsoll-static")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	out3 := filepath.Join(dir, "public3")
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	run := exec.Command(bin,
		"-db", dbPath, "-out", out3, "-key", keyPath,
		"-base-url", "https://plimsoll.example.test", "-spec", spec,
	)
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	assertTreesEqual(t, out1, out3)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// cmd/plimsoll-static -> repo root
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func buildBigLog(t *testing.T, dbPath string, priv ed25519.PrivateKey) *log.Log {
	t.Helper()
	l, err := log.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	xssName := `<script>alert(1)</script>`
	baseTS := int64(1_700_000_000)

	for i := 0; i < 50; i++ {
		name := nameFor(i, xssName)
		canon := []byte(fmt.Sprintf(
			"plimsoll-canon-v1\n"+`{"kind":"seal","n":%d,"name":%q,"reason":%q}`,
			i, name, xssName,
		))
		hash := "sha256:" + hex.EncodeToString(log.LeafHash(canon))
		if _, err := l.AppendSeal(log.SealInput{
			SealHash: hash, Canonical: canon, SubmitterID: name,
			SubmittedAt: baseTS + int64(i),
			Supersedes:  "", Signature: "dGVzdA==", PublicKey: "dGVzdA==",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := l.SignCheckpointAt(priv, baseTS+1000+int64(i)); err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < 200; i++ {
		sealIdx := i % 50
		canonSeal := []byte(fmt.Sprintf(
			"plimsoll-canon-v1\n"+`{"kind":"seal","n":%d,"name":%q,"reason":%q}`,
			sealIdx, nameFor(sealIdx, xssName), xssName,
		))
		sealHash := "sha256:" + hex.EncodeToString(log.LeafHash(canonSeal))
		attCanon := []byte(fmt.Sprintf(
			"plimsoll-canon-v1\n"+`{"kind":"att","seal":%q,"i":%d}`,
			sealHash, i,
		))
		if _, err := l.AppendAttestation(log.AttestationInput{
			SealHash: sealHash, ResultDigest: fmt.Sprintf("sha256:%064x", i),
			Verdict: "pass", Canonical: attCanon, SubmittedAt: baseTS + 10_000 + int64(i),
		}); err != nil {
			t.Fatal(err)
		}
		if i%10 == 0 {
			if _, err := l.SignCheckpointAt(priv, baseTS+20_000+int64(i)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := l.SignCheckpointAt(priv, baseTS+99_999); err != nil {
		t.Fatal(err)
	}
	return l
}

func nameFor(i int, xss string) string {
	if i == 7 {
		return xss
	}
	return fmt.Sprintf("org-%d", i)
}

func testKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func assertTreesEqual(t *testing.T, a, b string) {
	t.Helper()
	filesA := readTree(t, a)
	filesB := readTree(t, b)
	if len(filesA) != len(filesB) {
		t.Fatalf("file count %d vs %d", len(filesA), len(filesB))
	}
	for rel, ba := range filesA {
		bb, ok := filesB[rel]
		if !ok {
			t.Fatalf("missing in b: %s", rel)
		}
		if !bytes.Equal(ba, bb) {
			t.Fatalf("differs: %s", rel)
		}
	}
}

func readTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func assertInclusionProofs(t *testing.T, out string, l *log.Log) {
	t.Helper()
	cpRaw, err := os.ReadFile(filepath.Join(out, "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	var cp struct {
		RootHash string `json:"root_hash"`
	}
	if err := json.Unmarshal(cpRaw, &cp); err != nil {
		t.Fatal(err)
	}
	root, err := hex.DecodeString(cp.RootHash)
	if err != nil {
		t.Fatal(err)
	}
	size, err := l.Size()
	if err != nil {
		t.Fatal(err)
	}
	for i := int64(0); i < size; i++ {
		raw, err := os.ReadFile(filepath.Join(out, "proof", "inclusion", fmt.Sprintf("%d", i)))
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			InclusionProof sealfile.StoredInclusionProof `json:"inclusion_proof"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		p := body.InclusionProof
		leaf, err := hex.DecodeString(p.LeafHash)
		if err != nil {
			t.Fatal(err)
		}
		path := make([][]byte, len(p.AuditPath))
		for j, h := range p.AuditPath {
			path[j], err = hex.DecodeString(h)
			if err != nil {
				t.Fatal(err)
			}
		}
		if !logmerkle.VerifyInclusion(int(p.Index), int(p.TreeSize), leaf, path, root) {
			t.Fatalf("inclusion failed idx=%d", i)
		}
	}
}

func assertXSSInert(t *testing.T, out string) {
	t.Helper()
	xss := `<script>alert(1)</script>`
	sealRoot := filepath.Join(out, "seal")
	entries, err := os.ReadDir(sealRoot)
	if err != nil {
		t.Fatal(err)
	}
	foundHTML := false
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		htmlPath := filepath.Join(sealRoot, e.Name(), "index.html")
		b, err := os.ReadFile(htmlPath)
		if err != nil {
			continue
		}
		s := string(b)
		if strings.Contains(s, xss) {
			t.Fatalf("unescaped script in %s", htmlPath)
		}
		if strings.Contains(s, "&lt;script&gt;") {
			foundHTML = true
		}
		badgePath := filepath.Join(sealRoot, e.Name(), "badge.svg")
		bb, err := os.ReadFile(badgePath)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(bb), xss) {
			t.Fatalf("unescaped script in badge %s", badgePath)
		}
	}
	if !foundHTML {
		t.Fatal("expected escaped subject name in at least one seal index.html")
	}
	sealsPage, err := os.ReadFile(filepath.Join(out, "seals", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealsPage), xss) {
		t.Fatal("unescaped xss in seals/index.html")
	}
	if !strings.Contains(string(sealsPage), "&lt;script&gt;") {
		t.Fatal("expected escaped xss in seals listing")
	}
}

func assertNoRowContent(t *testing.T, out string) {
	t.Helper()
	needles := []string{`"prompt":`, `"output":`, `"messages":`, "dataset row", "model_weights"}
	err := filepath.WalkDir(out, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		low := strings.ToLower(string(b))
		for _, n := range needles {
			if strings.Contains(low, strings.ToLower(n)) {
				return fmt.Errorf("%s contains %q", path, n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
