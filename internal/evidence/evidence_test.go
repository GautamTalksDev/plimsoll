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

package evidence_test

import (
	"bytes"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GautamTalksDev/plimsoll/internal/evidence"
	"github.com/GautamTalksDev/plimsoll/internal/keys"
	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/logd"
	"github.com/GautamTalksDev/plimsoll/internal/verify"
)

func TestPDFDeterministic(t *testing.T) {
	env := publishForEvidence(t)
	pack, err := evidence.Build(evidence.Options{
		SealRef:  env.sealFile,
		LogURL:   env.srv.URL,
		AttestDir: env.dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	pdf1, err := evidence.ToPDF(pack)
	if err != nil {
		t.Fatal(err)
	}
	pdf2, err := evidence.ToPDF(pack)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pdf1, pdf2) {
		t.Fatalf("PDF not byte-identical across runs (%d vs %d bytes)", len(pdf1), len(pdf2))
	}
	if !bytes.HasPrefix(pdf1, []byte("%PDF-1.4")) {
		t.Fatal("missing PDF header")
	}
}

func TestEvidencePackContents(t *testing.T) {
	env := publishForEvidence(t)
	pack, err := evidence.Build(evidence.Options{
		SealRef: env.sealHash, LogURL: env.srv.URL, AttestDir: env.dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pack.Version != evidence.Version {
		t.Fatalf("version=%q", pack.Version)
	}
	if pack.Preregistration.YAML == "" {
		t.Fatal("missing prereg yaml")
	}
	if len(pack.Attempts) != 1 {
		t.Fatalf("attempts=%d", len(pack.Attempts))
	}
	if len(pack.Attempts[0].Verification.Checks) != 9 {
		t.Fatalf("checks=%d", len(pack.Attempts[0].Verification.Checks))
	}
	if pack.Attempts[0].VerifyURL == "" {
		t.Fatal("missing per-attempt verify_url")
	}
	if pack.VerifyURL == "" {
		t.Fatal("missing pack verify_url")
	}
	if len(pack.Instructions) == 0 {
		t.Fatal("missing instructions")
	}
	foundVerifier := false
	for _, step := range pack.Instructions {
		if strings.Contains(step, evidence.DefaultBrowserVerifierURL) {
			foundVerifier = true
			break
		}
	}
	if !foundVerifier {
		t.Fatal("missing browser verifier URL in instructions")
	}
}

func TestCLIEvidenceJSON(t *testing.T) {
	env := publishForEvidence(t)
	outPath := filepath.Join(env.dir, "pack.json")
	plimsoll := buildPlimsoll(t)
	out, err := runPlimsoll(plimsoll, env.dir, "evidence",
		"--seal", env.sealFile,
		"--log", env.srv.URL,
		"--format", "json",
		"--out", outPath,
	)
	if err != nil {
		t.Fatalf("evidence cli: %v\n%s", err, out)
	}
	b, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"version": "plimsoll-evidence-v1"`) {
		t.Fatalf("bad json: %s", string(b[:min(200, len(b))]))
	}
}

type evidenceEnv struct {
	dir      string
	srv      *httptest.Server
	sealFile string
	sealHash string
}

func publishForEvidence(t *testing.T) *evidenceEnv {
	t.Helper()
	dir := t.TempDir()
	copyTree(t, filepath.Join("..", "..", "testdata", "e2e"), dir)
	key := filepath.Join(dir, "test.key")
	logPath := filepath.Join(dir, "log.sqlite")
	plimsoll := buildPlimsoll(t)
	prereg := filepath.Join(dir, "prereg.yaml")
	if out, err := runPlimsoll(plimsoll, dir, "seal", "--file", prereg, "--key", key, "--publish", "--log", logPath); err != nil {
		t.Fatalf("seal: %v\n%s", err, out)
	}
	sealFile := filepath.Join(dir, "e2e-claim.seal.json")
	if out, err := runPlimsoll(plimsoll, dir, "attest", "--seal", sealFile, "--results", filepath.Join(dir, "results_pass.json"), "--key", key, "--publish", "--log", logPath); err != nil {
		t.Fatalf("attest: %v\n%s", err, out)
	}
	priv, pub, err := keys.LoadOrCreate(key)
	if err != nil {
		t.Fatal(err)
	}
	l, err := log.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(logd.New(logd.Config{Log: l, PrivKey: priv, PublicKey: pub}).Handler())
	t.Cleanup(func() {
		srv.Close()
		_ = l.Close()
	})
	doc, err := verify.LoadAttestation(filepath.Join(dir, "e2e-claim.attest.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &evidenceEnv{dir: dir, srv: srv, sealFile: sealFile, sealHash: doc.SealHash}
}

func buildPlimsoll(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "plimsoll")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = filepath.Join("..", "..", "cmd", "plimsoll")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}
	return out
}

func runPlimsoll(bin, dir string, args ...string) (string, error) {
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	_ = filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
