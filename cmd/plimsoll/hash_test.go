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

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// These digests come from the seal published to the public log at index 3 on
// 26 August 2026. They are not computed by this test; they are transcribed
// from a signed, logged artifact. If this test fails, either the command
// changed or the canonicalizer did, and every seal ever published is affected.
const (
	knownPromptDigest  = "sha256:ab20e9b0d7fb7e3128263c8aaadb8e0f1de754ad684ff5d533fd6ebc92db87a5"
	knownConfigDigest  = "sha256:715a8c894b0559b2feddd824ca7856a86403450c97f5347f272b73a59bf31dc2"
	knownDatasetDigest = "sha256:5289446f67a9b7354610f30776ada803032e150b34103b8fc82c5e2799c292ab"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHashFileMatchesPublishedSeal(t *testing.T) {
	dir := t.TempDir()

	prompt := writeFile(t, dir, "prompt.txt", "You are a terse factual assistant.\n")
	got, _, err := hashFile(prompt, modeText)
	if err != nil {
		t.Fatalf("text: %v", err)
	}
	if got != knownPromptDigest {
		t.Errorf("prompt digest changed:\n got %s\nwant %s", got, knownPromptDigest)
	}

	config := writeFile(t, dir, "config.json", "{\"temperature\":0,\"max_tokens\":16}\n")
	got, _, err = hashFile(config, modeJSON)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	if got != knownConfigDigest {
		t.Errorf("config digest changed:\n got %s\nwant %s", got, knownConfigDigest)
	}

	rows := `{"id":1,"question":"2+2","expected":"4"}
{"id":2,"question":"capital of France","expected":"Paris"}
{"id":3,"question":"3*3","expected":"9"}
{"id":4,"question":"largest ocean","expected":"Pacific"}
{"id":5,"question":"10/2","expected":"5"}
`
	dataset := writeFile(t, dir, "eval.jsonl", rows)
	got, n, err := hashFile(dataset, modeDataset)
	if err != nil {
		t.Fatalf("dataset: %v", err)
	}
	if got != knownDatasetDigest {
		t.Errorf("dataset digest changed:\n got %s\nwant %s", got, knownDatasetDigest)
	}
	if n != 5 {
		t.Errorf("row count: got %d want 5", n)
	}
}

// The mode must never be inferred. A prompt whose entire body is valid JSON
// must still hash as text, or two prompts differing only in whether they
// happen to parse would be treated differently without the user seeing it.
func TestHashModeIsNeverInferred(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "ambiguous.txt", "true")

	asText, _, err := hashFile(p, modeText)
	if err != nil {
		t.Fatal(err)
	}
	asJSON, _, err := hashFile(p, modeJSON)
	if err != nil {
		t.Fatal(err)
	}
	if asText == asJSON {
		t.Error("a body of \"true\" hashed identically as text and as JSON; the modes are not distinct")
	}
}

func TestHashJSONModeRejectsNonJSON(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "prose.txt", "this is not json")
	if _, _, err := hashFile(p, modeJSON); err == nil {
		t.Error("--json-doc accepted a non-JSON file")
	}
}
