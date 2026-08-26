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
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/GautamTalksDev/plimsoll/internal/canonical"
	"github.com/GautamTalksDev/plimsoll/internal/cliout"
	"github.com/GautamTalksDev/plimsoll/internal/datasetload"
)

// hashMode is never inferred from file contents. A prompt whose entire body is
// "true" or "123" is valid JSON, and auto-detection would hash it as a boolean
// or a number rather than as text. Two prompts differing only in whether they
// happen to parse would then be treated differently, silently, which is the
// class of bug this canonicalizer exists to prevent.
type hashMode string

const (
	modeText    hashMode = "text"
	modeJSON    hashMode = "json"
	modeDataset hashMode = "dataset"
)

func newHashCmd(root *rootFlags) *cobra.Command {
	var (
		asJSONDoc bool
		asDataset bool
	)

	cmd := &cobra.Command{
		Use:   "hash <file>",
		Short: "Compute the canonical digest of a prompt, config or dataset file",
		Long: `Print the digest a seal needs for prompt_sha256, config_sha256 or
dataset.sha256. Everything is computed locally; this command makes no
network request.

Three modes, always explicit and never inferred from the contents:

  (default)   the file is an opaque text document, hashed under
              plimsoll-canon-v1 as a JSON string. Use this for prompts.
  --json-doc  the file is a JSON document, hashed under plimsoll-canon-v1.
              Fails if it does not parse. Use this for config files.
  --dataset   the file is JSONL or a JSON array, hashed under
              plimsoll-dataset-v1 as a sorted multiset of rows. Prints the
              row count, which a seal records separately as dataset.n.

The mode is not detected from the file, because a prompt whose entire body
is "true" is valid JSON and hashing it as a boolean rather than as text
would be silently wrong.

Note that 'plimsoll seal' already fills in dataset.sha256 and dataset.n
from dataset.path. --dataset exists to check that digest by hand.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cliout.New()
			out.JSON = root.json

			if asJSONDoc && asDataset {
				return fmt.Errorf("--json-doc and --dataset are mutually exclusive")
			}
			mode := modeText
			switch {
			case asDataset:
				mode = modeDataset
			case asJSONDoc:
				mode = modeJSON
			}

			path := args[0]
			digest, n, err := hashFile(path, mode)
			if err != nil {
				return err
			}

			if root.json {
				payload := map[string]any{
					"file":   path,
					"mode":   string(mode),
					"digest": digest,
				}
				if mode == modeDataset {
					payload["n"] = n
					payload["canon_version"] = strings.TrimSuffix(canonical.DatasetVersionPrefix, "\n")
				} else {
					payload["canon_version"] = strings.TrimSuffix(canonical.CanonVersionPrefix, "\n")
				}
				return out.EmitJSON(payload)
			}

			out.Printf("%s\n", digest)
			switch mode {
			case modeDataset:
				out.Printf("\nplimsoll-dataset-v1, %d rows.\n", n)
				out.Printf("In your pre-registration:\n")
				out.Printf("  dataset:\n")
				out.Printf("    sha256: %q\n", digest)
				out.Printf("    n: %d\n", n)
			case modeJSON:
				out.Printf("\nplimsoll-canon-v1 over a JSON document. Use for config_sha256.\n")
			default:
				out.Printf("\nplimsoll-canon-v1 over an opaque text document. Use for prompt_sha256.\n")
				out.Printf("If this file is meant to be JSON, re-run with --json-doc:\n")
				out.Printf("the two modes produce different digests.\n")
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSONDoc, "json-doc", false, "hash the file as a JSON document (config_sha256)")
	cmd.Flags().BoolVar(&asDataset, "dataset", false, "hash the file as a dataset multiset (dataset.sha256)")
	return cmd
}

// hashFile returns the digest and, for datasets, the row count.
func hashFile(path string, mode hashMode) (string, int, error) {
	if mode == modeDataset {
		return datasetload.HashFile(path)
	}

	b, err := os.ReadFile(path) //nolint:gosec // G304 -- a user-supplied path is the point of this command
	if err != nil {
		return "", 0, err
	}

	var raw json.RawMessage
	if mode == modeJSON {
		if !json.Valid(b) {
			return "", 0, fmt.Errorf("%s is not valid JSON; drop --json-doc to hash it as text", path)
		}
		raw = json.RawMessage(b)
	} else {
		// An opaque document becomes a JSON string, so canonicalization applies
		// NFC and CRLF normalization to its contents exactly as it would to any
		// other string value in a seal.
		encoded, err := json.Marshal(string(b))
		if err != nil {
			return "", 0, err
		}
		raw = json.RawMessage(encoded)
	}

	digest, err := canonical.Hash(raw)
	if err != nil {
		return "", 0, err
	}
	return digest, 0, nil
}
