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

package datasetload

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/GautamTalksDev/plimsoll/internal/canonical"
)

// Load reads a local dataset file (JSON array or JSONL) and returns rows for
// hashing. The file never leaves the caller's machine.
func Load(path string) ([]json.RawMessage, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("dataset: path required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("dataset: read %s: %w", path, err)
	}
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, fmt.Errorf("dataset: %s is empty", path)
	}
	if b[0] == '[' {
		var rows []json.RawMessage
		if err := json.Unmarshal(b, &rows); err != nil {
			return nil, fmt.Errorf("dataset: parse array: %w", err)
		}
		if len(rows) == 0 {
			return nil, fmt.Errorf("dataset: no rows")
		}
		return rows, nil
	}
	return loadJSONL(b, path)
}

func loadJSONL(b []byte, path string) ([]json.RawMessage, error) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var rows []json.RawMessage
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if !json.Valid(line) {
			return nil, fmt.Errorf("dataset: %s:%d: invalid JSON", filepath.Base(path), lineNo)
		}
		rows = append(rows, append(json.RawMessage(nil), line...))
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("dataset: scan: %w", err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("dataset: no rows in %s", path)
	}
	return rows, nil
}

// HashFile hashes a dataset file locally.
func HashFile(path string) (hash string, n int, err error) {
	rows, err := Load(path)
	if err != nil {
		return "", 0, err
	}
	hash, err = canonical.HashDataset(rows)
	if err != nil {
		return "", 0, err
	}
	return hash, len(rows), nil
}
