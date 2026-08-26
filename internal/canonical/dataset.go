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

package canonical

import (
	"bytes"
	"encoding/json"
	"sort"
)

// CanonicalizeDataset canonicalizes an unordered multiset of rows.
//
// This function runs ONLY on the user's machine, on their local data.
// The library never transmits rows anywhere. Digests leave the machine;
// the rows themselves do not.
//
// A dataset is a multiset: duplicate rows are retained, so a dataset
// with a duplicated row hashes differently from the same rows with
// duplicates removed. Callers must also record len(rows) as separate
// metadata next to the hash (row count is not inferred from the digest).
//
// Each row is Canonicalize'd, the resulting byte sequences are sorted
// lexicographically, joined with 0x0A, and prefixed with
// DatasetVersionPrefix.
func CanonicalizeDataset(rows []json.RawMessage) ([]byte, error) {
	canons := make([][]byte, len(rows))
	for i, row := range rows {
		c, err := Canonicalize(row)
		if err != nil {
			return nil, err
		}
		canons[i] = c
	}
	sort.Slice(canons, func(i, j int) bool {
		return bytes.Compare(canons[i], canons[j]) < 0
	})
	var buf bytes.Buffer
	buf.Grow(len(DatasetVersionPrefix) + len(rows)*8)
	buf.WriteString(DatasetVersionPrefix)
	for i, c := range canons {
		if i > 0 {
			buf.WriteByte(0x0A)
		}
		buf.Write(c)
	}
	return buf.Bytes(), nil
}

// HashDataset returns "sha256:<hex>" of CanonicalizeDataset(rows).
func HashDataset(rows []json.RawMessage) (string, error) {
	canon, err := CanonicalizeDataset(rows)
	if err != nil {
		return "", err
	}
	return "sha256:" + sha256Sum(canon), nil
}
