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
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type caseFile struct {
	Pairs []struct {
		Name      string `json:"name"`
		Left      string `json:"left"`
		Right     string `json:"right"`
		WantEqual bool   `json:"want_equal"`
		Note      string `json:"note"`
	} `json:"pairs"`
	Nested                 string   `json:"nested"`
	DatasetRows            []string `json:"dataset_rows"`
	DatasetTrailingNewline []string `json:"dataset_trailing_newline"`
}

func testdataDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "canonical")
}

func readTD(t *testing.T, name string) []byte {
	t.Helper()
	if name != filepath.Base(name) {
		t.Fatalf("fixture name must be a base name: %q", name)
	}
	b, err := os.ReadFile(filepath.Join(testdataDir(t), name)) //nolint:gosec // basename of a committed testdata fixture
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

func loadCases(t *testing.T) caseFile {
	t.Helper()
	var c caseFile
	if err := json.Unmarshal(readTD(t, "cases.json"), &c); err != nil {
		t.Fatalf("cases.json: %v", err)
	}
	return c
}

func TestVersionPrefixesPresentAndDistinct(t *testing.T) {
	t.Parallel()
	if CanonVersionPrefix == "" || DatasetVersionPrefix == "" {
		t.Fatal("version prefixes must be non-empty")
	}
	if CanonVersionPrefix == DatasetVersionPrefix {
		t.Fatal("canon and dataset prefixes must be distinct")
	}
	if !strings.HasPrefix(CanonVersionPrefix, "plimsoll-canon-v1") {
		t.Fatalf("CanonVersionPrefix = %q", CanonVersionPrefix)
	}
	if !strings.HasPrefix(DatasetVersionPrefix, "plimsoll-dataset-v1") {
		t.Fatalf("DatasetVersionPrefix = %q", DatasetVersionPrefix)
	}
}

func TestHashPairsFromTestdata(t *testing.T) {
	t.Parallel()
	cases := loadCases(t)
	for _, c := range cases.Pairs {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			left, err := Hash(readTD(t, c.Left))
			if err != nil {
				t.Fatalf("left: %v", err)
			}
			right, err := Hash(readTD(t, c.Right))
			if err != nil {
				t.Fatalf("right: %v", err)
			}
			equal := left == right
			if equal != c.WantEqual {
				t.Fatalf("Hash(%s)=%s Hash(%s)=%s equal=%v want %v\nnote: %s",
					c.Left, left, c.Right, right, equal, c.WantEqual, c.Note)
			}
			if !strings.HasPrefix(left, "sha256:") || !strings.HasPrefix(right, "sha256:") {
				t.Fatalf("hash must use sha256: prefix: %q %q", left, right)
			}
		})
	}
}

func TestNestedFiveLevels(t *testing.T) {
	t.Parallel()
	raw := readTD(t, loadCases(t).Nested)
	a, err := Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("nested canonicalize is not deterministic")
	}
	if !bytes.HasPrefix(a, []byte(CanonVersionPrefix)) {
		t.Fatalf("missing canon prefix: %q", a[:min(len(a), 32)])
	}
	depth := bytes.Count(raw, []byte(`{"`))
	if depth < 5 {
		t.Fatalf("fixture is not 5 levels deep, saw %d object opens", depth)
	}
}

func TestDatasetRowsReorderedIdenticalHash(t *testing.T) {
	t.Parallel()
	files := loadCases(t).DatasetRows
	a := json.RawMessage(readTD(t, files[0]))
	b := json.RawMessage(readTD(t, files[1]))
	h1, err := HashDataset([]json.RawMessage{a, b})
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashDataset([]json.RawMessage{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("row order affected hash: %s vs %s", h1, h2)
	}
	canon, err := CanonicalizeDataset([]json.RawMessage{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(canon, []byte(DatasetVersionPrefix)) {
		t.Fatalf("missing dataset prefix: %q", canon[:min(len(canon), 40)])
	}
}

func TestDatasetDuplicateRowDifferentHash(t *testing.T) {
	t.Parallel()
	files := loadCases(t).DatasetRows
	a := json.RawMessage(readTD(t, files[0]))
	b := json.RawMessage(readTD(t, files[1]))
	unique, err := HashDataset([]json.RawMessage{a, b})
	if err != nil {
		t.Fatal(err)
	}
	dup, err := HashDataset([]json.RawMessage{a, b, a})
	if err != nil {
		t.Fatal(err)
	}
	if unique == dup {
		t.Fatal("duplicate row did not change dataset hash")
	}
}

func TestDatasetTrailingNewlineIdenticalHash(t *testing.T) {
	t.Parallel()
	files := loadCases(t).DatasetTrailingNewline
	plain := json.RawMessage(readTD(t, files[0]))
	trailing := json.RawMessage(readTD(t, files[1]))
	h1, err := HashDataset([]json.RawMessage{plain})
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashDataset([]json.RawMessage{trailing})
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("trailing newline affected hash: %s vs %s", h1, h2)
	}
}

func TestTwoMiBInputErrorNotHash(t *testing.T) {
	t.Parallel()
	in := bytes.Repeat([]byte("a"), 2<<20)
	_, err := Canonicalize(in)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Canonicalize 2MiB: err=%v want ErrTooLarge", err)
	}
	h, err := Hash(in)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Hash 2MiB: err=%v want ErrTooLarge", err)
	}
	if h != "" {
		t.Fatalf("Hash 2MiB returned %q", h)
	}
}

func TestCanonicalizeInvalidJSON(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"", "   ", "{", `{"a":1}{"b":2}`, "not-json"} {
		_, err := Canonicalize([]byte(in))
		if !errors.Is(err, ErrInvalidJSON) {
			t.Errorf("Canonicalize(%q) err=%v want ErrInvalidJSON", in, err)
		}
	}
}

func TestCanonicalizePreservesControlAndZeroWidth(t *testing.T) {
	t.Parallel()
	raw := readTD(t, "zwsp.json")
	out, err := Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte{0xe2, 0x80, 0x8b}) {
		t.Fatalf("zero-width space was stripped: %q", out)
	}
}

func TestHashDatasetEmpty(t *testing.T) {
	t.Parallel()
	h, err := HashDataset(nil)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashDataset([]json.RawMessage{})
	if err != nil {
		t.Fatal(err)
	}
	if h != h2 {
		t.Fatalf("nil vs empty dataset: %s vs %s", h, h2)
	}
}

func TestDecimalPrecision6EqualNeighbor(t *testing.T) {
	t.Parallel()
	a, err := ParseDecimal("0.82", 6)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseDecimal("0.8200000000000001", 6)
	if err != nil {
		t.Fatal(err)
	}
	if a.Cmp(b) != 0 {
		t.Fatalf("0.82 vs 0.8200000000000001 at precision 6: Cmp=%d want 0", a.Cmp(b))
	}
}

func TestDecimalPrecision6NotEqual(t *testing.T) {
	t.Parallel()
	a, err := ParseDecimal("0.82", 6)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseDecimal("0.821", 6)
	if err != nil {
		t.Fatal(err)
	}
	if a.Cmp(b) == 0 {
		t.Fatal("0.82 vs 0.821 at precision 6 compared equal")
	}
}

func TestDecimalErrors(t *testing.T) {
	t.Parallel()
	if _, err := ParseDecimal("0.82", -1); !errors.Is(err, ErrPrecision) {
		t.Fatalf("neg precision: %v", err)
	}
	if _, err := ParseDecimal("0.82", 19); !errors.Is(err, ErrPrecision) {
		t.Fatalf("oversize precision: %v", err)
	}
	if _, err := ParseDecimal("", 6); !errors.Is(err, ErrInvalidDecimal) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := ParseDecimal("not-a-number", 6); !errors.Is(err, ErrInvalidDecimal) {
		t.Fatalf("junk: %v", err)
	}
	if _, err := ParseDecimal("1/2", 6); !errors.Is(err, ErrInvalidDecimal) {
		t.Fatalf("slash: %v", err)
	}
}

func TestDecimalCmpSignAndScale(t *testing.T) {
	t.Parallel()
	neg, err := ParseDecimal("-1.5", 2)
	if err != nil {
		t.Fatal(err)
	}
	pos, err := ParseDecimal("1.5", 2)
	if err != nil {
		t.Fatal(err)
	}
	if neg.Cmp(pos) >= 0 {
		t.Fatal("expected negative < positive")
	}
	wide, err := ParseDecimal("1.50", 2)
	if err != nil {
		t.Fatal(err)
	}
	narrow, err := ParseDecimal("1.5", 1)
	if err != nil {
		t.Fatal(err)
	}
	if wide.Cmp(narrow) != 0 {
		t.Fatal("1.50@2 vs 1.5@1 should be equal")
	}
	zero := Decimal{}
	if zero.Cmp(zero) != 0 {
		t.Fatal("zero Decimal Cmp")
	}
}

func TestHashDatasetPropagatesRowError(t *testing.T) {
	t.Parallel()
	_, err := HashDataset([]json.RawMessage{[]byte("{")})
	if !errors.Is(err, ErrInvalidJSON) {
		t.Fatalf("err=%v", err)
	}
}

func TestNormalizeUnexpectedType(t *testing.T) {
	t.Parallel()
	if _, err := normalizeValue(make(chan int)); err == nil {
		t.Fatal("expected error for unexpected type")
	}
}

func TestDecimalNegativeRoundingHalfAway(t *testing.T) {
	t.Parallel()
	got, err := ParseDecimal("-0.825", 2)
	if err != nil {
		t.Fatal(err)
	}
	want, err := ParseDecimal("-0.83", 2)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(want) != 0 {
		t.Fatalf("half away from zero: Cmp=%d", got.Cmp(want))
	}
}

func TestCanonicalizeBoolAndNullAndArray(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"true", "false", "null", "[]", "[1,2,3]"} {
		c, err := Canonicalize([]byte(in))
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if !bytes.HasPrefix(c, []byte(CanonVersionPrefix)) {
			t.Fatalf("%s missing prefix", in)
		}
	}
}
