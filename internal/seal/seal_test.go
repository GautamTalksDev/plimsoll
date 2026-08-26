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

package seal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func testdata(t *testing.T, name string) []byte {
	t.Helper()
	if filepath.Base(name) != name {
		t.Fatalf("bad name %q", name)
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "testdata", "seal", name)) //nolint:gosec
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func valid(t *testing.T) *Seal {
	t.Helper()
	s, err := Parse(testdata(t, "valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestParseJSONAndYAML(t *testing.T) {
	t.Parallel()
	js, err := Parse(testdata(t, "valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	ym, err := Parse(testdata(t, "valid.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := js.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := ym.Validate(); err != nil {
		t.Fatal(err)
	}
	hj, err := js.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	hy, err := ym.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	if hj != hy {
		t.Fatalf("json/yaml hashes differ:\n%s\n%s", hj, hy)
	}
}

func TestUnknownTopLevelField(t *testing.T) {
	t.Parallel()
	raw := testdata(t, "valid.json")
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["forward_compat"] = []byte("true")
	in, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(in)
	var u *UnknownFieldError
	if !errors.As(err, &u) || u.Field != "forward_compat" {
		t.Fatalf("got %v", err)
	}
}

func TestUnknownTopLevelFieldYAML(t *testing.T) {
	t.Parallel()
	in := append(testdata(t, "valid.yaml"), []byte("\nextra_field: 1\n")...)
	_, err := Parse(in)
	var u *UnknownFieldError
	if !errors.As(err, &u) || u.Field != "extra_field" {
		t.Fatalf("got %v", err)
	}
}

func TestPlannedAttempts(t *testing.T) {
	t.Parallel()
	s := valid(t)
	s.PlannedAttempts = 0
	err := s.Validate()
	var e *PlannedAttemptsError
	if !errors.As(err, &e) || e.N != 0 {
		t.Fatalf("got %v", err)
	}
}

func TestDatasetErrors(t *testing.T) {
	t.Parallel()
	s := valid(t)
	s.Dataset.N = 0
	err := s.Validate()
	var e *DatasetError
	if !errors.As(err, &e) {
		t.Fatalf("n<=0: %v", err)
	}
	s = valid(t)
	s.Dataset.SHA256 = ""
	err = s.Validate()
	if !errors.As(err, &e) {
		t.Fatalf("missing sha256: %v", err)
	}
}

func TestUnknownMetric(t *testing.T) {
	t.Parallel()
	s := valid(t)
	s.DecisionRule.Expression = "nope.mean >= 0.82"
	err := s.Validate()
	var e *UnknownMetricError
	if !errors.As(err, &e) || e.ID != "nope" {
		t.Fatalf("got %v", err)
	}
}

func TestExpressionParseFailure(t *testing.T) {
	t.Parallel()
	s := valid(t)
	s.DecisionRule.Expression = "acc.mean + 1 >= 0.82"
	err := s.Validate()
	var e *ExpressionError
	if !errors.As(err, &e) {
		t.Fatalf("got %v", err)
	}
}

func TestPrecision(t *testing.T) {
	t.Parallel()
	for _, p := range []int{0, 13} {
		s := valid(t)
		s.DecisionRule.Precision = p
		err := s.Validate()
		var e *PrecisionError
		if !errors.As(err, &e) || e.Precision != p {
			t.Fatalf("precision %d: %v", p, err)
		}
	}
}

func TestSignVerify(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := valid(t)
	ss, err := s.Sign(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(pub, ss); err != nil {
		t.Fatal(err)
	}
	ss.Signature[0] ^= 1
	if err := VerifySignature(pub, ss); err == nil {
		t.Fatal("expected verify failure")
	}
}

func TestCanonicalHashStable(t *testing.T) {
	t.Parallel()
	s := valid(t)
	a, err := s.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	if a != b || len(a) != len("sha256:")+64 {
		t.Fatalf("hash %q", a)
	}
}
