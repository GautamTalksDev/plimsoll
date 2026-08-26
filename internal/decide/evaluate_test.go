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

package decide

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GautamTalksDev/plimsoll/internal/adapt"
	"github.com/GautamTalksDev/plimsoll/internal/canonical"
	"github.com/GautamTalksDev/plimsoll/internal/seal"
)

type fixtureFile struct {
	ID           string                   `json:"id"`
	Seal         fixtureSeal              `json:"seal"`
	ResultSet    fixtureResultSet         `json:"result_set"`
	Expected     json.RawMessage          `json:"-"`
	SkipGolden   bool                     `json:"skip_golden,omitempty"`
	ExtraMetrics map[string]fixtureMetric `json:"extra_metrics,omitempty"`
}

type fixtureSeal struct {
	CanonVersion string              `json:"canon_version"`
	Dataset      fixtureDataset      `json:"dataset"`
	Harness      fixtureHarness      `json:"harness"`
	DecisionRule fixtureDecisionRule `json:"decision_rule"`
}

type fixtureDataset struct {
	N int `json:"n"`
}

type fixtureHarness struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
}

type fixtureDecisionRule struct {
	Expression string `json:"expression"`
	Precision  int    `json:"precision"`
}

type fixtureResultSet struct {
	Harness    string                   `json:"harness"`
	HarnessVer string                   `json:"harness_ver"`
	Metrics    map[string]fixtureMetric `json:"metrics"`
}

type fixtureMetric struct {
	Raw []string `json:"raw"`
	N   int      `json:"n"`
}

func (f *fixtureFile) seal() *seal.Seal {
	return &seal.Seal{
		CanonVersion: f.Seal.CanonVersion,
		Dataset: seal.Dataset{
			N: f.Seal.Dataset.N,
		},
		Harness: seal.Harness{
			Tool:    f.Seal.Harness.Tool,
			Version: f.Seal.Harness.Version,
		},
		DecisionRule: seal.DecisionRule{
			Expression: f.Seal.DecisionRule.Expression,
			Precision:  f.Seal.DecisionRule.Precision,
		},
	}
}

func (f *fixtureFile) resultSet() *adapt.ResultSet {
	metrics := make(map[string]adapt.MetricValues, len(f.ResultSet.Metrics))
	for id, m := range f.ResultSet.Metrics {
		metrics[id] = adapt.MetricValues{
			MetricID: id,
			Raw:      append([]string(nil), m.Raw...),
			N:        m.N,
		}
	}
	return &adapt.ResultSet{
		Harness:    f.ResultSet.Harness,
		HarnessVer: f.ResultSet.HarnessVer,
		Metrics:    metrics,
		RowDigest:  "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		Extra:      json.RawMessage("{}"),
	}
}

func verdictJSON(v *Verdict) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(buf.Bytes()), nil
}

func loadFixtures(t *testing.T) []fixtureFile {
	t.Helper()
	dir := filepath.Join("..", "..", "testdata", "decide")
	expDir := filepath.Join(dir, "expected")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read decide fixtures: %v", err)
	}
	var out []fixtureFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var f fixtureFile
		if err := json.Unmarshal(b, &f); err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		expPath := filepath.Join(expDir, f.ID+".json")
		exp, err := os.ReadFile(expPath)
		if err != nil {
			t.Fatalf("read expected %s: %v", expPath, err)
		}
		f.Expected = exp
		out = append(out, f)
	}
	if len(out) < 30 {
		t.Fatalf("want >= 30 fixtures, got %d", len(out))
	}
	return out
}

func TestEvaluateFixturesGolden(t *testing.T) {
	fixtures := loadFixtures(t)
	for _, f := range fixtures {
		f := f
		t.Run(f.ID, func(t *testing.T) {
			got, err := Evaluate(f.seal(), f.resultSet())
			if err != nil {
				t.Fatal(err)
			}
			gotJSON, err := verdictJSON(got)
			if err != nil {
				t.Fatal(err)
			}
			want := bytes.TrimSpace(f.Expected)
			if len(want) == 0 {
				t.Fatalf("fixture %q missing expected verdict JSON", f.ID)
			}
			if !bytes.Equal(gotJSON, want) {
				t.Fatalf("verdict mismatch\n--- got ---\n%s\n--- want ---\n%s", gotJSON, want)
			}
		})
	}
}

func TestInvalidDistinctFromFail(t *testing.T) {
	fixtures := loadFixtures(t)
	var failCode, invalidCode int
	for _, f := range fixtures {
		v, err := Evaluate(f.seal(), f.resultSet())
		if err != nil {
			t.Fatal(err)
		}
		switch v.Result {
		case "FAIL":
			failCode = v.ExitCode()
		case "INVALID":
			invalidCode = v.ExitCode()
		}
	}
	if failCode != 1 {
		t.Fatalf("FAIL exit code=%d want 1", failCode)
	}
	if invalidCode != 2 {
		t.Fatalf("INVALID exit code=%d want 2", invalidCode)
	}
}

func TestNoSealMutation(t *testing.T) {
	decideDir := filepath.Join("..", "..", "internal", "decide")
	pattern := `s\.(PlimsollVersion|CreatedAt|Subject|Dataset|Harness|Metrics|DecisionRule|Exclusions|PlannedAttempts|AnalysisPlan|CanonVersion|Supersedes)\s*=`
	cmd := exec.Command("grep", "-En", pattern, "--exclude=*_test.go", "-r", decideDir)
	out, _ := cmd.CombinedOutput()
	if len(strings.TrimSpace(string(out))) > 0 {
		t.Fatalf("decide package assigns to seal fields:\n%s", out)
	}
}

func TestNoFloat64InDecide(t *testing.T) {
	decideDir := filepath.Join("..", "..", "internal", "decide")
	cmd := exec.Command("grep", "-rn", "float64", "--exclude=*_test.go", decideDir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("float64 found in decide:\n%s", out)
	}
}

// TestWriteFixtureExpected regenerates the "expected" field for all fixtures.
// Run: go test ./internal/decide -run TestWriteFixtureExpected
func TestWriteFixtureExpected(t *testing.T) {
	if os.Getenv("PLIMSOLL_WRITE_FIXTURES") != "1" {
		t.Skip("set PLIMSOLL_WRITE_FIXTURES=1 to regenerate")
	}
	dir := filepath.Join("..", "..", "testdata", "decide")
	expDir := filepath.Join(dir, "expected")
	if err := os.MkdirAll(expDir, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var f fixtureFile
		if err := json.Unmarshal(b, &f); err != nil {
			t.Fatal(err)
		}
		v, err := Evaluate(f.seal(), f.resultSet())
		if err != nil {
			t.Fatal(err)
		}
		exp, err := verdictJSON(v)
		if err != nil {
			t.Fatal(err)
		}
		expPath := filepath.Join(expDir, f.ID+".json")
		if err := os.WriteFile(expPath, exp, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("updated %s", expPath)
	}
}

func TestPercentileBoundariesSpec(t *testing.T) {
	// SPEC-PREREG §6.1 boundary table spot checks.
	raw := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}
	prec := 0
	cases := []struct {
		agg  string
		p    int
		want string
	}{
		{"p10", 10, "1"},
		{"p50", 50, "5"},
		{"p90", 90, "9"},
		{"p95", 95, "10"},
	}
	for _, tc := range cases {
		got, err := computeAggregate(tc.agg, raw, prec)
		if err != nil {
			t.Fatalf("%s: %v", tc.agg, err)
		}
		if got.String() != tc.want {
			t.Fatalf("%s: got %s want %s", tc.agg, got.String(), tc.want)
		}
	}
	// n=2 p50 -> x[1], not mean.
	raw2 := []string{"0.9", "0.1"}
	got, err := computeAggregate("median", raw2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "0.1" {
		t.Fatalf("median n=2: got %s want 0.1", got.String())
	}
}

func TestComparatorBoundaries(t *testing.T) {
	val, err := parseDec("0.82", 2)
	if err != nil {
		t.Fatal(err)
	}
	lit, err := parseDec("0.82", 2)
	if err != nil {
		t.Fatal(err)
	}
	if !compare(val, lit, ">=") {
		t.Fatal(">= at threshold should pass")
	}
	if compare(val, lit, ">") {
		t.Fatal("> at threshold should fail")
	}
	if !compare(val, lit, "<=") {
		t.Fatal("<= at threshold should pass")
	}
	if compare(val, lit, "<") {
		t.Fatal("< at threshold should fail")
	}
	if !compare(val, lit, "==") {
		t.Fatal("== at threshold should pass")
	}
	if compare(val, lit, "!=") {
		t.Fatal("!= at threshold should fail")
	}
}

func parseDec(s string, prec int) (canonical.Decimal, error) {
	return canonical.ParseDecimal(s, prec)
}
