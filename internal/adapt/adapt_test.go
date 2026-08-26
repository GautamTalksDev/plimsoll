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

package adapt

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var harnesses = []string{"generic", "deepeval", "inspect", "promptfoo"}

func loadFixture(t *testing.T, harness, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "adapters", harness, name+".json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return b
}

func TestDetectAllHarnesses(t *testing.T) {
	for _, h := range harnesses {
		h := h
		t.Run(h, func(t *testing.T) {
			raw := loadFixture(t, h, "valid")
			got, err := Detect(raw)
			if err != nil {
				t.Fatal(err)
			}
			if got != h {
				t.Fatalf("Detect=%q want %q", got, h)
			}
		})
	}
}

func TestAdaptValidFixtures(t *testing.T) {
	for _, h := range harnesses {
		h := h
		t.Run(h, func(t *testing.T) {
			raw := loadFixture(t, h, "valid")
			rs, err := Adapt(h, raw)
			if err != nil {
				t.Fatal(err)
			}
			if rs.Harness != h {
				t.Fatalf("Harness=%q", rs.Harness)
			}
			if rs.HarnessVer == "" {
				t.Fatal("empty HarnessVer")
			}
			if len(rs.Metrics) == 0 {
				t.Fatal("no metrics extracted")
			}
			for id, mv := range rs.Metrics {
				if mv.MetricID != id {
					t.Fatalf("metric key/id mismatch: %q vs %q", id, mv.MetricID)
				}
				if mv.N != len(mv.Raw) {
					t.Fatalf("metric %q N=%d len(Raw)=%d", id, mv.N, len(mv.Raw))
				}
				if mv.N == 0 {
					t.Fatalf("metric %q empty", id)
				}
			}
			if rs.RowDigest == "" || !strings.HasPrefix(rs.RowDigest, "sha256:") {
				t.Fatalf("RowDigest=%q", rs.RowDigest)
			}
			if len(rs.Extra) == 0 {
				t.Fatal("Extra empty")
			}
		})
	}
}

func TestVersionMismatchAllHarnesses(t *testing.T) {
	for _, h := range harnesses {
		h := h
		t.Run(h, func(t *testing.T) {
			raw := loadFixture(t, h, "version_mismatch")
			_, err := Adapt(h, raw)
			if !errors.Is(err, ErrUnsupportedVersion) {
				t.Fatalf("err=%v want ErrUnsupportedVersion", err)
			}
		})
	}
}

func TestMalformedAllHarnesses(t *testing.T) {
	for _, h := range harnesses {
		h := h
		t.Run(h, func(t *testing.T) {
			raw := loadFixture(t, h, "malformed")
			_, err := Adapt(h, raw)
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("err=%v want ErrMalformed", err)
			}
		})
	}
}

func TestMetricStringPreservation(t *testing.T) {
	cases := []struct {
		harness string
		checks  map[string][]string
	}{
		{
			harness: "generic",
			checks: map[string][]string{
				"accuracy":   {"0.875", "1.0", "0.5"},
				"latency_ms": {"42", "38", "51"},
			},
		},
		{
			harness: "deepeval",
			checks: map[string][]string{
				"Answer Relevancy": {"0.95", "0.88"},
				"Faithfulness":     {"1.0", "0.75"},
			},
		},
		{
			harness: "inspect",
			checks: map[string][]string{
				"match":    {"1", "1", "0"},
				"accuracy": {"1.0", "1.0", "0.0"},
			},
		},
		{
			harness: "promptfoo",
			checks: map[string][]string{
				"contains_check": {"1", "0"},
				"similarity":     {"0.92", "0.41"},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.harness, func(t *testing.T) {
			raw := loadFixture(t, tc.harness, "valid")
			rs, err := Adapt(tc.harness, raw)
			if err != nil {
				t.Fatal(err)
			}
			for metricID, want := range tc.checks {
				got, ok := rs.Metrics[metricID]
				if !ok {
					t.Fatalf("missing metric %q", metricID)
				}
				if len(got.Raw) != len(want) {
					t.Fatalf("metric %q: got %d values want %d", metricID, len(got.Raw), len(want))
				}
				for i := range want {
					if got.Raw[i] != want[i] {
						t.Fatalf("metric %q[%d]=%q want %q", metricID, i, got.Raw[i], want[i])
					}
				}
			}

			// Re-serialize ResultSet and assert metric strings unchanged.
			out, err := json.Marshal(rs)
			if err != nil {
				t.Fatal(err)
			}
			var round ResultSet
			if err := json.Unmarshal(out, &round); err != nil {
				t.Fatal(err)
			}
			for metricID, want := range tc.checks {
				got := round.Metrics[metricID].Raw
				for i := range want {
					if got[i] != want[i] {
						t.Fatalf("after round-trip metric %q[%d]=%q want %q", metricID, i, got[i], want[i])
					}
				}
			}
		})
	}
}

func TestNoRowContentInOutput(t *testing.T) {
	secrets := map[string][]string{
		"generic": {
			"SECRET_PROMPT_ALPHA",
			"SECRET_OUTPUT_BETA",
		},
		"deepeval": {
			"What is the capital of France?",
			"Paris is the capital.",
			"Explain quantum entanglement briefly.",
		},
		"inspect": {
			"Janet has 3 apples",
			"Janet has 5 apples.",
			"What is 17 + 25?",
		},
		"promptfoo": {
			"Paris is the capital of France.",
			"Berlin is in France.",
			"France geography",
		},
	}

	for _, h := range harnesses {
		h := h
		t.Run(h, func(t *testing.T) {
			raw := loadFixture(t, h, "valid")
			rs, err := Adapt(h, raw)
			if err != nil {
				t.Fatal(err)
			}
			out, err := json.Marshal(rs)
			if err != nil {
				t.Fatal(err)
			}
			text := string(out)
			for _, secret := range secrets[h] {
				if strings.Contains(text, secret) {
					t.Fatalf("output contains row content %q", secret)
				}
			}
		})
	}
}

func TestErrTooLarge(t *testing.T) {
	raw := make([]byte, maxInputBytes+1)
	_, err := Detect(raw)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Detect err=%v want ErrTooLarge", err)
	}
	_, err = Adapt("generic", raw)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Adapt err=%v want ErrTooLarge", err)
	}
}

func TestErrUnknownHarness(t *testing.T) {
	_, err := Detect([]byte(`{"foo":1}`))
	if !errors.Is(err, ErrUnknownHarness) {
		t.Fatalf("Detect err=%v", err)
	}
	_, err = Adapt("unknown", []byte(`{}`))
	if !errors.Is(err, ErrUnknownHarness) {
		t.Fatalf("Adapt err=%v", err)
	}
}

func TestDeepEvalIgnoresAggregateMetricsScores(t *testing.T) {
	raw := loadFixture(t, "deepeval", "valid")
	rs, err := Adapt("deepeval", raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rs.Metrics["Answer Relevancy"]; !ok {
		t.Fatal("missing per-row metric")
	}
	// Aggregate score 0.915 from metricsScores must not appear as a row value.
	for _, mv := range rs.Metrics {
		for _, v := range mv.Raw {
			if v == "0.915" {
				t.Fatal("adapter extracted aggregate metricsScores value")
			}
		}
	}
}

func TestExtraPreservesUnknownFields(t *testing.T) {
	raw := loadFixture(t, "generic", "valid")
	rs, err := Adapt("generic", raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rs.Extra), "baseline run") {
		t.Fatalf("Extra lost unknown field: %s", rs.Extra)
	}
}
