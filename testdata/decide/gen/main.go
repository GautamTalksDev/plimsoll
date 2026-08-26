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

// One-shot fixture generator. Run from repo root:
//   go run ./testdata/decide/gen/
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type fixture struct {
	ID         string      `json:"id"`
	Seal       sealPart    `json:"seal"`
	ResultSet  rsPart      `json:"result_set"`
	Expected   interface{} `json:"-"`
}

type sealPart struct {
	CanonVersion string   `json:"canon_version"`
	Dataset      struct{ N int `json:"n"` } `json:"dataset"`
	Harness      struct {
		Tool    string `json:"tool"`
		Version string `json:"version"`
	} `json:"harness"`
	DecisionRule struct {
		Expression string `json:"expression"`
		Precision  int    `json:"precision"`
	} `json:"decision_rule"`
}

type rsPart struct {
	Harness    string                 `json:"harness"`
	HarnessVer string                 `json:"harness_ver"`
	Metrics    map[string]metricPart  `json:"metrics"`
}

type metricPart struct {
	Raw []string `json:"raw"`
	N   int      `json:"n"`
}

func base() fixture {
	f := fixture{}
	f.Seal.CanonVersion = "plimsoll-canon-v1"
	f.Seal.Harness.Tool = "generic"
	f.Seal.Harness.Version = "1.0.0"
	f.ResultSet.Harness = "generic"
	f.ResultSet.HarnessVer = "1.0.0"
	f.Expected = nil
	return f
}

func acc(raw []string) map[string]metricPart {
	return map[string]metricPart{"acc": {Raw: raw, N: len(raw)}}
}

func main() {
	dir := filepath.Join("testdata", "decide")
	_ = os.MkdirAll(dir, 0o755)

	seq := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}
	fixtures := []fixture{
		func() fixture {
			f := base()
			f.ID = "01_mean_gte_pass_at_threshold"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule = struct {
				Expression string `json:"expression"`
				Precision  int    `json:"precision"`
			}{"acc.mean >= 0.82", 2}
			f.ResultSet.Metrics = acc([]string{"0.82", "0.82"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "02_mean_gt_fail_at_threshold"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "acc.mean > 0.82"
			f.Seal.DecisionRule.Precision = 2
			f.ResultSet.Metrics = acc([]string{"0.82", "0.82"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "03_mean_lte_pass_at_threshold"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "acc.mean <= 0.82"
			f.Seal.DecisionRule.Precision = 2
			f.ResultSet.Metrics = acc([]string{"0.82", "0.82"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "04_mean_lt_fail_at_threshold"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "acc.mean < 0.82"
			f.Seal.DecisionRule.Precision = 2
			f.ResultSet.Metrics = acc([]string{"0.82", "0.82"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "05_mean_eq_pass_at_threshold"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "acc.mean == 0.82"
			f.Seal.DecisionRule.Precision = 2
			f.ResultSet.Metrics = acc([]string{"0.82", "0.82"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "06_mean_ne_fail_at_threshold"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "acc.mean != 0.82"
			f.Seal.DecisionRule.Precision = 2
			f.ResultSet.Metrics = acc([]string{"0.82", "0.82"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "07_median_n2_nearest_rank"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "acc.median >= 0.1"
			f.Seal.DecisionRule.Precision = 1
			f.ResultSet.Metrics = acc([]string{"0.9", "0.1"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "08_median_n2_not_midmean"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "acc.median >= 0.5"
			f.Seal.DecisionRule.Precision = 1
			f.ResultSet.Metrics = acc([]string{"0.9", "0.1"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "09_min_aggregate"
			f.Seal.Dataset.N = 3
			f.Seal.DecisionRule.Expression = "acc.min >= 0.3"
			f.Seal.DecisionRule.Precision = 1
			f.ResultSet.Metrics = acc([]string{"0.3", "0.7", "0.5"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "10_max_aggregate"
			f.Seal.Dataset.N = 3
			f.Seal.DecisionRule.Expression = "acc.max <= 0.7"
			f.Seal.DecisionRule.Precision = 1
			f.ResultSet.Metrics = acc([]string{"0.3", "0.7", "0.5"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "11_p10_n10_boundary"
			f.Seal.Dataset.N = 10
			f.Seal.DecisionRule.Expression = "acc.p10 == 1"
			f.Seal.DecisionRule.Precision = 0
			f.ResultSet.Metrics = acc(seq)
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "12_p50_n10_boundary"
			f.Seal.Dataset.N = 10
			f.Seal.DecisionRule.Expression = "acc.p50 == 5"
			f.Seal.DecisionRule.Precision = 0
			f.ResultSet.Metrics = acc(seq)
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "13_p90_n10_boundary"
			f.Seal.Dataset.N = 10
			f.Seal.DecisionRule.Expression = "acc.p90 == 9"
			f.Seal.DecisionRule.Precision = 0
			f.ResultSet.Metrics = acc(seq)
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "14_p95_n10_boundary"
			f.Seal.Dataset.N = 10
			f.Seal.DecisionRule.Expression = "acc.p95 == 10"
			f.Seal.DecisionRule.Precision = 0
			f.ResultSet.Metrics = acc(seq)
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "15_count_aggregate"
			f.Seal.Dataset.N = 3
			f.Seal.DecisionRule.Expression = "acc.count == 3"
			f.Seal.DecisionRule.Precision = 0
			f.ResultSet.Metrics = acc([]string{"1", "2", "3"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "16_pass_rate"
			f.Seal.Dataset.N = 3
			f.Seal.DecisionRule.Expression = "acc.pass_rate >= 0.666666"
			f.Seal.DecisionRule.Precision = 6
			f.ResultSet.Metrics = acc([]string{"1", "0", "1"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "17_and_pass"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "acc.mean >= 0.5 AND acc.min >= 0.4"
			f.Seal.DecisionRule.Precision = 1
			f.ResultSet.Metrics = acc([]string{"0.8", "0.6"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "18_and_fail"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "acc.mean >= 0.5 AND acc.min >= 0.7"
			f.Seal.DecisionRule.Precision = 1
			f.ResultSet.Metrics = acc([]string{"0.8", "0.6"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "19_or_pass"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "acc.mean >= 0.9 OR acc.min >= 0.4"
			f.Seal.DecisionRule.Precision = 1
			f.ResultSet.Metrics = acc([]string{"0.8", "0.6"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "20_or_fail"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "acc.mean >= 0.9 OR acc.min >= 0.7"
			f.Seal.DecisionRule.Precision = 1
			f.ResultSet.Metrics = acc([]string{"0.8", "0.6"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "21_not_pass"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "NOT acc.mean < 0.5"
			f.Seal.DecisionRule.Precision = 1
			f.ResultSet.Metrics = acc([]string{"0.8", "0.6"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "22_not_fail"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "NOT acc.mean >= 0.5"
			f.Seal.DecisionRule.Precision = 1
			f.ResultSet.Metrics = acc([]string{"0.8", "0.6"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "23_nested_or_in_parens"
			f.Seal.Dataset.N = 10
			f.Seal.DecisionRule.Expression = "(acc.p50 >= 7 OR acc.p90 >= 9)"
			f.Seal.DecisionRule.Precision = 0
			f.ResultSet.Metrics = acc(seq)
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "24_invalid_n_mismatch"
			f.Seal.Dataset.N = 3
			f.Seal.DecisionRule.Expression = "acc.mean >= 0.5"
			f.Seal.DecisionRule.Precision = 1
			f.ResultSet.Metrics = acc([]string{"0.8", "0.6"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "25_invalid_missing_metric"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "loss.mean >= 0.5"
			f.Seal.DecisionRule.Precision = 1
			f.ResultSet.Metrics = acc([]string{"0.8", "0.6"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "26_invalid_harness_mismatch"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "acc.mean >= 0.5"
			f.Seal.DecisionRule.Precision = 1
			f.ResultSet.Metrics = acc([]string{"0.8", "0.6"})
			f.ResultSet.Harness = "deepeval"
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "27_invalid_harness_version"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "acc.mean >= 0.5"
			f.Seal.DecisionRule.Precision = 1
			f.ResultSet.Metrics = acc([]string{"0.8", "0.6"})
			f.ResultSet.HarnessVer = "9.9.9"
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "28_invalid_canon_version"
			f.Seal.CanonVersion = "plimsoll-canon-v9"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "acc.mean >= 0.5"
			f.Seal.DecisionRule.Precision = 1
			f.ResultSet.Metrics = acc([]string{"0.8", "0.6"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "29_invalid_no_finite_values"
			f.Seal.Dataset.N = 1
			f.Seal.DecisionRule.Expression = "acc.mean >= 0"
			f.Seal.DecisionRule.Precision = 0
			f.ResultSet.Metrics = acc([]string{"not-a-decimal"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "30_invalid_pass_bit"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "acc.pass_rate >= 0.5"
			f.Seal.DecisionRule.Precision = 1
			f.ResultSet.Metrics = acc([]string{"1", "maybe"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "31_mean_fail_below"
			f.Seal.Dataset.N = 3
			f.Seal.DecisionRule.Expression = "acc.mean >= 0.9"
			f.Seal.DecisionRule.Precision = 2
			f.ResultSet.Metrics = acc([]string{"0.80", "0.85", "0.88"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "32_precision_rounding"
			f.Seal.Dataset.N = 3
			f.Seal.DecisionRule.Expression = "acc.mean >= 0.333"
			f.Seal.DecisionRule.Precision = 3
			f.ResultSet.Metrics = acc([]string{"0.333", "0.333", "0.334"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "33_dual_metric_and"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "acc.mean >= 0.7 AND loss.max <= 0.2"
			f.Seal.DecisionRule.Precision = 1
			f.ResultSet.Metrics = map[string]metricPart{
				"acc":  {Raw: []string{"0.8", "0.6"}, N: 2},
				"loss": {Raw: []string{"0.1", "0.2"}, N: 2},
			}
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "34_not_pass_rate"
			f.Seal.Dataset.N = 4
			f.Seal.DecisionRule.Expression = "NOT acc.pass_rate < 0.5"
			f.Seal.DecisionRule.Precision = 2
			f.ResultSet.Metrics = acc([]string{"1", "0", "1", "0"})
			return f
		}(),
		func() fixture {
			f := base()
			f.ID = "35_complex_bool_mix"
			f.Seal.Dataset.N = 2
			f.Seal.DecisionRule.Expression = "acc.min >= 0.5 AND (acc.max <= 0.9 OR acc.mean >= 0.95)"
			f.Seal.DecisionRule.Precision = 1
			f.ResultSet.Metrics = acc([]string{"0.6", "0.8"})
			return f
		}(),
	}

	for _, f := range fixtures {
		path := filepath.Join(dir, f.ID+".json")
		b, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			panic(err)
		}
		fmt.Println("wrote", path)
	}
}
