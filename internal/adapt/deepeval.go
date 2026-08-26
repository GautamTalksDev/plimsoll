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

package adapt

import (
	"encoding/json"
	"fmt"
)

var (
	deepevalMinVer = semver{0, 21, 0}
	deepevalMaxVer = semver{2, 99, 99}
)

func detectDeepEval(top map[string]json.RawMessage) bool {
	if _, ok := top["testCases"]; ok {
		return true
	}
	if _, ok := top["test_cases"]; ok {
		return true
	}
	return false
}

func adaptDeepEval(raw []byte) (*ResultSet, error) {
	top, err := parseTopObject(raw)
	if err != nil {
		return nil, err
	}
	if detectGeneric(top) {
		return nil, fmt.Errorf("%w: generic format marker present", ErrMalformed)
	}
	if !detectDeepEval(top) {
		return nil, fmt.Errorf("%w: missing testCases", ErrMalformed)
	}

	verRaw, ok := top["deepevalVersion"]
	if !ok {
		verRaw, ok = top["deepeval_version"]
	}
	if !ok {
		return nil, fmt.Errorf("%w: missing deepevalVersion", ErrMalformed)
	}
	version, ok, err := rawStringField(verRaw)
	if err != nil || !ok || version == "" {
		return nil, fmt.Errorf("%w: invalid deepevalVersion", ErrMalformed)
	}
	if err := checkSemverRange(version, deepevalMinVer, deepevalMaxVer); err != nil {
		return nil, err
	}

	casesRaw, ok := top["testCases"]
	if !ok {
		casesRaw = top["test_cases"]
	}
	var cases []map[string]json.RawMessage
	if err := json.Unmarshal(casesRaw, &cases); err != nil {
		return nil, fmt.Errorf("%w: testCases: %v", ErrMalformed, err)
	}
	if len(cases) == 0 {
		return nil, fmt.Errorf("%w: testCases empty", ErrMalformed)
	}

	metrics := make(map[string]MetricValues)
	rowIDs := make([]string, 0, len(cases))
	for i, tc := range cases {
		rowID, err := deepevalRowID(tc, i)
		if err != nil {
			return nil, err
		}
		rowIDs = append(rowIDs, rowID)

		mdRaw, ok := tc["metricsData"]
		if !ok {
			mdRaw = tc["metrics_data"]
		}
		if !ok {
			return nil, fmt.Errorf("%w: test case %d missing metricsData", ErrMalformed, i)
		}
		var metricRows []map[string]json.RawMessage
		if err := json.Unmarshal(mdRaw, &metricRows); err != nil {
			return nil, fmt.Errorf("%w: test case %d metricsData: %v", ErrMalformed, i, err)
		}
		if len(metricRows) == 0 {
			return nil, fmt.Errorf("%w: test case %d metricsData empty", ErrMalformed, i)
		}
		for _, md := range metricRows {
			nameRaw, ok := md["name"]
			if !ok {
				return nil, fmt.Errorf("%w: test case %d metric missing name", ErrMalformed, i)
			}
			name, ok, err := rawStringField(nameRaw)
			if err != nil || !ok || name == "" {
				return nil, fmt.Errorf("%w: test case %d metric invalid name", ErrMalformed, i)
			}
			scoreRaw, ok := md["score"]
			if !ok {
				return nil, fmt.Errorf("%w: test case %d metric %q missing score", ErrMissingMetric, i, name)
			}
			score, err := jsonLiteralString(scoreRaw)
			if err != nil {
				return nil, fmt.Errorf("%w: test case %d metric %q: %v", ErrMalformed, i, name, err)
			}
			appendMetric(metrics, name, score)
		}
	}

	extra, err := collectExtra(top,
		"testCases", "test_cases", "deepevalVersion", "deepeval_version",
	)
	if err != nil {
		return nil, err
	}

	return &ResultSet{
		Harness:    "deepeval",
		HarnessVer: version,
		Metrics:    finalizeMetrics(metrics),
		RowDigest:  rowDigest(rowIDs),
		Extra:      extra,
	}, nil
}

func deepevalRowID(tc map[string]json.RawMessage, index int) (string, error) {
	if orderRaw, ok := tc["order"]; ok {
		val, err := jsonLiteralString(orderRaw)
		if err != nil {
			return "", fmt.Errorf("%w: order: %v", ErrMalformed, err)
		}
		return val, nil
	}
	return intString(index), nil
}
