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

const (
	promptfooMinVer = 3
	promptfooMaxVer = 3
)

func detectPromptfoo(top map[string]json.RawMessage) bool {
	verRaw, ok := top["version"]
	if !ok {
		return false
	}
	if _, err := jsonLiteralString(verRaw); err != nil {
		return false
	}
	_, ok = top["results"]
	return ok
}

func adaptPromptfoo(raw []byte) (*ResultSet, error) {
	top, err := parseTopObject(raw)
	if err != nil {
		return nil, err
	}
	if !detectPromptfoo(top) {
		return nil, fmt.Errorf("%w: missing promptfoo results envelope", ErrMalformed)
	}

	verRaw := top["version"]
	version, err := jsonLiteralString(verRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid version", ErrMalformed)
	}
	verInt, err := parseSingleIntVersion(version)
	if err != nil {
		return nil, fmt.Errorf("%w: version %q", ErrMalformed, version)
	}
	if err := checkIntRange(verInt, promptfooMinVer, promptfooMaxVer); err != nil {
		return nil, err
	}

	resultsRaw, ok := top["results"]
	if !ok {
		return nil, fmt.Errorf("%w: missing results", ErrMalformed)
	}
	var results map[string]json.RawMessage
	if err := json.Unmarshal(resultsRaw, &results); err != nil {
		return nil, fmt.Errorf("%w: results: %v", ErrMalformed, err)
	}

	rowsRaw, ok := results["results"]
	if !ok {
		rowsRaw, ok = results["outputs"]
	}
	if !ok {
		return nil, fmt.Errorf("%w: missing results.results", ErrMalformed)
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(rowsRaw, &rows); err != nil {
		return nil, fmt.Errorf("%w: results rows: %v", ErrMalformed, err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%w: results rows empty", ErrMalformed)
	}

	metrics := make(map[string]MetricValues)
	rowIDs := make([]string, 0, len(rows))
	for i, row := range rows {
		rowID, err := promptfooRowID(row, i)
		if err != nil {
			return nil, err
		}
		rowIDs = append(rowIDs, rowID)

		namedRaw, ok := row["namedScores"]
		if !ok {
			namedRaw = row["named_scores"]
		}
		if !ok {
			// Fall back to top-level score as metric "score".
			scoreRaw, ok := row["score"]
			if !ok {
				return nil, fmt.Errorf("%w: row %d missing namedScores/score", ErrMalformed, i)
			}
			score, err := jsonLiteralString(scoreRaw)
			if err != nil {
				return nil, fmt.Errorf("%w: row %d score: %v", ErrMalformed, i, err)
			}
			appendMetric(metrics, "score", score)
			continue
		}
		var named map[string]json.RawMessage
		if err := json.Unmarshal(namedRaw, &named); err != nil {
			return nil, fmt.Errorf("%w: row %d namedScores: %v", ErrMalformed, i, err)
		}
		if len(named) == 0 {
			return nil, fmt.Errorf("%w: row %d namedScores empty", ErrMalformed, i)
		}
		for metricID, valRaw := range named {
			val, err := jsonLiteralString(valRaw)
			if err != nil {
				return nil, fmt.Errorf("%w: row %d metric %q: %v", ErrMalformed, i, metricID, err)
			}
			appendMetric(metrics, metricID, val)
		}
	}

	extra, err := collectExtra(top, "version", "results", "timestamp")
	if err != nil {
		return nil, err
	}

	return &ResultSet{
		Harness:    "promptfoo",
		HarnessVer: version,
		Metrics:    finalizeMetrics(metrics),
		RowDigest:  rowDigest(rowIDs),
		Extra:      extra,
	}, nil
}

func promptfooRowID(row map[string]json.RawMessage, index int) (string, error) {
	if idRaw, ok := row["id"]; ok {
		id, ok, err := rawStringField(idRaw)
		if err != nil || !ok || id == "" {
			return "", fmt.Errorf("%w: invalid row id", ErrMalformed)
		}
		return id, nil
	}
	testIdx := intString(index)
	if tRaw, ok := row["testIdx"]; ok {
		v, err := jsonLiteralString(tRaw)
		if err != nil {
			return "", err
		}
		testIdx = v
	}
	promptIdx := "0"
	if pRaw, ok := row["promptIdx"]; ok {
		v, err := jsonLiteralString(pRaw)
		if err != nil {
			return "", err
		}
		promptIdx = v
	}
	return testIdx + ":" + promptIdx, nil
}
