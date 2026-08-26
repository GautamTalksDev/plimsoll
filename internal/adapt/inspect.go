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
	"fmt"
)

const (
	inspectLogMinVer = 2
	inspectLogMaxVer = 2
)

func detectInspect(top map[string]json.RawMessage) bool {
	if _, ok := top["eval"]; !ok {
		return false
	}
	if _, ok := top["samples"]; !ok {
		return false
	}
	_, ok := top["status"]
	return ok
}

func adaptInspect(raw []byte) (*ResultSet, error) {
	top, err := parseTopObject(raw)
	if err != nil {
		return nil, err
	}
	if !detectInspect(top) {
		return nil, fmt.Errorf("%w: missing eval/samples/status", ErrMalformed)
	}

	verRaw, ok := top["version"]
	if !ok {
		return nil, fmt.Errorf("%w: missing version", ErrMalformed)
	}
	version, err := jsonLiteralString(verRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid version: %v", ErrMalformed, err)
	}
	verInt, err := parseInspectLogVersion(version)
	if err != nil {
		return nil, err
	}
	if err := checkIntRange(verInt, inspectLogMinVer, inspectLogMaxVer); err != nil {
		return nil, err
	}

	samplesRaw, ok := top["samples"]
	if !ok {
		return nil, fmt.Errorf("%w: missing samples", ErrMalformed)
	}
	var samples []map[string]json.RawMessage
	if err := json.Unmarshal(samplesRaw, &samples); err != nil {
		return nil, fmt.Errorf("%w: samples: %v", ErrMalformed, err)
	}
	if len(samples) == 0 {
		return nil, fmt.Errorf("%w: samples empty", ErrMalformed)
	}

	metrics := make(map[string]MetricValues)
	rowIDs := make([]string, 0, len(samples))
	for i, sample := range samples {
		rowID, err := inspectRowID(sample, i)
		if err != nil {
			return nil, err
		}
		rowIDs = append(rowIDs, rowID)

		scoresRaw, ok := sample["scores"]
		if !ok {
			return nil, fmt.Errorf("%w: sample %d missing scores", ErrMalformed, i)
		}
		var scores map[string]map[string]json.RawMessage
		if err := json.Unmarshal(scoresRaw, &scores); err != nil {
			return nil, fmt.Errorf("%w: sample %d scores: %v", ErrMalformed, i, err)
		}
		if len(scores) == 0 {
			return nil, fmt.Errorf("%w: sample %d scores empty", ErrMalformed, i)
		}
		for scorer, scoreObj := range scores {
			valRaw, ok := scoreObj["value"]
			if !ok {
				return nil, fmt.Errorf("%w: sample %d scorer %q missing value", ErrMissingMetric, i, scorer)
			}
			val, err := jsonLiteralString(valRaw)
			if err != nil {
				return nil, fmt.Errorf("%w: sample %d scorer %q: %v", ErrMalformed, i, scorer, err)
			}
			appendMetric(metrics, scorer, val)
		}
	}

	extra, err := collectExtra(top, "version", "eval", "samples", "status")
	if err != nil {
		return nil, err
	}

	return &ResultSet{
		Harness:    "inspect",
		HarnessVer: version,
		Metrics:    finalizeMetrics(metrics),
		RowDigest:  rowDigest(rowIDs),
		Extra:      extra,
	}, nil
}

func parseInspectLogVersion(s string) (int, error) {
	v, err := parseSemver(s + ".0")
	if err != nil {
		// EvalLog version is a single integer (e.g. "2").
		n, convErr := parseSingleIntVersion(s)
		if convErr != nil {
			return 0, fmt.Errorf("%w: version %q", ErrMalformed, s)
		}
		return n, nil
	}
	return v.major, nil
}

func parseSingleIntVersion(s string) (int, error) {
	v, err := parseSemver(s + ".0.0")
	if err != nil {
		return 0, err
	}
	return v.major, nil
}

func inspectRowID(sample map[string]json.RawMessage, index int) (string, error) {
	if idRaw, ok := sample["id"]; ok {
		val, err := jsonLiteralString(idRaw)
		if err != nil {
			return "", fmt.Errorf("%w: sample id: %v", ErrMalformed, err)
		}
		return val, nil
	}
	return intString(index), nil
}
