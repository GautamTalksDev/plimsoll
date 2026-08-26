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

// Package adapt maps third-party harness result files into a normalized
// ResultSet. Pure functions only: zero I/O, zero network. Adapters extract
// per-row metric strings; they never compute aggregates.
package adapt

import (
	"encoding/json"
	"fmt"
)

const genericFormatID = "plimsoll-generic-v1"

var (
	genericMinVer = semver{1, 0, 0}
	genericMaxVer = semver{1, 99, 99}
)

func detectGeneric(top map[string]json.RawMessage) bool {
	raw, ok := top["format"]
	if !ok {
		return false
	}
	s, ok, err := rawStringField(raw)
	return err == nil && ok && s == genericFormatID
}

func adaptGeneric(raw []byte) (*ResultSet, error) {
	top, err := parseTopObject(raw)
	if err != nil {
		return nil, err
	}
	if !detectGeneric(top) {
		return nil, fmt.Errorf("%w: missing format %q", ErrMalformed, genericFormatID)
	}

	verRaw, ok := top["harness_version"]
	if !ok {
		return nil, fmt.Errorf("%w: missing harness_version", ErrMalformed)
	}
	version, ok, err := rawStringField(verRaw)
	if err != nil || !ok || version == "" {
		return nil, fmt.Errorf("%w: invalid harness_version", ErrMalformed)
	}
	if err := checkSemverRange(version, genericMinVer, genericMaxVer); err != nil {
		return nil, err
	}

	rowsRaw, ok := top["rows"]
	if !ok {
		return nil, fmt.Errorf("%w: missing rows", ErrMalformed)
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(rowsRaw, &rows); err != nil {
		return nil, fmt.Errorf("%w: rows: %v", ErrMalformed, err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("%w: rows must be non-empty", ErrMalformed)
	}

	metrics := make(map[string]MetricValues)
	rowIDs := make([]string, 0, len(rows))
	for i, row := range rows {
		idRaw, ok := row["id"]
		if !ok {
			return nil, fmt.Errorf("%w: row %d missing id", ErrMalformed, i)
		}
		id, ok, err := rawStringField(idRaw)
		if err != nil || !ok || id == "" {
			return nil, fmt.Errorf("%w: row %d invalid id", ErrMalformed, i)
		}
		rowIDs = append(rowIDs, id)

		metricsRaw, ok := row["metrics"]
		if !ok {
			return nil, fmt.Errorf("%w: row %d missing metrics", ErrMalformed, i)
		}
		var metricObj map[string]json.RawMessage
		if err := json.Unmarshal(metricsRaw, &metricObj); err != nil {
			return nil, fmt.Errorf("%w: row %d metrics: %v", ErrMalformed, i, err)
		}
		for metricID, valRaw := range metricObj {
			val, err := jsonLiteralString(valRaw)
			if err != nil {
				return nil, fmt.Errorf("%w: row %d metric %q: %v", ErrMalformed, i, metricID, err)
			}
			appendMetric(metrics, metricID, val)
		}
	}

	extra, err := collectExtra(top, "format", "harness_version", "rows")
	if err != nil {
		return nil, err
	}

	return &ResultSet{
		Harness:    "generic",
		HarnessVer: version,
		Metrics:    finalizeMetrics(metrics),
		RowDigest:  rowDigest(rowIDs),
		Extra:      extra,
	}, nil
}
