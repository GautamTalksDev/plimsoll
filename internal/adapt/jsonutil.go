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
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

const maxInputBytes = 64 << 20 // 64 MiB

func checkSize(raw []byte) error {
	if len(raw) > maxInputBytes {
		return ErrTooLarge
	}
	return nil
}

func parseTopObject(raw []byte) (map[string]json.RawMessage, error) {
	if err := checkSize(raw); err != nil {
		return nil, err
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return nil, fmt.Errorf("%w: not a JSON object", ErrMalformed)
	}
	var top map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing JSON", ErrMalformed)
	}
	return top, nil
}

func rawStringField(raw json.RawMessage) (string, bool, error) {
	if len(raw) == 0 {
		return "", false, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false, err
	}
	return s, true, nil
}

// jsonLiteralString returns the original JSON token as a string without
// binary64 round-trip. Numbers use json.Number; booleans and null are
// rendered canonically.
func jsonLiteralString(raw json.RawMessage) (string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return "", fmt.Errorf("%w: empty metric value", ErrMalformed)
	}
	switch raw[0] {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		return s, nil
	case 't', 'f', 'n':
		var v any
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return "", fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		switch x := v.(type) {
		case bool:
			if x {
				return "true", nil
			}
			return "false", nil
		case nil:
			return "null", nil
		default:
			return "", fmt.Errorf("%w: unexpected literal", ErrMalformed)
		}
	default:
		var num json.Number
		if err := json.Unmarshal(raw, &num); err != nil {
			return "", fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		return num.String(), nil
	}
}

func collectExtra(top map[string]json.RawMessage, known ...string) (json.RawMessage, error) {
	skip := make(map[string]struct{}, len(known))
	for _, k := range known {
		skip[k] = struct{}{}
	}
	extra := make(map[string]json.RawMessage)
	for k, v := range top {
		if _, ok := skip[k]; ok {
			continue
		}
		extra[k] = append(json.RawMessage(nil), v...)
	}
	if len(extra) == 0 {
		return json.RawMessage("{}"), nil
	}
	return json.Marshal(extra)
}

func appendMetric(metrics map[string]MetricValues, id, value string) {
	mv, ok := metrics[id]
	if !ok {
		mv = MetricValues{MetricID: id, Raw: make([]string, 0, 8)}
	}
	mv.Raw = append(mv.Raw, value)
	mv.N = len(mv.Raw)
	metrics[id] = mv
}

func finalizeMetrics(metrics map[string]MetricValues) map[string]MetricValues {
	if metrics == nil {
		return map[string]MetricValues{}
	}
	return metrics
}

func intString(n int) string {
	return strconv.Itoa(n)
}

func int64String(n int64) string {
	return strconv.FormatInt(n, 10)
}
