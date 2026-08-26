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
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

var allowedTopLevel = map[string]struct{}{
	"plimsoll_version": {},
	"created_at":       {},
	"subject":          {},
	"dataset":          {},
	"harness":          {},
	"metrics":          {},
	"decision_rule":    {},
	"exclusions":       {},
	"planned_attempts": {},
	"analysis_plan":    {},
	"canon_version":    {},
	"supersedes":       {},
}

// Parse decodes a prereg-v1 seal from JSON or YAML. Unknown top-level
// fields are rejected. Parse does not transmit the document anywhere.
func Parse(yamlOrJSON []byte) (*Seal, error) {
	in := bytes.TrimSpace(yamlOrJSON)
	if len(in) == 0 {
		return nil, fmt.Errorf("seal: empty document")
	}
	if in[0] == '{' {
		return parseJSON(in)
	}
	return parseYAML(in)
}

func parseJSON(in []byte) (*Seal, error) {
	if err := rejectUnknownTopLevelJSON(in); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.DisallowUnknownFields()
	var s Seal
	if err := dec.Decode(&s); err != nil {
		if f := unknownFieldName(err); f != "" {
			return nil, &UnknownFieldError{Field: f}
		}
		return nil, fmt.Errorf("seal: json: %w", err)
	}
	return &s, nil
}

func parseYAML(in []byte) (*Seal, error) {
	var top map[string]yaml.Node
	if err := yaml.Unmarshal(in, &top); err != nil {
		return nil, fmt.Errorf("seal: yaml: %w", err)
	}
	for k := range top {
		if _, ok := allowedTopLevel[k]; !ok {
			return nil, &UnknownFieldError{Field: k}
		}
	}
	dec := yaml.NewDecoder(bytes.NewReader(in))
	dec.KnownFields(true)
	var s Seal
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("seal: yaml: %w", err)
	}
	return &s, nil
}

func rejectUnknownTopLevelJSON(in []byte) error {
	dec := json.NewDecoder(bytes.NewReader(in))
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("seal: json: %w", err)
	}
	d, ok := tok.(json.Delim)
	if !ok || d != '{' {
		return fmt.Errorf("seal: json: expected object")
	}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return fmt.Errorf("seal: json: %w", err)
		}
		key, ok := k.(string)
		if !ok {
			return fmt.Errorf("seal: json: expected field name")
		}
		if _, ok := allowedTopLevel[key]; !ok {
			return &UnknownFieldError{Field: key}
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return fmt.Errorf("seal: json: %w", err)
		}
	}
	return nil
}

func unknownFieldName(err error) string {
	const p = "json: unknown field "
	s := err.Error()
	if !strings.HasPrefix(s, p) {
		return ""
	}
	return strings.Trim(s[len(p):], `"`)
}
