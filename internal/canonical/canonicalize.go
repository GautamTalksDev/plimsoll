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

package canonical

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/gowebpki/jcs"
	"golang.org/x/text/unicode/norm"
)

// Canonicalize applies the PLIMSOLL v1 rules, in this exact order:
//
//  1. Parse JSON. Reject anything over 1 MiB with ErrTooLarge.
//  2. Normalize all string values to Unicode NFC.
//  3. Normalize line endings in string values: CRLF -> LF, CR -> LF.
//  4. Do not strip zero-width, bidi, or control characters. Preserve them.
//  5. Serialize per RFC 8785 JCS: lexicographic key ordering by UTF-16
//     code unit, no insignificant whitespace, JCS number serialization.
//  6. Prefix the output with CanonVersionPrefix ("plimsoll-canon-v1\n").
//
// JSON numbers follow JCS (IEEE 754 binary64, then ECMAScript
// Number.toString). That is why 1 and 1.0 hash identically. Metric
// values compared as quality numbers must use Decimal instead, parsed
// from their original string representation, never through binary64.
func Canonicalize(v json.RawMessage) ([]byte, error) {
	if len(v) > MaxInputBytes {
		return nil, ErrTooLarge
	}
	parsed, err := parseJSON(v)
	if err != nil {
		return nil, err
	}
	normalized, err := normalizeValue(parsed)
	if err != nil {
		return nil, err
	}
	marshaled, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("canonical: marshal: %w", err)
	}
	jcsBytes, err := jcs.Transform(marshaled)
	if err != nil {
		return nil, fmt.Errorf("canonical: jcs: %w", err)
	}
	out := make([]byte, 0, len(CanonVersionPrefix)+len(jcsBytes))
	out = append(out, CanonVersionPrefix...)
	out = append(out, jcsBytes...)
	return out, nil
}

// Hash returns "sha256:<hex>" of Canonicalize(v).
func Hash(v json.RawMessage) (string, error) {
	canon, err := Canonicalize(v)
	if err != nil {
		return "", err
	}
	sum := sha256Sum(canon)
	return "sha256:" + sum, nil
}

func parseJSON(v json.RawMessage) (any, error) {
	if len(bytes.TrimSpace(v)) == 0 {
		return nil, ErrInvalidJSON
	}
	dec := json.NewDecoder(bytes.NewReader(v))
	dec.UseNumber()
	var parsed any
	if err := dec.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalidJSON)
	}
	return parsed, nil
}

func normalizeValue(v any) (any, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case bool:
		return x, nil
	case json.Number:
		return x, nil
	case string:
		return normalizeString(x), nil
	case []any:
		out := make([]any, len(x))
		for i, el := range x {
			n, err := normalizeValue(el)
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, el := range x {
			n, err := normalizeValue(el)
			if err != nil {
				return nil, err
			}
			out[k] = n
		}
		return out, nil
	default:
		return nil, fmt.Errorf("canonical: unexpected type %T", v)
	}
}

func normalizeString(s string) string {
	// Rule 2, then rule 3. NFC does not alter CR/LF, so either order
	// is equivalent for line endings; we follow the published order.
	s = norm.NFC.String(s)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return s
}

func sha256Sum(b []byte) string {
	return Sum256(b)
}

// DecodeCanonical unmarshals JSON from plimsoll-canon-v1 prefixed bytes into v.
func DecodeCanonical(b []byte, v any) error {
	if !bytes.HasPrefix(b, []byte(CanonVersionPrefix)) {
		return fmt.Errorf("canonical: missing version prefix")
	}
	if err := json.Unmarshal(b[len(CanonVersionPrefix):], v); err != nil {
		return fmt.Errorf("canonical: decode: %w", err)
	}
	return nil
}
