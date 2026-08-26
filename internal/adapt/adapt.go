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
	"fmt"
)

// Detect classifies raw harness result bytes. Adapters are tried in priority
// order: generic, deepeval, inspect, promptfoo.
func Detect(raw []byte) (string, error) {
	top, err := parseTopObject(raw)
	if err != nil {
		return "", err
	}
	switch {
	case detectGeneric(top):
		return "generic", nil
	case detectDeepEval(top):
		return "deepeval", nil
	case detectInspect(top):
		return "inspect", nil
	case detectPromptfoo(top):
		return "promptfoo", nil
	default:
		return "", ErrUnknownHarness
	}
}

// Adapt maps raw harness bytes into a ResultSet. harness must be one of
// generic, deepeval, inspect, or promptfoo (as returned by Detect).
func Adapt(harness string, raw []byte) (*ResultSet, error) {
	switch harness {
	case "generic":
		return adaptGeneric(raw)
	case "deepeval":
		return adaptDeepEval(raw)
	case "inspect":
		return adaptInspect(raw)
	case "promptfoo":
		return adaptPromptfoo(raw)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownHarness, harness)
	}
}
