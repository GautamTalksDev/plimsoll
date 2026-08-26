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

import "errors"

var (
	// ErrUnknownHarness is returned when Detect cannot classify raw bytes.
	ErrUnknownHarness = errors.New("adapt: unknown harness format")

	// ErrUnsupportedVersion is returned when the harness version is outside
	// the range declared by the adapter.
	ErrUnsupportedVersion = errors.New("adapt: unsupported harness version")

	// ErrMalformed is returned when raw bytes are not valid adapter input.
	ErrMalformed = errors.New("adapt: malformed harness result")

	// ErrMissingMetric is returned when a required metric is absent.
	ErrMissingMetric = errors.New("adapt: missing required metric")

	// ErrTooLarge is returned when raw exceeds the adapter size cap.
	ErrTooLarge = errors.New("adapt: input exceeds 64 MiB cap")
)
