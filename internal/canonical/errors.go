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

package canonical

import "errors"

// ErrTooLarge is returned when a JSON document exceeds MaxInputBytes.
var ErrTooLarge = errors.New("canonical: input exceeds 1 MiB")

// ErrInvalidJSON is returned when the input is not a single JSON value.
var ErrInvalidJSON = errors.New("canonical: invalid JSON")

// ErrInvalidDecimal is returned when a decimal string cannot be parsed.
var ErrInvalidDecimal = errors.New("canonical: invalid decimal")

// ErrPrecision is returned when a requested decimal precision is out of range.
var ErrPrecision = errors.New("canonical: decimal precision out of range")
