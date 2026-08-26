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

package seal

import "fmt"

// UnknownFieldError is returned when a seal document has a member not
// in prereg-v1. v1 rejects unknown top-level fields; no forward compat.
type UnknownFieldError struct{ Field string }

func (e *UnknownFieldError) Error() string {
	return fmt.Sprintf("seal: unknown field %q", e.Field)
}

// UnknownMetricError is a decision_rule metric_id not listed in metrics[].
type UnknownMetricError struct{ ID string }

func (e *UnknownMetricError) Error() string {
	return fmt.Sprintf("seal: unknown metric_id %q", e.ID)
}

// PlannedAttemptsError is planned_attempts < 1.
type PlannedAttemptsError struct{ N int }

func (e *PlannedAttemptsError) Error() string {
	return fmt.Sprintf("seal: planned_attempts %d is < 1", e.N)
}

// DatasetError is an invalid dataset (n <= 0 or missing sha256).
type DatasetError struct{ Reason string }

func (e *DatasetError) Error() string {
	return fmt.Sprintf("seal: dataset: %s", e.Reason)
}

// ExpressionError wraps a decision_rule.expression parse failure.
type ExpressionError struct{ Err error }

func (e *ExpressionError) Error() string {
	return fmt.Sprintf("seal: expression: %v", e.Err)
}

func (e *ExpressionError) Unwrap() error { return e.Err }

// PrecisionError is decision_rule.precision outside 1..12.
type PrecisionError struct{ Precision int }

func (e *PrecisionError) Error() string {
	return fmt.Sprintf("seal: precision %d is outside 1..12", e.Precision)
}
