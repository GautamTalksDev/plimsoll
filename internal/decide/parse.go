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

package decide

import "github.com/GautamTalksDev/plimsoll/internal/expr"

// Aggregates allowed after a metric_id.
var Aggregates = expr.Aggregates

// Comparators allowed in a comparison.
var Comparators = expr.Comparators

// ParseError is a typed failure to parse an expression.
type ParseError = expr.ParseError

// Program is a parsed expression.
type Program = expr.Program

// Node is a parse tree node.
type Node = expr.Node

// Comparison is metric_id.aggregate comparator literal.
type Comparison = expr.Comparison

// Not is NOT x.
type Not = expr.Not

// Bool is a binary AND or OR.
type Bool = expr.Bool

// ParseExpression parses a prereg-v1 decision_rule.expression.
func ParseExpression(s string) (*Program, error) {
	return expr.ParseExpression(s)
}
