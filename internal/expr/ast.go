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

// Package decide parses and evaluates prereg-v1 decision_rule expressions
// against normalized result sets using fixed-precision decimal arithmetic.
// The sealed expression and threshold are never modified.
package expr

import "fmt"

// Aggregates allowed after a metric_id. These are names, not calls.
var Aggregates = map[string]struct{}{
	"mean": {}, "median": {}, "min": {}, "max": {},
	"p10": {}, "p50": {}, "p90": {}, "p95": {},
	"count": {}, "pass_rate": {},
}

// Comparators allowed in a comparison.
var Comparators = map[string]struct{}{
	">=": {}, "<=": {}, ">": {}, "<": {}, "==": {}, "!=": {},
}

// ParseError is a typed failure to parse an expression.
type ParseError struct {
	Offset int
	Msg    string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("expr: parse at %d: %s", e.Offset, e.Msg)
}

// Program is a parsed expression. It has no Eval method.
type Program struct {
	Root Node
}

// MetricIDs returns the metric identifiers referenced by the program,
// in first-seen order.
func (p *Program) MetricIDs() []string {
	if p == nil || p.Root == nil {
		return nil
	}
	var ids []string
	seen := map[string]struct{}{}
	walk(p.Root, func(c *Comparison) {
		if _, ok := seen[c.MetricID]; ok {
			return
		}
		seen[c.MetricID] = struct{}{}
		ids = append(ids, c.MetricID)
	})
	return ids
}

func walk(n Node, f func(*Comparison)) {
	switch x := n.(type) {
	case *Comparison:
		f(x)
	case *Not:
		walk(x.X, f)
	case *Bool:
		walk(x.Left, f)
		walk(x.Right, f)
	}
}

// Node is a parse tree node. There is no evaluation method.
type Node interface {
	isNode()
}

// Comparison is metric_id.aggregate comparator literal.
type Comparison struct {
	MetricID  string
	Aggregate string
	Op        string
	Literal   string
}

func (*Comparison) isNode() {}

// Not is NOT x.
type Not struct{ X Node }

func (*Not) isNode() {}

// Bool is a binary AND or OR.
type Bool struct {
	Op          string // AND or OR
	Left, Right Node
}

func (*Bool) isNode() {}
