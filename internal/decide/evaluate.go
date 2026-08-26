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

package decide

import (
	"fmt"

	"github.com/GautamTalksDev/plimsoll/internal/adapt"
	"github.com/GautamTalksDev/plimsoll/internal/canonical"
	"github.com/GautamTalksDev/plimsoll/internal/expr"
	"github.com/GautamTalksDev/plimsoll/internal/seal"
)

var supportedCanonVersions = map[string]struct{}{
	seal.CanonVersion: {},
}

// Evaluate applies the sealed decision_rule.expression to rs using only
// aggregates named in the expression. Threshold and expression are never
// altered. Pre-registration mismatches yield INVALID, not FAIL.
func Evaluate(s *seal.Seal, rs *adapt.ResultSet) (*Verdict, error) {
	if s == nil {
		return nil, fmt.Errorf("decide: nil seal")
	}
	if rs == nil {
		return nil, fmt.Errorf("decide: nil result set")
	}

	v := &Verdict{
		Expression: s.DecisionRule.Expression,
		Terms:      []Term{},
	}

	if _, ok := supportedCanonVersions[s.CanonVersion]; !ok {
		return invalid(v, fmt.Sprintf("canon_version %q is unknown to this binary", s.CanonVersion)), nil
	}
	if rs.Harness != s.Harness.Tool {
		return invalid(v, fmt.Sprintf("harness %q does not match sealed %q", rs.Harness, s.Harness.Tool)), nil
	}
	if rs.HarnessVer != s.Harness.Version {
		return invalid(v, fmt.Sprintf("harness version %q does not match sealed %q", rs.HarnessVer, s.Harness.Version)), nil
	}

	prog, err := ParseExpression(s.DecisionRule.Expression)
	if err != nil {
		return invalid(v, fmt.Sprintf("expression parse: %v", err)), nil
	}

	prec := s.DecisionRule.Precision
	for _, id := range prog.MetricIDs() {
		mv, ok := rs.Metrics[id]
		if !ok {
			return invalid(v, fmt.Sprintf("metric %q named in expression is absent from results", id)), nil
		}
		if mv.N != s.Dataset.N {
			return invalid(v, fmt.Sprintf("metric %q has n=%d, seal dataset.n=%d", id, mv.N, s.Dataset.N)), nil
		}
		if len(mv.Raw) != mv.N {
			return invalid(v, fmt.Sprintf("metric %q raw length %d != n=%d", id, len(mv.Raw), mv.N)), nil
		}
	}

	ok, terms, evalErr := evalNode(prog.Root, rs, prec)
	v.Terms = terms
	if evalErr != nil {
		return invalid(v, evalErr.Error()), nil
	}
	if ok {
		v.Result = "PASS"
	} else {
		v.Result = "FAIL"
	}
	return v, nil
}

func invalid(v *Verdict, reason string) *Verdict {
	v.Result = "INVALID"
	v.Reasons = append(v.Reasons, reason)
	return v
}

func evalNode(n expr.Node, rs *adapt.ResultSet, prec int) (bool, []Term, error) {
	switch x := n.(type) {
	case *expr.Comparison:
		return evalComparison(x, rs, prec)
	case *expr.Not:
		ok, terms, err := evalNode(x.X, rs, prec)
		if err != nil {
			return false, terms, err
		}
		out := !ok
		terms = append(terms, Term{
			Label:   "NOT",
			Value:   boolString(out),
			Outcome: out,
		})
		return out, terms, nil
	case *expr.Bool:
		leftOK, leftTerms, err := evalNode(x.Left, rs, prec)
		if err != nil {
			return false, leftTerms, err
		}
		rightOK, rightTerms, err := evalNode(x.Right, rs, prec)
		if err != nil {
			return false, append(leftTerms, rightTerms...), err
		}
		var out bool
		if x.Op == "AND" {
			out = leftOK && rightOK
		} else {
			out = leftOK || rightOK
		}
		terms := append(leftTerms, rightTerms...)
		terms = append(terms, Term{
			Label:   x.Op,
			Value:   boolString(out),
			Outcome: out,
		})
		return out, terms, nil
	default:
		return false, nil, fmt.Errorf("decide: unknown node type")
	}
}

func evalComparison(c *expr.Comparison, rs *adapt.ResultSet, prec int) (bool, []Term, error) {
	id := c.MetricID + "." + c.Aggregate
	mv := rs.Metrics[c.MetricID]
	val, err := computeAggregate(c.Aggregate, mv.Raw, prec)
	if err != nil {
		return false, nil, err
	}
	lit, err := canonical.ParseDecimal(c.Literal, prec)
	if err != nil {
		return false, nil, fmt.Errorf("literal %q: %w", c.Literal, err)
	}
	out := compare(val, lit, c.Op)
	term := Term{
		Label:      fmt.Sprintf("%s %s %s", id, c.Op, c.Literal),
		Identifier: id,
		Value:      val.String(),
		Comparator: c.Op,
		Literal:    c.Literal,
		Outcome:    out,
	}
	return out, []Term{term}, nil
}

func compare(left, right canonical.Decimal, op string) bool {
	cmp := left.Cmp(right)
	switch op {
	case ">=":
		return cmp >= 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case "<":
		return cmp < 0
	case "==":
		return cmp == 0
	case "!=":
		return cmp != 0
	default:
		return false
	}
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
