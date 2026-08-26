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

	"github.com/GautamTalksDev/plimsoll/internal/expr"
)

// ReplayVerdict re-evaluates doc.Expression using comparison outcomes
// recorded in doc.Terms. Boolean operators are recomputed from the AST.
func ReplayVerdict(expression string, terms []Term) (string, error) {
	prog, err := ParseExpression(expression)
	if err != nil {
		return "", fmt.Errorf("decide: replay parse: %w", err)
	}
	ok, err := replayNode(prog.Root, terms)
	if err != nil {
		return "", err
	}
	if ok {
		return "PASS", nil
	}
	return "FAIL", nil
}

func replayNode(n expr.Node, terms []Term) (bool, error) {
	switch x := n.(type) {
	case *expr.Comparison:
		id := x.MetricID + "." + x.Aggregate
		for _, t := range terms {
			if t.Identifier == id && t.Comparator == x.Op && t.Literal == x.Literal {
				return t.Outcome, nil
			}
		}
		return false, fmt.Errorf("decide: replay missing term for %s %s %s", id, x.Op, x.Literal)
	case *expr.Not:
		ok, err := replayNode(x.X, terms)
		if err != nil {
			return false, err
		}
		return !ok, nil
	case *expr.Bool:
		leftOK, err := replayNode(x.Left, terms)
		if err != nil {
			return false, err
		}
		rightOK, err := replayNode(x.Right, terms)
		if err != nil {
			return false, err
		}
		if x.Op == "AND" {
			return leftOK && rightOK, nil
		}
		return leftOK || rightOK, nil
	default:
		return false, fmt.Errorf("decide: replay unknown node")
	}
}
