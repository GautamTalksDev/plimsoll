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

package expr

// ParseExpression parses a prereg-v1 decision_rule.expression.
// It does not evaluate the expression and does not look up metrics.
func ParseExpression(s string) (*Program, error) {
	p := &parser{lex: lexer{src: s}}
	n, err := p.orExpr()
	if err != nil {
		return nil, err
	}
	t, err := p.lex.peek()
	if err != nil {
		return nil, err
	}
	if t.kind != tokEOF {
		return nil, &ParseError{Offset: t.offset, Msg: "trailing input"}
	}
	return &Program{Root: n}, nil
}

type parser struct {
	lex lexer
}

func (p *parser) orExpr() (Node, error) {
	left, err := p.andExpr()
	if err != nil {
		return nil, err
	}
	for {
		t, err := p.lex.peek()
		if err != nil {
			return nil, err
		}
		if t.kind != tokOR {
			return left, nil
		}
		if _, err := p.lex.next(); err != nil {
			return nil, err
		}
		right, err := p.andExpr()
		if err != nil {
			return nil, err
		}
		left = &Bool{Op: "OR", Left: left, Right: right}
	}
}

func (p *parser) andExpr() (Node, error) {
	left, err := p.notExpr()
	if err != nil {
		return nil, err
	}
	for {
		t, err := p.lex.peek()
		if err != nil {
			return nil, err
		}
		if t.kind != tokAND {
			return left, nil
		}
		if _, err := p.lex.next(); err != nil {
			return nil, err
		}
		right, err := p.notExpr()
		if err != nil {
			return nil, err
		}
		left = &Bool{Op: "AND", Left: left, Right: right}
	}
}

func (p *parser) notExpr() (Node, error) {
	t, err := p.lex.peek()
	if err != nil {
		return nil, err
	}
	if t.kind == tokNOT {
		if _, err := p.lex.next(); err != nil {
			return nil, err
		}
		x, err := p.notExpr()
		if err != nil {
			return nil, err
		}
		return &Not{X: x}, nil
	}
	return p.primary()
}

func (p *parser) primary() (Node, error) {
	t, err := p.lex.peek()
	if err != nil {
		return nil, err
	}
	if t.kind == tokLParen {
		if _, err := p.lex.next(); err != nil {
			return nil, err
		}
		n, err := p.orExpr()
		if err != nil {
			return nil, err
		}
		closeTok, err := p.lex.next()
		if err != nil {
			return nil, err
		}
		if closeTok.kind != tokRParen {
			return nil, &ParseError{Offset: closeTok.offset, Msg: "expected )"}
		}
		return n, nil
	}
	return p.comparison()
}

func (p *parser) comparison() (Node, error) {
	id, err := p.lex.next()
	if err != nil {
		return nil, err
	}
	if id.kind != tokIdent {
		return nil, &ParseError{Offset: id.offset, Msg: "expected metric_id"}
	}
	dot, err := p.lex.next()
	if err != nil {
		return nil, err
	}
	if dot.kind != tokDot {
		return nil, &ParseError{Offset: dot.offset, Msg: "expected '.' after metric_id"}
	}
	agg, err := p.lex.next()
	if err != nil {
		return nil, err
	}
	if agg.kind != tokIdent {
		return nil, &ParseError{Offset: agg.offset, Msg: "expected aggregate"}
	}
	if _, ok := Aggregates[agg.val]; !ok {
		return nil, &ParseError{Offset: agg.offset, Msg: "unknown aggregate"}
	}
	cmp, err := p.lex.next()
	if err != nil {
		return nil, err
	}
	if cmp.kind != tokCmp {
		return nil, &ParseError{Offset: cmp.offset, Msg: "expected comparator"}
	}
	lit, err := p.lex.next()
	if err != nil {
		return nil, err
	}
	if lit.kind != tokNumber {
		return nil, &ParseError{Offset: lit.offset, Msg: "expected decimal literal"}
	}
	return &Comparison{
		MetricID:  id.val,
		Aggregate: agg.val,
		Op:        cmp.val,
		Literal:   lit.val,
	}, nil
}
