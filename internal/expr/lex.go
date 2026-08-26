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

package expr

type kind int

const (
	tokEOF kind = iota
	tokIdent
	tokNumber
	tokAND
	tokOR
	tokNOT
	tokCmp
	tokDot
	tokLParen
	tokRParen
)

type token struct {
	kind   kind
	val    string
	offset int
}

type lexer struct {
	src    string
	i      int
	peeked *token
}

func (l *lexer) peek() (token, error) {
	if l.peeked != nil {
		return *l.peeked, nil
	}
	t, err := l.next()
	if err != nil {
		return token{}, err
	}
	l.peeked = &t
	return t, nil
}

func (l *lexer) next() (token, error) {
	if l.peeked != nil {
		t := *l.peeked
		l.peeked = nil
		return t, nil
	}
	l.skipWS()
	if l.i >= len(l.src) {
		return token{kind: tokEOF, offset: l.i}, nil
	}
	off := l.i
	c := l.src[l.i]
	switch c {
	case '(':
		l.i++
		return token{kind: tokLParen, val: "(", offset: off}, nil
	case ')':
		l.i++
		return token{kind: tokRParen, val: ")", offset: off}, nil
	case '.':
		l.i++
		return token{kind: tokDot, val: ".", offset: off}, nil
	case '+', '*', '/', '%', '^', ',', '[', ']', '{', '}', '\'', '"', '=', '!':
		if c == '=' || c == '!' {
			break
		}
		return token{}, &ParseError{Offset: off, Msg: "arithmetic and extra punctuation are not allowed"}
	}
	if c == '>' || c == '<' || c == '=' || c == '!' {
		return l.cmp(off)
	}
	if c == '-' {
		if l.i+1 < len(l.src) && isDigit(l.src[l.i+1]) {
			return l.number(off)
		}
		return token{}, &ParseError{Offset: off, Msg: "binary minus is not allowed"}
	}
	if isDigit(c) {
		return l.number(off)
	}
	if isLetter(c) {
		return l.ident(off)
	}
	return token{}, &ParseError{Offset: off, Msg: "unexpected character"}
}

func (l *lexer) cmp(off int) (token, error) {
	if l.i+1 < len(l.src) {
		two := l.src[l.i : l.i+2]
		if _, ok := Comparators[two]; ok {
			l.i += 2
			return token{kind: tokCmp, val: two, offset: off}, nil
		}
	}
	one := l.src[l.i : l.i+1]
	if _, ok := Comparators[one]; ok {
		l.i++
		return token{kind: tokCmp, val: one, offset: off}, nil
	}
	return token{}, &ParseError{Offset: off, Msg: "invalid comparator"}
}

func (l *lexer) number(off int) (token, error) {
	i := l.i
	if l.src[i] == '-' {
		i++
	}
	if i >= len(l.src) || !isDigit(l.src[i]) {
		return token{}, &ParseError{Offset: off, Msg: "invalid decimal"}
	}
	if l.src[i] == '0' {
		i++
		if i < len(l.src) && isDigit(l.src[i]) {
			return token{}, &ParseError{Offset: off, Msg: "leading zeros are not allowed"}
		}
	} else {
		for i < len(l.src) && isDigit(l.src[i]) {
			i++
		}
	}
	if i < len(l.src) && l.src[i] == '.' {
		i++
		if i >= len(l.src) || !isDigit(l.src[i]) {
			return token{}, &ParseError{Offset: off, Msg: "invalid decimal"}
		}
		for i < len(l.src) && isDigit(l.src[i]) {
			i++
		}
	}
	val := l.src[l.i:i]
	l.i = i
	return token{kind: tokNumber, val: val, offset: off}, nil
}

func (l *lexer) ident(off int) (token, error) {
	i := l.i
	for i < len(l.src) && (isLetter(l.src[i]) || isDigit(l.src[i]) || l.src[i] == '_') {
		i++
	}
	val := l.src[l.i:i]
	l.i = i
	switch val {
	case "AND":
		return token{kind: tokAND, val: val, offset: off}, nil
	case "OR":
		return token{kind: tokOR, val: val, offset: off}, nil
	case "NOT":
		return token{kind: tokNOT, val: val, offset: off}, nil
	default:
		return token{kind: tokIdent, val: val, offset: off}, nil
	}
}

func (l *lexer) skipWS() {
	for l.i < len(l.src) {
		switch l.src[l.i] {
		case ' ', '\t', '\n', '\r':
			l.i++
		default:
			return
		}
	}
}

func isLetter(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}
