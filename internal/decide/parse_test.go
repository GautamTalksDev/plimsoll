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

import (
	"errors"
	"testing"
)

func TestParseValid(t *testing.T) {
	t.Parallel()
	for _, s := range []string{
		"acc.mean >= 0.82",
		"acc.mean >= 0.82 AND loss.max <= 1.0",
		"NOT acc.pass_rate < 0.5",
		"(acc.p50 >= 0.7 OR acc.p90 >= 0.8)",
		"acc.count == 100",
		"acc.min != -1.5",
	} {
		p, err := ParseExpression(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if p == nil || p.Root == nil {
			t.Fatalf("%q: nil program", s)
		}
	}
}

func TestParseRejectsArithmeticAndCalls(t *testing.T) {
	t.Parallel()
	for _, s := range []string{
		"acc.mean + 0.01 >= 0.82",
		"acc.mean >= 0.8 + 0.02",
		"mean(acc) >= 0.82",
		"acc.mean() >= 0.82",
		"acc.mean >= 0.82 * 1",
		"acc.mean - 1 >= 0",
		"acc.mean >= 0.82 AND",
		"",
		"acc.mean >=",
		"acc.foo >= 1",
	} {
		if _, err := ParseExpression(s); err == nil {
			t.Fatalf("expected error for %q", s)
		} else {
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("%q: want ParseError, got %T %v", s, err, err)
			}
		}
	}
}

func TestMetricIDs(t *testing.T) {
	t.Parallel()
	p, err := ParseExpression("acc.mean >= 0.82 AND loss.max <= 1")
	if err != nil {
		t.Fatal(err)
	}
	ids := p.MetricIDs()
	if len(ids) != 2 || ids[0] != "acc" || ids[1] != "loss" {
		t.Fatalf("ids=%v", ids)
	}
}

func TestMaximalMunchComparator(t *testing.T) {
	t.Parallel()
	p, err := ParseExpression("acc.mean >= 1")
	if err != nil {
		t.Fatal(err)
	}
	c, ok := p.Root.(*Comparison)
	if !ok || c.Op != ">=" {
		t.Fatalf("got %#v", p.Root)
	}
}

func FuzzParseExpression(f *testing.F) {
	for _, s := range []string{
		"",
		"acc.mean >= 0.82",
		"acc.mean >= 0.82 AND loss.max <= 1",
		"NOT (acc.p10 >= 0)",
		"acc.mean + 1",
		"mean(acc)",
		"\x00",
		"AND OR NOT",
		"acc.mean >= 0.82 extra",
		"((((((((((acc.mean >= 1))))))))))",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, err := ParseExpression(s)
		if err != nil {
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("non-ParseError: %T %v", err, err)
			}
		}
	})
}
