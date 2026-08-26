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
	"math/big"
	"sort"

	"github.com/GautamTalksDev/plimsoll/internal/canonical"
)

func parseFiniteValues(raw []string, prec int) ([]canonical.Decimal, error) {
	out := make([]canonical.Decimal, 0, len(raw))
	for i, s := range raw {
		d, err := canonical.ParseDecimal(s, prec)
		if err != nil {
			return nil, fmt.Errorf("row %d value %q: %w", i, s, err)
		}
		out = append(out, d)
	}
	return out, nil
}

func computeAggregate(agg string, raw []string, prec int) (canonical.Decimal, error) {
	switch agg {
	case "count":
		vals, err := parseFiniteValues(raw, prec)
		if err != nil {
			return canonical.Decimal{}, err
		}
		return canonical.FromInt(len(vals), prec), nil
	case "pass_rate":
		return passRate(raw, prec)
	case "mean":
		return meanAggregate(raw, prec)
	case "min", "max":
		return minMaxAggregate(agg, raw, prec)
	case "median", "p10", "p50", "p90", "p95":
		p := percentileForAggregate(agg)
		return percentileNearestRank(raw, prec, p)
	default:
		return canonical.Decimal{}, fmt.Errorf("decide: unknown aggregate %q", agg)
	}
}

func percentileForAggregate(agg string) int {
	switch agg {
	case "median", "p50":
		return 50
	case "p10":
		return 10
	case "p90":
		return 90
	case "p95":
		return 95
	default:
		return 0
	}
}

func meanAggregate(raw []string, prec int) (canonical.Decimal, error) {
	vals, err := parseFiniteValues(raw, prec)
	if err != nil {
		return canonical.Decimal{}, err
	}
	if len(vals) == 0 {
		return canonical.Decimal{}, errNoObservations
	}
	sum := vals[0]
	for i := 1; i < len(vals); i++ {
		sum = sum.Add(vals[i])
	}
	return sum.DivInt(len(vals))
}

func minMaxAggregate(which string, raw []string, prec int) (canonical.Decimal, error) {
	vals, err := parseFiniteValues(raw, prec)
	if err != nil {
		return canonical.Decimal{}, err
	}
	if len(vals) == 0 {
		return canonical.Decimal{}, errNoObservations
	}
	best := vals[0]
	for i := 1; i < len(vals); i++ {
		if which == "min" {
			if vals[i].Cmp(best) < 0 {
				best = vals[i]
			}
		} else if vals[i].Cmp(best) > 0 {
			best = vals[i]
		}
	}
	return best, nil
}

func percentileNearestRank(raw []string, prec int, p int) (canonical.Decimal, error) {
	vals, err := parseFiniteValues(raw, prec)
	if err != nil {
		return canonical.Decimal{}, err
	}
	n := len(vals)
	if n == 0 {
		return canonical.Decimal{}, errNoObservations
	}
	sort.SliceStable(vals, func(i, j int) bool {
		return vals[i].Cmp(vals[j]) < 0
	})
	r := ceilPercentileRank(p, n)
	return vals[r-1], nil
}

func ceilPercentileRank(p, n int) int {
	if p < 1 {
		p = 1
	}
	num := big.NewInt(int64(p * n))
	den := big.NewInt(100)
	quo, rem := num.QuoRem(num, den, new(big.Int))
	if rem.Sign() != 0 {
		quo.Add(quo, big.NewInt(1))
	}
	r := int(quo.Int64())
	if r < 1 {
		r = 1
	}
	if r > n {
		r = n
	}
	return r
}

func passRate(raw []string, prec int) (canonical.Decimal, error) {
	if len(raw) == 0 {
		return canonical.Decimal{}, errNoObservations
	}
	passes := 0
	for i, s := range raw {
		switch s {
		case "1", "true":
			passes++
		case "0", "false":
		default:
			return canonical.Decimal{}, fmt.Errorf("row %d pass bit %q: %w", i, s, errInvalidPassBit)
		}
	}
	return canonical.FromInt(passes, prec).DivInt(len(raw))
}

var (
	errNoObservations = fmt.Errorf("decide: no finite observations")
	errInvalidPassBit = fmt.Errorf("decide: invalid pass bit")
)
