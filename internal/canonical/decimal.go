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

import (
	"fmt"
	"math/big"
	"strings"
)

const maxPrecision = 18

// Decimal is a fixed-precision decimal used for metric values.
//
// Metric values are parsed from their ORIGINAL string representation in
// the results file wherever possible, never through float64 / IEEE 754
// binary64. 0.82 cannot be represented exactly in binary64; parsing it
// as float64 yields a neighbor such as 0.8200000000000001, so two
// writings of the same reported metric would either disagree or would
// require an ad-hoc epsilon. Comparison here is exact at the declared
// scale after rounding half away from zero.
type Decimal struct {
	coeff *big.Int
	prec  int
}

// ParseDecimal parses s as a decimal and rounds it to precision digits
// after the point. precision must be in [0, 18].
func ParseDecimal(s string, precision int) (Decimal, error) {
	if precision < 0 || precision > maxPrecision {
		return Decimal{}, ErrPrecision
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return Decimal{}, ErrInvalidDecimal
	}
	if strings.ContainsAny(s, "/_") {
		return Decimal{}, fmt.Errorf("%w: %q", ErrInvalidDecimal, s)
	}
	r := new(big.Rat)
	if _, ok := r.SetString(s); !ok {
		return Decimal{}, fmt.Errorf("%w: %q", ErrInvalidDecimal, s)
	}
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(precision)), nil)
	scaled := new(big.Rat).Mul(r, new(big.Rat).SetInt(scale))
	return Decimal{coeff: roundRatToInt(scaled), prec: precision}, nil
}

// String returns the decimal formatted with d.prec digits after the point.
func (d Decimal) String() string {
	if d.coeff == nil {
		d.coeff = new(big.Int)
	}
	if d.prec == 0 {
		return d.coeff.String()
	}
	sign := ""
	c := new(big.Int).Set(d.coeff)
	if c.Sign() < 0 {
		sign = "-"
		c.Abs(c)
	}
	scale := pow10(d.prec)
	intPart, fracPart := new(big.Int).QuoRem(c, scale, new(big.Int))
	fracStr := fracPart.String()
	for len(fracStr) < d.prec {
		fracStr = "0" + fracStr
	}
	return sign + intPart.String() + "." + fracStr
}

// Add returns d + other at the same precision.
func (d Decimal) Add(other Decimal) Decimal {
	if d.prec != other.prec {
		panic("decimal: Add requires equal precision")
	}
	if d.coeff == nil {
		d.coeff = new(big.Int)
	}
	if other.coeff == nil {
		other.coeff = new(big.Int)
	}
	return Decimal{
		coeff: new(big.Int).Add(d.coeff, other.coeff),
		prec:  d.prec,
	}
}

// DivInt divides d by n using half-away-from-zero rounding at d's precision.
func (d Decimal) DivInt(n int) (Decimal, error) {
	if n <= 0 {
		return Decimal{}, ErrInvalidDecimal
	}
	if d.coeff == nil {
		d.coeff = new(big.Int)
	}
	r := new(big.Rat).SetFrac(d.coeff, big.NewInt(int64(n)))
	return Decimal{coeff: roundRatToInt(r), prec: d.prec}, nil
}

// FromInt builds a decimal integer at precision prec.
func FromInt(n int, prec int) Decimal {
	return Decimal{coeff: big.NewInt(int64(n)), prec: prec}
}

// Values with different precision are compared exactly by cross-scaling.
func (d Decimal) Cmp(other Decimal) int {
	if d.coeff == nil {
		d.coeff = new(big.Int)
	}
	if other.coeff == nil {
		other.coeff = new(big.Int)
	}
	if d.prec == other.prec {
		return d.coeff.Cmp(other.coeff)
	}
	// d.coeff / 10^d.prec  vs  other.coeff / 10^other.prec
	// d.coeff * 10^other.prec  vs  other.coeff * 10^d.prec
	left := new(big.Int).Set(d.coeff)
	right := new(big.Int).Set(other.coeff)
	left.Mul(left, pow10(other.prec))
	right.Mul(right, pow10(d.prec))
	return left.Cmp(right)
}

func pow10(n int) *big.Int {
	return new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
}

func roundRatToInt(r *big.Rat) *big.Int {
	num := new(big.Int).Set(r.Num())
	den := new(big.Int).Set(r.Denom())
	neg := num.Sign() < 0
	if neg {
		num.Abs(num)
	}
	quo, rem := new(big.Int).QuoRem(num, den, new(big.Int))
	twice := new(big.Int).Lsh(rem, 1)
	if twice.Cmp(den) >= 0 {
		quo.Add(quo, big.NewInt(1))
	}
	if neg {
		quo.Neg(quo)
	}
	return quo
}
