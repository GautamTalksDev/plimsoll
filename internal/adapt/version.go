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

package adapt

import (
	"fmt"
	"strconv"
	"strings"
)

type semver struct {
	major int
	minor int
	patch int
}

func parseSemver(s string) (semver, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return semver{}, fmt.Errorf("empty version")
	}
	parts := strings.Split(s, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return semver{}, fmt.Errorf("invalid version %q", s)
	}
	var out semver
	for i, p := range parts {
		if p == "" {
			return semver{}, fmt.Errorf("invalid version %q", s)
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, fmt.Errorf("invalid version %q", s)
		}
		switch i {
		case 0:
			out.major = n
		case 1:
			out.minor = n
		case 2:
			out.patch = n
		}
	}
	return out, nil
}

func semverInRange(v, minV, maxV semver) bool {
	if cmpSemver(v, minV) < 0 {
		return false
	}
	return cmpSemver(v, maxV) <= 0
}

func cmpSemver(a, b semver) int {
	if a.major != b.major {
		return a.major - b.major
	}
	if a.minor != b.minor {
		return a.minor - b.minor
	}
	return a.patch - b.patch
}

func checkSemverRange(version string, minV, maxV semver) error {
	v, err := parseSemver(version)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if !semverInRange(v, minV, maxV) {
		return fmt.Errorf("%w: %s", ErrUnsupportedVersion, version)
	}
	return nil
}

func checkIntRange(version int, minV, maxV int) error {
	if version < minV || version > maxV {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, version)
	}
	return nil
}
