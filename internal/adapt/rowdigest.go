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

package adapt

import (
	"strings"

	"github.com/GautamTalksDev/plimsoll/internal/canonical"
)

const rowDigestPrefix = "plimsoll-row-digest-v1\n"

// rowDigest hashes ordered row identifiers only. Row content never enters
// the digest, so customer data cannot be reconstructed from what we hold.
func rowDigest(rowIDs []string) string {
	var b strings.Builder
	b.WriteString(rowDigestPrefix)
	for i, id := range rowIDs {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(id)
	}
	return "sha256:" + canonical.Sum256([]byte(b.String()))
}
