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

package evidence

import (
	"github.com/GautamTalksDev/plimsoll/internal/canonical"
	"github.com/GautamTalksDev/plimsoll/internal/seal"
)

func buildSupersedeChain(src *source, startHash string) ([]SupersedeLink, error) {
	var reversed []SupersedeLink
	hash := startHash
	for hash != "" {
		rec, doc, err := src.seal(hash)
		if err != nil {
			return nil, err
		}
		link := SupersedeLink{
			SealHash:    rec.SealHash,
			Supersedes:  rec.Supersedes,
			SubmittedAt: rec.SubmittedAt,
		}
		if doc != nil && doc.Seal != nil && doc.Seal.Seal != nil && doc.Seal.Seal.Supersedes != nil {
			link.SupersedeReason = doc.Seal.Seal.Supersedes.Reason
		} else if len(rec.Canonical) > 0 {
			var s seal.Seal
			if err := canonical.DecodeCanonical(rec.Canonical, &s); err == nil && s.Supersedes != nil {
				link.SupersedeReason = s.Supersedes.Reason
			}
		}
		reversed = append(reversed, link)
		if rec.Supersedes == "" {
			break
		}
		hash = rec.Supersedes
	}
	out := make([]SupersedeLink, len(reversed))
	for i := range reversed {
		out[i] = reversed[len(reversed)-1-i]
	}
	return out, nil
}
