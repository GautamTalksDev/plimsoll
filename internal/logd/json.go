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

package logd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/sealfile"
	"github.com/GautamTalksDev/plimsoll/internal/site"
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

var errBadSealHash = errors.New("logd: missing seal hash")

func decodeSealHash(s string) (string, error) {
	s = strings.Trim(s, " /")
	if s == "" {
		return "", errBadSealHash
	}
	// Accept both the static-tree directory form (sha256-<hex>) and the
	// canonical digest (sha256:<hex>). net/http has already decoded any
	// percent-encoding by this point, so %3A arrives here as a colon.
	return site.ParseSealDir(s), nil
}

func wantsHTML(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if accept == "" {
		return true
	}
	return strings.Contains(accept, "text/html") && !strings.Contains(accept, "application/json")
}

func sealRecordJSON(rec log.SealRecord) map[string]any {
	return map[string]any{
		"index":          rec.Idx,
		"seal_hash":      rec.SealHash,
		"canonical_b64":  encodeB64(rec.Canonical),
		"signature_b64":  rec.Signature,
		"public_key_b64": rec.PublicKey,
		"submitter_id":   rec.SubmitterID,
		"submitted_at":   rec.SubmittedAt,
		"supersedes":     rec.Supersedes,
		"leaf_hash":      rec.LeafHash,
	}
}

func storeProof(p log.InclusionProof) sealfile.StoredInclusionProof {
	return sealfile.StoreProof(p)
}

func cpJSON(cp log.Checkpoint) map[string]any {
	return map[string]any{
		"tree_size": cp.TreeSize, "root_hash": cp.RootHash,
		"timestamp": cp.Timestamp, "signature": cp.Signature,
	}
}

func encodeB64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
