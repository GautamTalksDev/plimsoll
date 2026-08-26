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

package payload

import (
	"testing"
)

func TestAssertPublishPayloads(t *testing.T) {
	sealOK := []byte(`{"seal_hash":"sha256:abc","canonical_b64":"e30=","submitter_id":"org","submitted_at":1,"supersedes":"","signature_b64":"AA==","public_key_b64":"BB=="}`)
	if err := AssertSealPublish(sealOK); err != nil {
		t.Fatal(err)
	}
	attOK := []byte(`{"seal_hash":"sha256:abc","result_digest":"sha256:def","verdict":"pass","canonical_b64":"e30=","signature_b64":"AA=="}`)
	if err := AssertAttestationPublish(attOK); err != nil {
		t.Fatal(err)
	}
	bad := []byte(`{"seal_hash":"x","rows":[]}`)
	if err := AssertSealPublish(bad); err == nil {
		t.Fatal("expected reject")
	}
}
