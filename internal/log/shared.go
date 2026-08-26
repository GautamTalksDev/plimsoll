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

package log

import (
	"crypto/ed25519"

	"github.com/GautamTalksDev/plimsoll/internal/logmerkle"
)

// Attempt is one attested attempt against a seal, in attempt order.
type Attempt = logmerkle.Attempt

// Checkpoint is a signed tree head for the Merkle log.
type Checkpoint = logmerkle.Checkpoint

// CheckpointVersion is the signed checkpoint payload tag for prereg-v1 logs.
const CheckpointVersion = logmerkle.CheckpointVersion

// VerifyCheckpoint verifies an Ed25519 signature over a checkpoint payload.
func VerifyCheckpoint(pub ed25519.PublicKey, cp Checkpoint) bool {
	return logmerkle.VerifyCheckpoint(pub, cp)
}
