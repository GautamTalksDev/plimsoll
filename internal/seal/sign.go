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

package seal

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/GautamTalksDev/plimsoll/internal/canonical"
)

// ForSign returns a copy of s suitable for canonical hashing and signing.
// Local-only fields such as dataset.path are cleared.
func (s *Seal) ForSign() *Seal {
	if s == nil {
		return nil
	}
	cp := *s
	cp.Dataset = s.Dataset
	cp.Dataset.Path = ""
	return &cp
}

// CanonicalHash returns sha256:<hex> of the plimsoll-canon-v1 bytes of s.
func (s *Seal) CanonicalHash() (string, error) {
	return s.ForSign().canonicalHash()
}

func (s *Seal) canonicalHash() (string, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("seal: marshal: %w", err)
	}
	return canonical.Hash(raw)
}

// CanonicalBytes returns plimsoll-canon-v1 bytes for signing/verification.
func (s *Seal) CanonicalBytes() ([]byte, error) {
	return s.canonicalBytes()
}

func (s *Seal) canonicalBytes() ([]byte, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("seal: marshal: %w", err)
	}
	return canonical.Canonicalize(raw)
}

// Sign returns an Ed25519 signature over the canonical seal bytes.
func (s *Seal) Sign(priv ed25519.PrivateKey) (*SignedSeal, error) {
	if s == nil {
		return nil, fmt.Errorf("seal: nil")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("seal: invalid private key size")
	}
	msg, err := s.ForSign().canonicalBytes()
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, msg)
	cp := *s.ForSign()
	return &SignedSeal{Seal: &cp, Signature: sig}, nil
}

// VerifySignature checks ss against pub using only the object and key.
// It does not contact a log.
func VerifySignature(pub ed25519.PublicKey, ss *SignedSeal) error {
	if ss == nil || ss.Seal == nil {
		return fmt.Errorf("seal: nil signed seal")
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("seal: invalid public key size")
	}
	msg, err := ss.Seal.ForSign().canonicalBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, ss.Signature) {
		return errors.New("seal: signature verification failed")
	}
	return nil
}
