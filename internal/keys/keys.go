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

package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

const DefaultKeyPath = ".config/plimsoll/key"

// LoadOrCreate loads an Ed25519 private key from path, creating it at mode
// 0600 if absent. path is expanded with UserHomeDir when it starts with ~.
func LoadOrCreate(path string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	path, err := expandPath(path)
	if err != nil {
		return nil, nil, err
	}
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("keys: invalid key size at %s", path)
		}
		priv := ed25519.PrivateKey(b)
		return priv, priv.Public().(ed25519.PublicKey), nil
	} else if !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("keys: read %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, fmt.Errorf("keys: mkdir: %w", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("keys: generate: %w", err)
	}
	if err := os.WriteFile(path, []byte(priv), 0o600); err != nil {
		return nil, nil, fmt.Errorf("keys: write %s: %w", path, err)
	}
	return priv, pub, nil
}

func expandPath(path string) (string, error) {
	if len(path) >= 2 && path[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, DefaultKeyPath), nil
}
