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

// Package testbin builds the plimsoll CLI binary for integration tests.
package testbin

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

var (
	once sync.Once
	bin  string
	err  error
)

// Plimsoll builds cmd/plimsoll once per process into a temp dir and returns
// its path. On Windows the binary ends with ".exe".
func Plimsoll(t testing.TB) string {
	t.Helper()
	once.Do(func() {
		dir, mkErr := os.MkdirTemp("", "plimsoll-testbin-*")
		if mkErr != nil {
			err = mkErr
			return
		}
		name := "plimsoll"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		out := filepath.Join(dir, name)
		cmd := exec.Command("go", "build", "-o", out, ".")
		cmd.Dir = filepath.Join(moduleRoot(), "cmd", "plimsoll")
		if b, buildErr := cmd.CombinedOutput(); buildErr != nil {
			err = buildErr
			_ = os.WriteFile(filepath.Join(dir, "build.log"), b, 0o600)
			return
		}
		bin = out
	})
	if err != nil {
		t.Fatalf("build plimsoll: %v", err)
	}
	return bin
}

func moduleRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	// internal/testbin/build.go -> repo root
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
