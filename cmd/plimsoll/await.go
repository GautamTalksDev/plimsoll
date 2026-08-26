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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/GautamTalksDev/plimsoll/internal/cliout"
	"github.com/GautamTalksDev/plimsoll/internal/logfetch"
)

const exitTimeout = 4

func newAwaitCmd(root *rootFlags) *cobra.Command {
	var (
		sealHash string
		logURL   string
		timeout  string
		digest   string
	)
	cmd := &cobra.Command{
		Use:   "await",
		Short: "Poll the log until a seal (or attestation) appears",
		Long: `Poll /seal/{hash} until the entry is queryable on the public log.

The public Plimsoll Log appends asynchronously (typically within about a
minute after --publish). Use this command, or --wait on seal/attest, when
you need the inclusion proof before continuing.

Exit codes: 0 found, 4 timeout, 3 operational error.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cliout.New()
			out.JSON = root.json
			err := runAwait(out, sealHash, logURL, timeout, digest)
			if err != nil {
				if errors.Is(err, errAwaitTimeout) {
					return &exitCode{code: exitTimeout}
				}
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sealHash, "seal", "", "seal digest (sha256:…)")
	cmd.Flags().StringVar(&logURL, "log", os.Getenv("PLIMSOLL_LOG_URL"), "HTTP log base URL")
	cmd.Flags().StringVar(&timeout, "timeout", "5m", "how long to wait (Go duration, e.g. 5m, 90s)")
	cmd.Flags().StringVar(&digest, "result-digest", "", "optional: wait for this attestation result_digest on the seal")
	_ = cmd.MarkFlagRequired("seal")
	_ = cmd.MarkFlagRequired("log")
	return cmd
}

var errAwaitTimeout = errors.New("await timeout")

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errAwaitTimeout) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "deadline exceeded") || strings.Contains(s, "context deadline")
}

func runAwait(out *cliout.Printer, sealHash, logURL, timeoutStr, resultDigest string) error {
	if logURL == "" {
		return opErrf("--log is required")
	}
	d, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return opErrf("timeout: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	fc := logfetch.New(logURL, nil)
	var wait *logfetch.WaitResult
	if resultDigest != "" {
		wait, err = fc.WaitForAttestation(ctx, sealHash, resultDigest, 2*time.Second)
	} else {
		wait, err = fc.WaitForSeal(ctx, sealHash, 2*time.Second)
	}
	if err != nil {
		if isTimeout(err) {
			return errAwaitTimeout
		}
		return opErrf("await: %v", err)
	}
	proof := wait.InclusionProof.InclusionProof
	idx := wait.Seal.Idx
	if resultDigest != "" {
		idx = wait.AttestationIndex
	}
	if out.JSON {
		return out.EmitJSON(map[string]any{
			"seal_hash":       sealHash,
			"index":           idx,
			"attempt_no":      wait.AttemptNo,
			"inclusion_proof": proof,
			"checkpoint":      wait.InclusionProof.Checkpoint,
		})
	}
	out.Success(fmt.Sprintf("Found in log at index %d", idx))
	out.Printf("Attempt number: %d\n", wait.AttemptNo)
	b, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		return opErrf("marshal proof: %v", err)
	}
	out.Printf("Inclusion proof:\n%s\n", string(b))
	return nil
}

func awaitSealHTTP(logURL, sealHash string, timeout time.Duration) (*logfetch.WaitResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return logfetch.New(logURL, nil).WaitForSeal(ctx, sealHash, 2*time.Second)
}

func awaitAttestHTTP(logURL, sealHash, resultDigest string, timeout time.Duration) (*logfetch.WaitResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return logfetch.New(logURL, nil).WaitForAttestation(ctx, sealHash, resultDigest, 2*time.Second)
}
