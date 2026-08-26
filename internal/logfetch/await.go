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

package logfetch

import (
	"context"
	"fmt"
	"time"

	"github.com/GautamTalksDev/plimsoll/internal/log"
)

// WaitResult is a seal that has appeared in the log, with proofs.
type WaitResult struct {
	Seal           *SealResponse
	Attempts       []log.Attempt
	InclusionProof *EntryProofResponse
	// AttemptNo is the latest attempt_no for the seal (0 if none).
	AttemptNo int
	// AttestationIndex is set when waiting for a specific result_digest.
	AttestationIndex int64
}

// WaitForSeal polls until GET /seal/{hash} succeeds or ctx is done.
func (c *Client) WaitForSeal(ctx context.Context, sealHash string, every time.Duration) (*WaitResult, error) {
	if every <= 0 {
		every = 2 * time.Second
	}
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return nil, fmt.Errorf("logfetch: await seal: %w (last: %v)", err, lastErr)
			}
			return nil, fmt.Errorf("logfetch: await seal: %w", err)
		}
		rec, err := c.Seal(sealHash)
		if err == nil {
			attempts, aerr := c.Attempts(sealHash)
			if aerr != nil {
				attempts = nil
			}
			proof, perr := c.EntryInclusionProof(rec.Idx)
			if perr != nil {
				return nil, perr
			}
			attemptNo := 0
			if len(attempts) > 0 {
				attemptNo = attempts[len(attempts)-1].AttemptNo
			}
			return &WaitResult{
				Seal: rec, Attempts: attempts, InclusionProof: proof, AttemptNo: attemptNo,
			}, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("logfetch: await seal: %w (last: %v)", ctx.Err(), lastErr)
		case <-time.After(every):
		}
	}
}

// WaitForAttestation polls until the seal has an attempt with resultDigest.
func (c *Client) WaitForAttestation(ctx context.Context, sealHash, resultDigest string, every time.Duration) (*WaitResult, error) {
	if every <= 0 {
		every = 2 * time.Second
	}
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return nil, fmt.Errorf("logfetch: await attestation: %w (last: %v)", err, lastErr)
			}
			return nil, fmt.Errorf("logfetch: await attestation: %w", err)
		}
		rec, err := c.Seal(sealHash)
		if err != nil {
			lastErr = err
		} else {
			attempts, aerr := c.Attempts(sealHash)
			if aerr != nil {
				lastErr = aerr
			} else {
				for _, a := range attempts {
					if a.ResultDigest == resultDigest {
						proof, perr := c.EntryInclusionProof(a.Idx)
						if perr != nil {
							return nil, perr
						}
						return &WaitResult{
							Seal: rec, Attempts: attempts, InclusionProof: proof,
							AttemptNo: a.AttemptNo, AttestationIndex: a.Idx,
						}, nil
					}
				}
				lastErr = fmt.Errorf("attestation %s not yet present", resultDigest)
			}
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("logfetch: await attestation: %w (last: %v)", ctx.Err(), lastErr)
		case <-time.After(every):
		}
	}
}
