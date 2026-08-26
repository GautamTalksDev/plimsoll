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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/GautamTalksDev/plimsoll/internal/adapt"
	"github.com/GautamTalksDev/plimsoll/internal/attestation"
	"github.com/GautamTalksDev/plimsoll/internal/cliout"
	"github.com/GautamTalksDev/plimsoll/internal/decide"
	"github.com/GautamTalksDev/plimsoll/internal/keys"
	"github.com/GautamTalksDev/plimsoll/internal/logclient"
	"github.com/GautamTalksDev/plimsoll/internal/sealfile"
	"github.com/GautamTalksDev/plimsoll/internal/verify"
)

func newAttestCmd(root *rootFlags) *cobra.Command {
	var (
		sealPath string
		results  string
		publish  bool
		wait     bool
		timeout  string
		keyPath  string
		logPath  string
		logURL   string
		harness  string
	)
	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Adapt results, evaluate the sealed rule, sign, and optionally publish",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cliout.New()
			out.JSON = root.json
			code, err := runAttest(out, sealPath, results, publish, wait, timeout, keyPath, logPath, logURL, harness)
			if err != nil {
				if errors.Is(err, errAwaitTimeout) {
					return &exitCode{code: exitTimeout}
				}
				return err
			}
			if code != 0 {
				return &exitCode{code: code}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sealPath, "seal", "", "signed seal file (.seal.json)")
	cmd.Flags().StringVar(&results, "results", "", "harness results file")
	cmd.Flags().BoolVar(&publish, "publish", false, "submit attestation to the log")
	cmd.Flags().BoolVar(&wait, "wait", false, "with --publish, block until the log includes the attestation")
	cmd.Flags().StringVar(&timeout, "timeout", "5m", "with --wait, how long to poll (Go duration)")
	cmd.Flags().StringVar(&keyPath, "key", "", "Ed25519 private key path")
	cmd.Flags().StringVar(&logPath, "log", os.Getenv("PLIMSOLL_LOG"), "SQLite log path for --publish")
	cmd.Flags().StringVar(&logURL, "log-url", os.Getenv("PLIMSOLL_LOG_URL"), "HTTP log base URL for --publish")
	cmd.Flags().StringVar(&harness, "harness", "", "harness name (default: detect)")
	_ = cmd.MarkFlagRequired("seal")
	_ = cmd.MarkFlagRequired("results")
	return cmd
}

func runAttest(out *cliout.Printer, sealPath, resultsPath string, publish, wait bool, timeoutStr, keyPath, logPath, logURL, harness string) (int, error) {
	doc, err := sealfile.Read(sealPath)
	if err != nil {
		return exitOperational, opErrf("read seal: %v", err)
	}
	pub, err := doc.PublicKeyBytes()
	if err != nil {
		return exitOperational, opErrf("public key: %v", err)
	}
	if err := doc.Verify(pub); err != nil {
		return exitOperational, opErrf("verify seal: %v", err)
	}
	rawResults, err := os.ReadFile(resultsPath)
	if err != nil {
		return exitOperational, opErrf("read results: %v", err)
	}
	if harness == "" {
		harness, err = adapt.Detect(rawResults)
		if err != nil {
			return exitOperational, opErrf("detect harness: %v", err)
		}
	}
	rs, err := adapt.Adapt(harness, rawResults)
	if err != nil {
		return exitOperational, opErrf("adapt: %v", err)
	}
	verdict, err := decide.Evaluate(doc.Seal.Seal, rs)
	if err != nil {
		return exitOperational, opErrf("evaluate: %v", err)
	}
	attDoc, err := attestation.Build(doc.SealHash, doc.Seal.Seal, rs, verdict)
	if err != nil {
		return exitOperational, opErrf("build attestation: %v", err)
	}
	if keyPath == "" {
		keyPath, err = keys.DefaultPath()
		if err != nil {
			return exitOperational, opErrf("key path: %v", err)
		}
	}
	priv, _, err := keys.LoadOrCreate(keyPath)
	if err != nil {
		return exitOperational, opErrf("key: %v", err)
	}
	signed, err := attestation.Sign(attDoc, priv)
	if err != nil {
		return exitOperational, opErrf("sign attestation: %v", err)
	}
	wd, _ := os.Getwd()
	attPath := filepath.Join(wd, sealfile.SafeBaseName(doc.Seal.Seal.Subject.Name)+".attest.json")
	b, _ := json.MarshalIndent(signed.Document, "", "  ")
	if err := os.WriteFile(attPath, b, 0o644); err != nil { //nolint:gosec // G306 -- public attestation artifact
		return exitOperational, opErrf("write attestation: %v", err)
	}
	var pubRes *logclient.PublishAttestResult
	published := false
	pending := false
	if publish {
		if wait && logURL == "" && logPath != "" {
			wait = false
		}
		lc, err := openLogClient(logPath, logURL, priv)
		if err != nil {
			return exitOperational, opErrf("log: %v", err)
		}
		defer func() { _ = lc.Close() }()
		pubRes, err = lc.PublishAttestation(signed)
		if err != nil {
			return exitOperational, opErrf("publish: %v", err)
		}
		if pubRes.Pending {
			pending = true
			if wait {
				d, err := time.ParseDuration(timeoutStr)
				if err != nil {
					return exitOperational, opErrf("timeout: %v", err)
				}
				if logURL == "" {
					return exitOperational, opErrf("--wait requires --log-url for the public HTTP log")
				}
				w, err := awaitAttestHTTP(logURL, signed.Document.SealHash, signed.Document.ResultDigest, d)
				if err != nil {
					if isTimeout(err) {
						return exitTimeout, errAwaitTimeout
					}
					return exitOperational, opErrf("wait: %v", err)
				}
				pubRes.Pending = false
				pubRes.AttemptNo = w.AttemptNo
				pubRes.Index = w.AttestationIndex
				pubRes.InclusionProof = w.InclusionProof.InclusionProof
				pubRes.Checkpoint = w.InclusionProof.Checkpoint
				prev := make([]string, 0, len(w.Attempts))
				for _, a := range w.Attempts {
					if a.ResultDigest == signed.Document.ResultDigest {
						break
					}
					prev = append(prev, strings.ToUpper(a.Verdict))
				}
				pubRes.PreviousVerdicts = prev
				pending = false
				published = true
				out.PrintAttemptLine(pubRes.AttemptNo, pubRes.PreviousVerdicts)
				env, err := verify.BuildAttestEnvelopeHTTP(logURL, signed.Document)
				if err != nil {
					return exitOperational, opErrf("envelope: %v", err)
				}
				eb, _ := json.MarshalIndent(env, "", "  ")
				if err := os.WriteFile(attPath, eb, 0o644); err != nil { //nolint:gosec // G306 -- public attestation artifact
					return exitOperational, opErrf("write envelope: %v", err)
				}
			}
		} else {
			published = true
			out.PrintAttemptLine(pubRes.AttemptNo, pubRes.PreviousVerdicts)
			env, err := buildAttestEnvelope(lc, logURL, signed.Document)
			if err != nil {
				return exitOperational, opErrf("envelope: %v", err)
			}
			eb, _ := json.MarshalIndent(env, "", "  ")
			if err := os.WriteFile(attPath, eb, 0o644); err != nil { //nolint:gosec // G306 -- public attestation artifact
				return exitOperational, opErrf("write envelope: %v", err)
			}
		}
	}
	verifyLog := logURL
	if verifyLog == "" {
		verifyLog = "<url>"
	}
	if out.JSON {
		payload := map[string]any{
			"verdict":     verdict.Result,
			"exit_code":   verdictExit(verdict),
			"attestation": attPath,
			"expression":  verdict.Expression,
			"terms":       verdict.Terms,
			"reasons":     verdict.Reasons,
			"submitted":   publish,
			"pending":     pending,
			"published":   published,
		}
		if pubRes != nil && published {
			payload["attempt_no"] = pubRes.AttemptNo
			payload["previous_verdicts"] = pubRes.PreviousVerdicts
			payload["log_index"] = pubRes.Index
		}
		_ = out.EmitJSON(payload)
	} else {
		out.Printf("Verdict: %s\n", cliout.Sanitize(verdict.Result))
		out.Printf("Wrote %s\n", attPath)
		for _, t := range verdict.Terms {
			if t.Identifier != "" {
				out.Printf("  %s = %s (%s %s %s) -> %v\n",
					cliout.Sanitize(t.Identifier), cliout.Sanitize(t.Value),
					cliout.Sanitize(t.Comparator), cliout.Sanitize(t.Literal),
					cliout.Sanitize(t.Label), t.Outcome)
			}
		}
		if pending {
			out.PrintSubmittedPending(attPath, verifyLog)
		}
	}
	return verdictExit(verdict), nil
}

func verdictExit(v *decide.Verdict) int {
	if v == nil {
		return 2
	}
	switch v.Result {
	case "PASS":
		return 0
	case "FAIL":
		return 1
	default:
		return 2
	}
}

func buildAttestEnvelope(lc *logclient.Client, logURL string, att *attestation.Document) (*verify.AttestEnvelope, error) {
	if l := lc.Log(); l != nil {
		return verify.BuildAttestEnvelope(l, lc.PublicKey(), att)
	}
	return verify.BuildAttestEnvelopeHTTP(logURL, att)
}
