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

package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/GautamTalksDev/plimsoll/internal/cliout"
	"github.com/GautamTalksDev/plimsoll/internal/verify"
)

func newVerifyCmd(root *rootFlags) *cobra.Command {
	var (
		offline    bool
		logURL     string
		bundlePath string
	)
	cmd := &cobra.Command{
		Use:   "verify <attestation.json>",
		Short: "Verify an attestation against a seal and transparency log",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cliout.New()
			out.JSON = root.json
			report, err := verify.Run(args[0], verify.Options{
				Offline:    offline,
				LogURL:     logURL,
				BundlePath: bundlePath,
			})
			if err != nil {
				return opErrf("verify: %v", err)
			}
			emitVerifyReport(out, report)
			if report.Verdict == verify.VerdictNotVerified {
				return &exitCode{code: 1}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&offline, "offline", false, "verify from bundle only (no network)")
	cmd.Flags().StringVar(&logURL, "log", os.Getenv("PLIMSOLL_LOG_URL"), "transparency log base URL")
	cmd.Flags().StringVar(&bundlePath, "bundle", "", "offline verification bundle path")
	return cmd
}

func emitVerifyReport(out *cliout.Printer, r *verify.Report) {
	if out.JSON {
		_ = out.EmitJSON(r)
		return
	}
	out.Printf("%s\n", cliout.Sanitize(r.Verdict))
	for _, c := range r.Checks {
		status := "FAIL"
		if c.Pass {
			status = "PASS"
		}
		out.Printf("  %s %s: %s\n", c.ID, status, cliout.Sanitize(c.Reason))
	}
	if r.Disclosure != nil && r.Verdict == verify.VerdictVerifiedDisclosures {
		out.Printf("Disclosure: %s\n", cliout.Sanitize(formatDisclosureLine(r.Disclosure)))
	}
}

func formatDisclosureLine(d *verify.Disclosure) string {
	if d == nil {
		return ""
	}
	parts := make([]string, 0, len(d.Attempts))
	for _, a := range d.Attempts {
		parts = append(parts, "#"+itoa(a.AttemptNo)+"="+a.Verdict)
	}
	line := "attempts " + itoa(d.AttemptNo) + "/" + itoa(d.TotalAttempts)
	if len(parts) > 0 {
		line += " [" + joinParts(parts) + "]"
	}
	if d.Supersedes != "" {
		line += "; supersedes " + d.Supersedes
	}
	return line
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func joinParts(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += ", " + parts[i]
	}
	return out
}
