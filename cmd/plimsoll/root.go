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
	"fmt"

	"github.com/spf13/cobra"
)

const exitOperational = 3

type rootFlags struct {
	json bool
}

func newRoot() *cobra.Command {
	flags := &rootFlags{}
	root := &cobra.Command{
		Use:   "plimsoll",
		Short: "Verify evaluations you ran with your own tools",
		Long: `Verify evaluations you ran with your own tools.

PLIMSOLL never sees your eval data. Datasets, models, prompts and outputs
never leave your machine; only digests, metadata and verdicts are published.

Without --publish, no command makes any network request. There is no
telemetry, no version check and no analytics.

A sealed decision rule cannot be amended by any flag, setting or tier.`,
	}
	root.PersistentFlags().BoolVar(&flags.json, "json", false, "machine-readable JSON output")
	root.AddCommand(newHashCmd(flags))
	root.AddCommand(newSealCmd(flags))
	root.AddCommand(newAttestCmd(flags))
	root.AddCommand(newAwaitCmd(flags))
	root.AddCommand(newSupersedeCmd(flags))
	root.AddCommand(newVerifyCmd(flags))
	root.AddCommand(newVerifyLogCmd(flags))
	root.AddCommand(newEvidenceCmd(flags))
	return root
}

func isOperational(err error) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(*opError); ok {
		return e.op
	}
	return false
}

type opError struct {
	op  bool
	msg string
}

func (e *opError) Error() string { return e.msg }

func opErrf(format string, args ...any) error {
	return &opError{op: true, msg: fmt.Sprintf(format, args...)}
}
