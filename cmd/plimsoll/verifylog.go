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
	"github.com/spf13/cobra"

	"github.com/GautamTalksDev/plimsoll/internal/cliout"
	"github.com/GautamTalksDev/plimsoll/internal/verifylog"
)

func newVerifyLogCmd(root *rootFlags) *cobra.Command {
	var (
		dir     string
		keyPath string
		dbPath  string
	)
	cmd := &cobra.Command{
		Use:   "verify-log",
		Short: "Replay a cloned plimsoll-log and verify every checkpoint",
		Long: `Replay log.sqlite from a plimsoll-log clone: recompute every Merkle leaf
from canonical bytes, rebuild each checkpoint root, and verify Ed25519
signatures against the published public key (keys/log-public.pem).

A rewritten or hand-edited log fails. See docs/MIRRORING.md.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cliout.New()
			out.JSON = root.json
			res, err := verifylog.VerifyDir(dir, verifylog.Options{
				KeyPath: keyPath,
				DBPath:  dbPath,
			})
			if err != nil {
				return err
			}
			if out.JSON {
				return out.EmitJSON(res)
			}
			out.Printf("ok: %d leaves, %d checkpoints (signatures valid)\n", res.Leaves, res.Checkpoints)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "path to a plimsoll-log clone (required)")
	cmd.Flags().StringVar(&keyPath, "key", "", "override keys/log-public.pem")
	cmd.Flags().StringVar(&dbPath, "db", "", "override log.sqlite under --dir")
	_ = cmd.MarkFlagRequired("dir")
	return cmd
}
