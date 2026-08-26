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
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/GautamTalksDev/plimsoll/internal/cliout"
	"github.com/GautamTalksDev/plimsoll/internal/seal"
	"github.com/GautamTalksDev/plimsoll/internal/sealfile"
)

func newSupersedeCmd(root *rootFlags) *cobra.Command {
	var (
		sealPath string
		reason   string
		outFile  string
	)
	cmd := &cobra.Command{
		Use:   "supersede",
		Short: "Author a new seal that references a previous one",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cliout.New()
			out.JSON = root.json
			if err := runSupersede(out, sealPath, reason, outFile); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sealPath, "seal", "", "existing signed seal file")
	cmd.Flags().StringVar(&reason, "reason", "", "public reason for superseding (required)")
	cmd.Flags().StringVar(&outFile, "out", "prereg-supersede.yaml", "output prereg YAML path")
	_ = cmd.MarkFlagRequired("seal")
	_ = cmd.MarkFlagRequired("reason")
	return cmd
}

func runSupersede(out *cliout.Printer, sealPath, reason, outFile string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return opErrf("reason is required and will be published")
	}
	doc, err := sealfile.Read(sealPath)
	if err != nil {
		return opErrf("read seal: %v", err)
	}
	pub, err := doc.PublicKeyBytes()
	if err != nil {
		return opErrf("public key: %v", err)
	}
	if err := doc.Verify(pub); err != nil {
		return opErrf("verify seal: %v", err)
	}
	s := doc.Seal.Seal
	s.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	s.Supersedes = &seal.Supersedes{
		SealHash: doc.SealHash,
		Reason:   reason,
	}
	raw, err := yaml.Marshal(s)
	if err != nil {
		return opErrf("marshal: %v", err)
	}
	if err := os.WriteFile(outFile, raw, 0o644); err != nil { //nolint:gosec // G306 -- public prereg draft, not a secret
		return opErrf("write: %v", err)
	}
	if out.JSON {
		return out.EmitJSON(map[string]any{
			"out":             outFile,
			"supersedes_hash": doc.SealHash,
			"reason":          reason,
		})
	}
	out.Success(fmt.Sprintf("Wrote %s", outFile))
	out.Printf("Supersedes: %s\n", doc.SealHash)
	out.Printf("Reason (will be published): %s\n", cliout.Sanitize(reason))
	return nil
}
