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
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/GautamTalksDev/plimsoll/internal/cliout"
	"github.com/GautamTalksDev/plimsoll/internal/evidence"
	"github.com/GautamTalksDev/plimsoll/internal/keys"
	ilog "github.com/GautamTalksDev/plimsoll/internal/log"
)

func newEvidenceCmd(root *rootFlags) *cobra.Command {
	var (
		format    string
		outPath   string
		logURL    string
		logDB     string
		logKey    string
		verifier  string
	)
	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Generate a self-contained evidence pack for a seal",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cliout.New()
			out.JSON = root.json
			return runEvidence(out, evidenceCLI{
				seal:     mustString(cmd, "seal"),
				format:   format,
				out:      outPath,
				logURL:   logURL,
				logDB:    logDB,
				logKey:   logKey,
				verifier: verifier,
			})
		},
	}
	cmd.Flags().String("seal", "", "seal hash (sha256:…) or path to .seal.json")
	cmd.Flags().StringVar(&format, "format", "json", "output format: json or pdf")
	cmd.Flags().StringVar(&outPath, "out", "", "output file path (default stdout for json)")
	cmd.Flags().StringVar(&logURL, "log", os.Getenv("PLIMSOLL_LOG_URL"), "transparency log base URL")
	cmd.Flags().StringVar(&logDB, "log-db", os.Getenv("PLIMSOLL_LOG"), "local SQLite log path (alternative to --log URL)")
	cmd.Flags().StringVar(&logKey, "log-key", "", "Ed25519 log signing key for --log-db (default ~/.config/plimsoll/key)")
	cmd.Flags().StringVar(&verifier, "browser-verifier", os.Getenv("PLIMSOLL_BROWSER_VERIFIER_URL"), "browser verifier URL")
	_ = cmd.MarkFlagRequired("seal")
	return cmd
}

type evidenceCLI struct {
	seal, format, out, logURL, logDB, logKey, verifier string
}

func runEvidence(out *cliout.Printer, cfg evidenceCLI) error {
	format := strings.ToLower(strings.TrimSpace(cfg.format))
	if format != "json" && format != "pdf" {
		return opErrf("evidence: format must be json or pdf")
	}
	opt := evidence.Options{
		SealRef:            cfg.seal,
		LogURL:             cfg.logURL,
		BrowserVerifierURL: cfg.verifier,
	}
	if cfg.logDB != "" {
		if cfg.logKey == "" {
			home, _ := os.UserHomeDir()
			cfg.logKey = filepath.Join(home, ".config/plimsoll/key")
		}
		_, pub, err := keys.LoadOrCreate(cfg.logKey)
		if err != nil {
			return opErrf("evidence: log key: %v", err)
		}
		l, err := ilog.Open(cfg.logDB)
		if err != nil {
			return opErrf("evidence: open log: %v", err)
		}
		defer func() { _ = l.Close() }()
		opt.LocalLog = l
		opt.LogPub = pub
	}
	pack, err := evidence.Build(opt)
	if err != nil {
		return opErrf("evidence: %v", err)
	}
	var data []byte
	switch format {
	case "json":
		data, err = evidence.ToJSON(pack)
	case "pdf":
		data, err = evidence.ToPDF(pack)
	}
	if err != nil {
		return opErrf("evidence: %v", err)
	}
	path := cfg.out
	if path == "" {
		if format == "pdf" {
			path = defaultEvidenceName(pack.SealHash, ".pdf")
		} else if out.JSON {
			path = ""
		} else {
			path = defaultEvidenceName(pack.SealHash, ".json")
		}
	}
	if path == "" {
		if out.JSON {
			return out.EmitJSON(pack)
		}
		_, err = out.Out.Write(data)
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return opErrf("evidence: write %s: %v", path, err)
	}
	if out.JSON {
		return out.EmitJSON(map[string]string{"path": path, "format": format})
	}
	out.Printf("Wrote evidence pack to %s\n", path)
	return nil
}

func defaultEvidenceName(sealHash, ext string) string {
	short := strings.TrimPrefix(sealHash, "sha256:")
	if len(short) > 16 {
		short = short[:16]
	}
	return fmt.Sprintf("evidence-%s%s", short, ext)
}

func mustString(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}
