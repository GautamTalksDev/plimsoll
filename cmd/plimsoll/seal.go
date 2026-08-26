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
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/GautamTalksDev/plimsoll/internal/cliout"
	"github.com/GautamTalksDev/plimsoll/internal/datasetload"
	"github.com/GautamTalksDev/plimsoll/internal/keys"
	"github.com/GautamTalksDev/plimsoll/internal/logclient"
	"github.com/GautamTalksDev/plimsoll/internal/seal"
	"github.com/GautamTalksDev/plimsoll/internal/sealfile"
)

func newSealCmd(root *rootFlags) *cobra.Command {
	var (
		file    string
		publish bool
		wait    bool
		timeout string
		keyPath string
		logPath string
		logURL  string
	)
	cmd := &cobra.Command{
		Use:   "seal",
		Short: "Parse, hash dataset locally, sign, and optionally publish a pre-registration",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cliout.New()
			out.JSON = root.json
			err := runSeal(out, file, publish, wait, timeout, keyPath, logPath, logURL)
			if err != nil {
				if errors.Is(err, errAwaitTimeout) {
					return &exitCode{code: exitTimeout}
				}
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "pre-registration YAML/JSON path")
	cmd.Flags().BoolVar(&publish, "publish", false, "submit seal to the log")
	cmd.Flags().BoolVar(&wait, "wait", false, "with --publish, block until the log includes the seal (~60s on the public log)")
	cmd.Flags().StringVar(&timeout, "timeout", "5m", "with --wait, how long to poll (Go duration)")
	cmd.Flags().StringVar(&keyPath, "key", "", "Ed25519 private key path (default ~/.config/plimsoll/key)")
	cmd.Flags().StringVar(&logPath, "log", os.Getenv("PLIMSOLL_LOG"), "SQLite log path for --publish")
	cmd.Flags().StringVar(&logURL, "log-url", os.Getenv("PLIMSOLL_LOG_URL"), "HTTP log base URL for --publish")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func runSeal(out *cliout.Printer, file string, publish, wait bool, timeoutStr, keyPath, logPath, logURL string) error {
	raw, err := os.ReadFile(file)
	if err != nil {
		return opErrf("read prereg: %v", err)
	}
	s, err := seal.Parse(raw)
	if err != nil {
		return opErrf("parse prereg: %v", err)
	}
	updated, err := ensureDataset(s, file, raw)
	if err != nil {
		return opErrf("dataset: %v", err)
	}
	if updated && !out.JSON {
		out.Printf("Updated dataset sha256 and n in %s\n", file)
	}
	if err := s.Validate(); err != nil {
		return opErrf("validate: %v", err)
	}
	if keyPath == "" {
		keyPath, err = keys.DefaultPath()
		if err != nil {
			return opErrf("key path: %v", err)
		}
	}
	priv, pub, err := keys.LoadOrCreate(keyPath)
	if err != nil {
		return opErrf("key: %v", err)
	}
	signed, err := s.ForSign().Sign(priv)
	if err != nil {
		return opErrf("sign: %v", err)
	}
	sealHash, err := signed.Seal.CanonicalHash()
	if err != nil {
		return opErrf("hash: %v", err)
	}
	doc := &sealfile.Document{
		SealHash:  sealHash,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Seal:      signed,
	}
	published := false
	pending := false
	if publish {
		if wait && logURL == "" && logPath != "" {
			// Local SQLite is synchronous; --wait is a no-op.
			wait = false
		}
		lc, err := openLogClient(logPath, logURL, priv)
		if err != nil {
			return opErrf("log: %v", err)
		}
		defer func() { _ = lc.Close() }()
		res, err := lc.PublishSeal(signed, sealHash, pub)
		if err != nil {
			return opErrf("publish: %v", err)
		}
		if res.Pending {
			pending = true
			if wait {
				d, err := time.ParseDuration(timeoutStr)
				if err != nil {
					return opErrf("timeout: %v", err)
				}
				if logURL == "" {
					return opErrf("--wait requires --log-url for the public HTTP log")
				}
				w, err := awaitSealHTTP(logURL, sealHash, d)
				if err != nil {
					if isTimeout(err) {
						return errAwaitTimeout
					}
					return opErrf("wait: %v", err)
				}
				proof := w.InclusionProof.InclusionProof
				cp := w.InclusionProof.Checkpoint
				doc.InclusionProof = &proof
				doc.Checkpoint = &cp
				idx := w.Seal.Idx
				doc.LogIndex = &idx
				published = true
				pending = false
			}
		} else {
			doc.InclusionProof = &res.InclusionProof
			doc.Checkpoint = &res.Checkpoint
			idx := res.Index
			doc.LogIndex = &idx
			published = true
		}
	} else {
		out.PrintLocalOnlyWarning()
	}
	wd, _ := os.Getwd()
	path, err := sealfile.Write(wd, doc)
	if err != nil {
		return opErrf("write seal: %v", err)
	}
	verifyLog := logURL
	if verifyLog == "" {
		verifyLog = "<url>"
	}
	if out.JSON {
		return out.EmitJSON(map[string]any{
			"seal_hash":       sealHash,
			"path":            path,
			"submitted":       publish,
			"pending":         pending,
			"published":       published,
			"dataset_updated": updated,
			"log_index":       doc.LogIndex,
		})
	}
	out.Success(fmt.Sprintf("Wrote %s", path))
	out.Printf("Seal hash: %s\n", sealHash)
	if pending {
		out.PrintSubmittedPending(path, verifyLog)
	} else if published && doc.LogIndex != nil {
		out.Printf("Log index: %d\n", *doc.LogIndex)
	}
	return nil
}

func ensureDataset(s *seal.Seal, file string, raw []byte) (updated bool, err error) {
	path := strings.TrimSpace(s.Dataset.Path)
	if path == "" {
		if s.Dataset.SHA256 == "" {
			return false, fmt.Errorf("dataset.path or dataset.sha256 required")
		}
		return false, nil
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(filepath.Dir(file), path)
	}
	hash, n, err := datasetload.HashFile(path)
	if err != nil {
		return false, err
	}
	if s.Dataset.SHA256 == "" {
		s.Dataset.SHA256 = hash
		s.Dataset.N = n
		return rewritePreregDataset(file, raw, hash, n)
	}
	if s.Dataset.SHA256 != hash {
		return false, fmt.Errorf("dataset sha256 mismatch: declared %s computed %s", s.Dataset.SHA256, hash)
	}
	if s.Dataset.N != n {
		return false, fmt.Errorf("dataset n mismatch: declared %d computed %d", s.Dataset.N, n)
	}
	return false, nil
}

func rewritePreregDataset(file string, raw []byte, hash string, n int) (bool, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return false, err
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return false, fmt.Errorf("yaml: expected document")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return false, fmt.Errorf("yaml: expected mapping")
	}
	setMapValue(root, "dataset", "sha256", hash)
	setMapValue(root, "dataset", "n", n)
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return false, err
	}
	if err := os.WriteFile(file, out, 0o644); err != nil { //nolint:gosec // G306 -- user prereg file, not a secret
		return false, err
	}
	return true, nil
}

func setMapValue(root *yaml.Node, section, key string, value any) {
	sec := findMapKey(root, section)
	if sec == nil || sec.Kind != yaml.MappingNode {
		return
	}
	setKeyTyped(sec, key, value)
}

func setKeyTyped(m *yaml.Node, key string, value any) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			setScalar(m.Content[i+1], value)
			return
		}
	}
	k := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
	v := &yaml.Node{Kind: yaml.ScalarNode}
	setScalar(v, value)
	m.Content = append(m.Content, k, v)
}

func setScalar(n *yaml.Node, value any) {
	switch v := value.(type) {
	case int:
		n.Kind = yaml.ScalarNode
		n.Value = fmt.Sprint(v)
		n.Tag = "!!int"
	case string:
		n.Kind = yaml.ScalarNode
		n.Value = v
		n.Tag = "!!str"
	default:
		n.SetString(fmt.Sprint(value))
	}
}

func findMapKey(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func openLogClient(logPath, logURL string, priv ed25519.PrivateKey) (*logclient.Client, error) {
	if logURL != "" {
		return logclient.NewHTTP(logURL, priv, nil), nil
	}
	if logPath == "" {
		return nil, fmt.Errorf("--log or --log-url required with --publish")
	}
	return logclient.OpenSQLite(logPath, priv)
}
