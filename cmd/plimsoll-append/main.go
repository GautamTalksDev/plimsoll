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

// Command plimsoll-append validates a submit payload and appends it to a
// SQLite log. Used by the plimsoll-log Actions workflow as the trust gate.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	ilog "github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/logappend"
)

func main() {
	dbPath := flag.String("db", "log.sqlite", "SQLite log path")
	keyPath := flag.String("key", "", "Ed25519 log signing private key (64 raw bytes)")
	pubPath := flag.String("public", "", "optional PEM/public key that must match -key")
	payloadPath := flag.String("payload", "", "path to submit JSON body")
	outPath := flag.String("out", "", "optional path to write KIND= HASH= IDX= lines for the workflow")
	flag.Parse()

	if *keyPath == "" || *payloadPath == "" {
		fmt.Fprintln(os.Stderr, "plimsoll-append: -key and -payload are required")
		os.Exit(2)
	}
	priv, err := loadPriv(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plimsoll-append: key: %v\n", err)
		os.Exit(1)
	}
	if *pubPath != "" {
		want, err := loadPub(*pubPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "plimsoll-append: public: %v\n", err)
			os.Exit(1)
		}
		got := priv.Public().(ed25519.PublicKey)
		if !bytesEqual(got, want) {
			fmt.Fprintln(os.Stderr, "plimsoll-append: LOG_SIGNING_KEY does not match committed public key")
			os.Exit(1)
		}
	}
	body, err := os.ReadFile(*payloadPath) //nolint:gosec // G304 -- operator/workflow path
	if err != nil {
		fmt.Fprintf(os.Stderr, "plimsoll-append: payload: %v\n", err)
		os.Exit(1)
	}
	l, err := ilog.Open(*dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plimsoll-append: open log: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = l.Close() }()

	res, err := logappend.Append(l, priv, body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plimsoll-append: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(res.CommitMessage())
	if *outPath != "" {
		content := fmt.Sprintf("KIND=%s\nHASH=%s\nIDX=%d\n", res.Kind, res.Hash, res.Idx)
		if err := os.WriteFile(*outPath, []byte(content), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "plimsoll-append: write out: %v\n", err)
			os.Exit(1)
		}
	}
}

func loadPriv(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304 -- operator/workflow path
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("want %d raw private key bytes, got %d", ed25519.PrivateKeySize, len(b))
	}
	return ed25519.PrivateKey(b), nil
}

func loadPub(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304 -- operator/workflow path
	if err != nil {
		return nil, err
	}
	if len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(append([]byte(nil), b...)), nil
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("expected PEM public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not Ed25519")
	}
	return ed, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
