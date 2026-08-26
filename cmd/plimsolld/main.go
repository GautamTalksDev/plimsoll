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
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/GautamTalksDev/plimsoll/internal/keys"
	ilog "github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/logd"
	"github.com/GautamTalksDev/plimsoll/internal/site"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	db := flag.String("db", "plimsoll-log.sqlite", "SQLite log path")
	keyPath := flag.String("key", "", "Ed25519 log signing key (created if missing)")
	specPath := flag.String("spec", "SPEC-PREREG.md", "path to SPEC-PREREG.md")
	baseURL := flag.String("base-url", "http://127.0.0.1:8080", "public base URL for badges/links")
	flag.Parse()

	if *keyPath == "" {
		home, _ := os.UserHomeDir()
		*keyPath = filepath.Join(home, ".config/plimsoll/log-signing.key")
	}
	priv, pub, err := keys.LoadOrCreate(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	l, err := ilog.Open(*db)
	if err != nil {
		log.Fatal(err)
	}

	siteRenderer, err := site.New(l, pub, *specPath, *baseURL)
	if err != nil {
		_ = l.Close()
		log.Fatal(err)
	}
	logSrv := logd.New(logd.Config{
		Log: l, PrivKey: priv, PublicKey: pub,
		Site: siteRenderer,
	})
	defer func() { _ = logSrv.Close() }()

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           logSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("plimsolld listening on %s", *addr)
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}
}
