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

// Package logd implements the CP-10 public transparency log HTTP service.
package logd

import (
	"crypto/ed25519"
	"net/http"
	"time"

	"github.com/GautamTalksDev/plimsoll/internal/log"
	"github.com/GautamTalksDev/plimsoll/internal/site"
)

// Config configures the public log daemon.
type Config struct {
	Log       *log.Log
	PrivKey   ed25519.PrivateKey
	PublicKey ed25519.PublicKey
	Site      *site.Renderer
	RateLimit RateLimitConfig
}

// Server is the CP-10 HTTP service.
type Server struct {
	cfg Config
	mux *http.ServeMux
	rl  *rateLimiter
}

// New builds an HTTP handler tree for the public log API and optional site.
func New(cfg Config) *Server {
	s := &Server{
		cfg: cfg,
		mux: http.NewServeMux(),
		rl:  newRateLimiter(cfg.RateLimit),
	}
	s.routes()
	return s
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.chain(s.mux)
}

func (s *Server) chain(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			w.Header().Set("Cache-Control", "public, max-age=60, s-maxage=300")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) routes() {
	s.mux.HandleFunc("/checkpoint", s.handleCheckpoint)
	s.mux.HandleFunc("/entries", s.handleEntries)
	s.mux.HandleFunc("/proof/inclusion", s.handleInclusionProof)
	s.mux.HandleFunc("/proof/consistency", s.handleConsistencyProof)
	s.mux.HandleFunc("/submit", s.handleSubmit)
	s.mux.HandleFunc("/seal/", s.handleSealPath)
	s.mountLegacyV1()
	if s.cfg.Site != nil {
		s.cfg.Site.Mount(s.mux, s.cfg.Log, s.cfg.PublicKey)
	}
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

// RateLimitConfig limits abusive traffic (per client IP per minute).
type RateLimitConfig struct {
	GetPerMinute  int
	PostPerMinute int
}

func (c RateLimitConfig) withDefaults() RateLimitConfig {
	if c.GetPerMinute <= 0 {
		c.GetPerMinute = 120
	}
	if c.PostPerMinute <= 0 {
		c.PostPerMinute = 20
	}
	return c
}

type rateLimiter struct {
	cfg  RateLimitConfig
	get  map[string]window
	post map[string]window
}

type window struct {
	start time.Time
	count int
}

func newRateLimiter(cfg RateLimitConfig) *rateLimiter {
	cfg = cfg.withDefaults()
	return &rateLimiter{cfg: cfg, get: map[string]window{}, post: map[string]window{}}
}

func (rl *rateLimiter) allow(ip string, post bool) bool {
	now := time.Now()
	limit := rl.cfg.GetPerMinute
	table := rl.get
	if post {
		limit = rl.cfg.PostPerMinute
		table = rl.post
	}
	w := table[ip]
	if now.Sub(w.start) > time.Minute {
		w = window{start: now, count: 0}
	}
	w.count++
	table[ip] = w
	return w.count <= limit
}

func (s *Server) limit(w http.ResponseWriter, r *http.Request, post bool) bool {
	if !s.rl.allow(clientIP(r), post) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		w.Header().Set("Retry-After", "60")
		return false
	}
	return true
}

func clientIP(r *http.Request) string {
	if x := r.Header.Get("X-Forwarded-For"); x != "" {
		for i := 0; i < len(x); i++ {
			if x[i] == ',' {
				return x[:i]
			}
		}
		return x
	}
	host := r.RemoteAddr
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}

func (s *Server) logPubB64() string {
	return encodeB64(s.cfg.PublicKey)
}

func parseIntQuery(r *http.Request, key string, def int64) int64 {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	var n int64
	for _, c := range v {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int64(c-'0')
	}
	return n
}
