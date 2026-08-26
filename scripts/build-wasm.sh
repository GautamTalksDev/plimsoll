#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/internal/site/verify"
GOOS=js GOARCH=wasm go build -o "$OUT/plimsoll_verify.wasm" "$ROOT/cmd/verifywasm"
cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" "$OUT/wasm_exec.js"
