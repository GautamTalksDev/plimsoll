#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/internal/site/verify"
GOOS=js GOARCH=wasm go build -o "$OUT/plimsoll_verify.wasm" "$ROOT/cmd/verifywasm"
# wasm_exec.js moved from misc/wasm to lib/wasm in Go 1.24. Try both so the
# script works across toolchains rather than pinning to one layout.
GOROOT="$(go env GOROOT)"
WASM_EXEC=""
for candidate in "$GOROOT/lib/wasm/wasm_exec.js" "$GOROOT/misc/wasm/wasm_exec.js"; do
  if [ -f "$candidate" ]; then
    WASM_EXEC="$candidate"
    break
  fi
done
if [ -z "$WASM_EXEC" ]; then
  echo "wasm_exec.js not found under $GOROOT (looked in lib/wasm and misc/wasm)" >&2
  exit 1
fi
cp "$WASM_EXEC" "$OUT/wasm_exec.js"
