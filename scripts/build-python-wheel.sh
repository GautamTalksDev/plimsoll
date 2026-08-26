#!/usr/bin/env bash
# Build a platform-specific Python wheel embedding the plimsoll binary.
# Usage: PLIMSOLL_BIN=/path/to/plimsoll ./scripts/build-python-wheel.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${ROOT}/python"
BIN_DIR="${PY}/plimsoll/bin"
mkdir -p "${BIN_DIR}"

if [[ -n "${PLIMSOLL_BIN:-}" ]]; then
  SRC="${PLIMSOLL_BIN}"
else
  echo "Building plimsoll binary..." >&2
  TMP="$(mktemp -d)"
  (cd "${ROOT}" && go build -trimpath -ldflags="-s -w" -o "${TMP}/plimsoll" ./cmd/plimsoll)
  SRC="${TMP}/plimsoll"
fi

NAME="plimsoll"
if [[ "$(uname -s)" == MINGW* ]] || [[ "$(uname -s)" == MSYS* ]] || [[ -f "${SRC}.exe" ]]; then
  NAME="plimsoll.exe"
fi
cp "${SRC}" "${BIN_DIR}/${NAME}"
chmod +x "${BIN_DIR}/${NAME}"

cd "${PY}"
python3 -m pip wheel . -w "${ROOT}/dist/python" --no-deps
echo "Wheel written to ${ROOT}/dist/python/"
