#!/usr/bin/env bash
set -euo pipefail

DEST="${RUNNER_TEMP}/plimsoll-bin"
mkdir -p "${DEST}"

if [[ -n "${INPUT_PLIMSOLL_PATH:-}" ]]; then
  cp "${INPUT_PLIMSOLL_PATH}" "${DEST}/plimsoll"
  chmod +x "${DEST}/plimsoll"
  echo "${DEST}" >> "${GITHUB_PATH}"
  exit 0
fi

if [[ -n "${INPUT_PLIMSOLL_VERSION:-}" ]]; then
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  ARCH="$(uname -m)"
  case "${ARCH}" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "unsupported arch: ${ARCH}" >&2; exit 1 ;;
  esac
  case "${OS}" in
    linux) ;;
    darwin) OS="darwin" ;;
    mingw*|msys*|cygwin*|windows*) OS="windows"; ARCH="amd64" ;;
    *) echo "unsupported os: ${OS}" >&2; exit 1 ;;
  esac
  TAG="${INPUT_PLIMSOLL_VERSION}"
  [[ "${TAG}" == v* ]] || TAG="v${TAG}"
  REPO="${GITHUB_REPOSITORY:-GautamTalksDev/plimsoll}"
  NAME="plimsoll_${TAG}_${OS}_${ARCH}"
  if [[ "${OS}" == "windows" ]]; then
    URL="https://github.com/${REPO}/releases/download/${TAG}/${NAME}.exe"
    curl -fsSL "${URL}" -o "${DEST}/plimsoll.exe"
    echo "${DEST}" >> "${GITHUB_PATH}"
    exit 0
  fi
  URL="https://github.com/${REPO}/releases/download/${TAG}/${NAME}"
  curl -fsSL "${URL}" -o "${DEST}/plimsoll"
  chmod +x "${DEST}/plimsoll"
  echo "${DEST}" >> "${GITHUB_PATH}"
  exit 0
fi

# Default: build from source in the checkout workspace.
ROOT="${GITHUB_WORKSPACE:-.}"
cd "${ROOT}"
go build -trimpath -ldflags="-s -w" -o "${DEST}/plimsoll" ./cmd/plimsoll
chmod +x "${DEST}/plimsoll"
echo "${DEST}" >> "${GITHUB_PATH}"
