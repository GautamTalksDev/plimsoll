# Distribution

PLIMSOLL ships through four channels. All release artifacts are built by
[GoReleaser](../.goreleaser.yaml) and cosign-signed on tag push.

## GitHub Releases

```bash
git tag v0.1.0
git push origin v0.1.0
```

The [Release workflow](../.github/workflows/release.yml) publishes binaries for
Linux, macOS, and Windows (amd64/arm64 where applicable), `SHA256SUMS`, and SLSA
provenance.

## Homebrew

GoReleaser pushes a formula to
[`gautamtalksdev/homebrew-plimsoll`](https://github.com/gautamtalksdev/homebrew-plimsoll)
on each release. One-time setup:

1. Create an empty `homebrew-plimsoll` repository on GitHub.
2. Add a `GITHUB_TOKEN` or PAT with `contents: write` on that repo to GoReleaser
   (default `GITHUB_TOKEN` works when the tap repo is under the same owner).

Install:

```bash
brew tap GautamTalksDev/plimsoll
brew install plimsoll
```

## Scoop

GoReleaser pushes a manifest to
[`gautamtalksdev/scoop-plimsoll`](https://github.com/gautamtalksdev/scoop-plimsoll).

```powershell
scoop bucket add plimsoll https://github.com/gautamtalksdev/scoop-plimsoll
scoop install plimsoll
```

## Python (PyPI)

Platform wheels bundle the matching `plimsoll` binary (ruff/uv model). The
[Python Release workflow](../.github/workflows/python-release.yml) builds wheels
on tag `release` and publishes to PyPI with OIDC.

Local wheel build:

```bash
go build -o /tmp/plimsoll ./cmd/plimsoll
PLIMSOLL_BIN=/tmp/plimsoll ./scripts/build-python-wheel.sh
pip install dist/python/plimsoll-*.whl
```

Configure a `pypi` GitHub environment with trusted publishing before the workflow runs.

## GitHub Action

Use `./.github/actions/plimsoll` in your workflow (see
[plimsoll-pr.yml](../.github/workflows/plimsoll-pr.yml) for a full example).
