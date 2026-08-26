# plimsoll Python wrapper

Thin wrapper around the `plimsoll` Go binary. All trust-path logic lives in
Go; this package only spawns the CLI and parses JSON.

## Install

```bash
pip install plimsoll
```

Platform wheels bundle the matching `plimsoll` binary (Linux, macOS, Windows).

Development without a wheel:

```bash
export PLIMSOLL_BINARY=/path/to/plimsoll
pip install -e ".[pytest]"
```

## Usage

```python
import plimsoll

seal = plimsoll.seal("prereg.yaml", publish=True, log_path="log.sqlite")
verdict = plimsoll.attest(seal, "results.json", publish=True, log_path="log.sqlite")
report = plimsoll.verify("claim.attest.json", log_url="https://log.example")
```

## pytest

```python
import plimsoll

@plimsoll.sealed("claim.seal.json")
def test_model_quality():
    ...
```

The test fails unless `claim.attest.json` exists and records verdict `PASS`.
