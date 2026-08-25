# PLIMSOLL

**PLIMSOLL never sees your eval data. We store cryptographic digests, metadata and verdicts. Datasets, models, prompts and outputs never leave your machine.**

**There is no override. A sealed decision rule cannot be amended by any flag, setting or paid tier.**

**PLIMSOLL does not run evaluations. It verifies evaluations you ran with your own tools.**

## Kill Tests

KT-1: If, 8 weeks after public launch, fewer than 25 distinct organizations have published a seal to the public log, nobody is being asked to prove their eval numbers. Publish and stop.

KT-2: If, across at least 100 sealed evaluations, fewer than 10% show either more than one attested attempt against the same seal or a superseding seal issued after a failed attempt, then post-hoc flexibility is not occurring in practice and this log adds nothing over a git commit. Publish and stop.

KT-3: If nobody has contacted us unprompted requesting a private log or evidence export within 3 months of launch, there is no business here. Keep the public log running and move on.

## What this is

PLIMSOLL is an integrity/verification tool. You seal a decision rule before you look at results. Later attempts against that seal are logged. Anyone can verify the attestation offline. The public log stores digests, metadata and verdicts only.

This repository is Week 1 foundations: layout, license, guardrails and prior art. There is no application logic yet.

See [docs/NON-GOALS.md](docs/NON-GOALS.md), [docs/PRIOR-ART.md](docs/PRIOR-ART.md) and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Repository layout

```
cmd/plimsoll/        CLI entrypoint (cobra)
internal/canonical/  canonicalization + hashing (pure, no I/O)
internal/seal/       preregistration schema, seal creation, signing
internal/adapt/      result adapters (pure, no I/O)
internal/decide/     deterministic decision engine
internal/log/        merkle append-only log
internal/verify/     verification (offline-capable)
testdata/
docs/
```

## Build

Requires Go 1.23.

```
go build ./...
go vet ./...
```

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Contributions require a Developer Certificate of Origin sign-off. See [CONTRIBUTING.md](CONTRIBUTING.md).
