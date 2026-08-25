# Contributing

## Developer Certificate of Origin

Every commit must be signed off with the Developer Certificate of Origin
(DCO), version 1.1: <https://developercertificate.org/>.

```
git commit -s
```

The `-s` flag adds a `Signed-off-by: Name <email>` trailer. That trailer
certifies that you have the right to submit the work under the Apache License
2.0 and that you agree to the DCO.

Pull requests whose commits lack a DCO sign-off will not be merged.

## Guardrails

Read [docs/NON-GOALS.md](docs/NON-GOALS.md) before writing code. In particular:

- Do not add an LLM call, heuristic score, probabilistic classifier, or
  network request the user did not explicitly request, anywhere in the trust
  path.
- Do not implement an evaluation metric, scorer, or assessment framework.
- Do not receive, store, or transmit datasets, models, prompts, or outputs.
- Do not add a flag, env var, or code path that overrides a sealed decision
  rule.
- Do not make our log the only endpoint that can verify an attestation.
- Do not add a dependency that is not already in `go.mod` without asking
  first. Prefer the standard library.

All logic in the trust path must be deterministic and unit-testable.

## Development

Requires Go 1.23.

```
go build ./...
go vet ./...
go test ./...
```

Lint (gosec, errcheck, govet, staticcheck):

```
golangci-lint run
```

Use LF line endings (see `.editorconfig`).
