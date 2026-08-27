# PLIMSOLL quickstart

Get from zero to a **published seal** in under five minutes. These paths
assume you installed the CLI (`brew install plimsoll`, `scoop install plimsoll`,
`pip install plimsoll`, or `go install github.com/GautamTalksDev/plimsoll/cmd/plimsoll@latest`).

Every path follows the same three steps:

1. **Seal** — hash your dataset locally, sign the pre-registration, publish to the log.
2. **Evaluate** — run your harness as you normally would; save results to a file.
3. **Attest** — adapt results, evaluate the sealed rule, sign, publish.

**Publish latency (public log):** `--publish` to `https://plimsoll.gautamkhosla.com`
(current entries: operator's own fixtures; RESULTS.md §2a)
is asynchronous. The Worker accepts the submit immediately; the git-backed log
appends within about a minute. Until then, `/seal/{hash}` is empty. Use
`--wait` (or `plimsoll await`) when you need the inclusion proof before the
next step. A local SQLite log (`--log ./plimsoll-log.sqlite`) stays synchronous.

Generate a key once (stored at `~/.config/plimsoll/key`):

```bash
plimsoll seal --file /dev/null 2>/dev/null || true   # creates key on first use
# or explicitly:
test -f ~/.config/plimsoll/key || plimsoll seal --help >/dev/null
```

Use a local SQLite log for development (`--log ./plimsoll-log.sqlite`).
For the public log, set `--log-url https://plimsoll.gautamkhosla.com` and prefer `--wait` in scripts.
Current public-log entries are the operator's own fixtures (RESULTS.md §2a), not third-party evaluations.

---

## Generic format

Best for custom scripts or exporters you control. See [GENERIC-FORMAT.md](GENERIC-FORMAT.md).

**1. Pre-registration** (`prereg.yaml`):

```yaml
plimsoll_version: prereg-v1
created_at: "2026-08-25T12:00:00Z"
canon_version: plimsoll-canon-v1
subject:
  name: my-claim
  system_under_test:
    model: gpt-4o-mini
    prompt_sha256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    config_sha256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
dataset:
  path: dataset.jsonl
  sampling: exhaustive
  held_out: false
harness:
  tool: generic
  version: "1.0.0"
  config_sha256: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
metrics:
  - id: acc
    name: accuracy
    definition_uri: https://example.invalid/metrics/accuracy
    direction: higher_is_better
decision_rule:
  expression: "acc.mean >= 0.75"
  primary_metric: acc
  threshold: "0.75"
  comparison: ">="
  precision: 2
planned_attempts: 3
analysis_plan: Quickstart generic example.
```

**2. Dataset** (`dataset.jsonl`) — one JSON object per line with an `id` field.

**3. Results** (`results.json`):

```json
{
  "format": "plimsoll-generic-v1",
  "harness_version": "1.0.0",
  "rows": [
    {"id": "r1", "metrics": {"acc": "0.90"}},
    {"id": "r2", "metrics": {"acc": "0.80"}},
    {"id": "r3", "metrics": {"acc": "0.70"}}
  ]
}
```

**4. Seal and attest:**

```bash
# Local SQLite (synchronous — fine for development):
plimsoll seal --file prereg.yaml --publish --log ./plimsoll-log.sqlite
plimsoll attest --seal my-claim.seal.json --results results.json --publish --log ./plimsoll-log.sqlite

# Public log (asynchronous — about a minute to appear; --wait blocks for CI).
# Operator fixtures only on this log today (RESULTS.md §2a) — not third-party evals.
plimsoll seal --file prereg.yaml --publish --log-url https://plimsoll.gautamkhosla.com --wait
plimsoll attest --seal my-claim.seal.json --results results.json \
  --publish --log-url https://plimsoll.gautamkhosla.com --wait  # fixtures: RESULTS.md §2a
```

Third parties verify with `plimsoll verify my-claim.attest.json --log https://plimsoll.gautamkhosla.com`.
Without `--wait`, confirm inclusion with `plimsoll await --seal sha256:… --log https://plimsoll.gautamkhosla.com`.
The log may already contain the operator's own fixtures; those are not third-party evaluations (RESULTS.md §2a).

---

## DeepEval

**1. Pre-registration** — set `harness.tool: deepeval`, `harness.version: "1.2.0"`,
and metrics whose `id` values match the DeepEval metric names you map (e.g.
`answer_relevancy` after adaptation). Check your export for exact names.

**2. Run DeepEval** and save the JSON export (must include `deepevalVersion` and
`testCases`).

**3. Seal and attest** (harness auto-detected):

```bash
plimsoll seal --file prereg-deepeval.yaml --publish --log ./plimsoll-log.sqlite
plimsoll attest --seal my-claim.seal.json --results deepeval-output.json --publish --log ./plimsoll-log.sqlite
```

Minimal valid export shape:

```json
{
  "deepevalVersion": "1.2.0",
  "testCases": [
    {
      "order": 0,
      "name": "case-1",
      "metricsData": [
        {"name": "Answer Relevancy", "score": 0.95, "success": true}
      ]
    }
  ]
}
```

---

## Inspect AI

**1. Pre-registration** — set `harness.tool: inspect`, `harness.version: "0.3.x"`
(to match your eval file's `eval` block).

**2. Run an Inspect eval** (`inspect eval …`) and point to the `.eval` JSON output.

**3. Seal and attest:**

```bash
plimsoll seal --file prereg-inspect.yaml --publish --log ./plimsoll-log.sqlite
plimsoll attest --seal my-claim.seal.json --results inspect-log.eval --publish --log ./plimsoll-log.sqlite
```

Inspect exports include `"version": 2`, `"status"`, and `"samples"` with
`scores` objects — the adapter detects this automatically.

---

## Promptfoo

**1. Pre-registration** — set `harness.tool: promptfoo`, `harness.version: "0.103.0"`
(or your `promptfoo -v`).

**2. Run Promptfoo** (`promptfoo eval`) and use the JSON results file (top-level
`version` + `results`).

**3. Seal and attest:**

```bash
plimsoll seal --file prereg-promptfoo.yaml --publish --log ./plimsoll-log.sqlite
plimsoll attest --seal my-claim.seal.json --results promptfoo-output.json --publish --log ./plimsoll-log.sqlite
```

---

## Python wrapper

Same flow, no trust-path logic in Python:

```python
import plimsoll

seal = plimsoll.seal("prereg.yaml", publish=True, log_path="plimsoll-log.sqlite")
verdict = plimsoll.attest(seal, "results.json", publish=True, log_path="plimsoll-log.sqlite")
print(verdict.result, verdict.attempt_no)
report = plimsoll.verify("my-claim.attest.json", log_url="http://127.0.0.1:8080")
```

## GitHub Action

```yaml
- uses: GautamTalksDev/plimsoll/.github/actions/plimsoll@v0.1.0
  with:
    seal-file: my-claim.seal.json
    results-file: results.json
    publish: true
    log-path: plimsoll-log.sqlite
```

On pull requests the action posts a **PLIMSOLL Evaluation** check and updates a
PR comment with the verdict, terms table, and attempt number. Attempt 4+ shows a
multi-attempt disclosure banner so it is visually distinct from attempt 1.

---

## What you should see

| Step | Success signal |
|------|----------------|
| `seal --publish` | `Wrote …seal.json`, no `LOCAL ONLY` warning |
| `attest` | `Verdict: PASS` or `FAIL`; `Attempt N of this seal` when publishing |
| `verify` | `VERIFIED` or `VERIFIED WITH DISCLOSURES` |

Exit codes: `0` = PASS, `1` = FAIL, `2` = INVALID (pre-registration mismatch).

---

## Next steps

- [GENERIC-FORMAT.md](GENERIC-FORMAT.md) — roll your own exporter
- [packaging/README.md](../packaging/README.md) — Homebrew, Scoop, PyPI releases
- Offline verification: build a bundle and run `plimsoll verify --offline --bundle …`
