# PLIMSOLL

**Commit your evaluation's threshold before you run it. Prove afterwards that you did.**

[![CI](https://github.com/GautamTalksDev/plimsoll/actions/workflows/ci.yml/badge.svg)](https://github.com/GautamTalksDev/plimsoll/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/GautamTalksDev/plimsoll/badge)](https://scorecard.dev/viewer/?uri=github.com/GautamTalksDev/plimsoll)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Spec](https://img.shields.io/badge/spec-CC0--1.0-lightgrey)](SPEC-PREREG.md)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22107450.svg)](https://doi.org/10.5281/zenodo.22107450)

> **PLIMSOLL never sees your eval data.** We store cryptographic digests, metadata, and verdicts. Datasets, models, prompts, and outputs never leave your machine.
>
> **There is no override.** A sealed decision rule cannot be amended by any flag, setting, or paid tier.
>
> **PLIMSOLL does not run evaluations.** It verifies evaluations you ran with your own tools.

---

## The problem, in thirty seconds

Someone tells you their model scores 0.87 on their internal eval, up from 0.81.

You have no way to check any of it. Not because they are lying, but because nothing about that claim is checkable. Did they pick 0.85 as the bar before running, or after seeing 0.87? Is the dataset the same one they used last quarter? And the question almost nobody asks out loud:

**How many times did they run it?**

That last one is the real problem. Moving a threshold after the fact is the amateur version, and everybody already watches for it. The version that actually happens is quieter. Run the eval nine times with slightly different seeds, temperatures, or retrieval settings. Publish the run that cleared the bar. Delete the other eight.

Nothing was falsified. Every number is real. The claim is still worthless.

Git commits do not catch this. Signed results do not catch this. A vendor's own eval platform structurally cannot catch this, because it belongs to the vendor.

## What PLIMSOLL does about it

A plumb line is a weighted string that defines true vertical. The Plimsoll line is the mark on a ship's hull, set in advance by an independent authority, that shows how deep it may be loaded. Anyone standing on the dock can look at the waterline and see whether the ship is overloaded. The mark is public, it was placed before the cargo went on, and it cannot be quietly moved.

That is the whole idea.

1. **Before** you run: write down your metric, threshold, dataset hash, and decision rule. PLIMSOLL canonicalizes it, hashes it, signs it, and appends it to a public append-only log. You get back a cryptographic proof of when that happened.
2. **Run your eval** with whatever tool you already use. PLIMSOLL does not touch it.
3. **After** you run: bind your results to the seal. PLIMSOLL applies *only the rule you sealed*, and appends the outcome.
4. **Anyone** can verify. Not just you, not just your customer, not just an auditor. Anyone, offline, in a browser, with no account.

And critically: every attempt against a seal is a public event. The log assigns the attempt number, not the client. So the answer to "how many times did you run it" is no longer something anyone has to take on trust.

---

## How it fits together

```
   YOUR EXISTING EVAL STACK  (untouched, stays on your machine)
   deepeval / inspect / promptfoo / ragas / your own script
                         |
                         |  results.json  (never uploaded)
                         v
        +----------------------------------------+
        |  ADAPTERS                              |
        |  read results, extract metric values,  |
        |  compute nothing                       |
        +--------------------+-------------------+
                             |
   prereg.yaml               v
       |          +---------------------------+
       v          |  DECISION ENGINE          |
  +----------+    |  applies ONLY the sealed  |
  | CANON    |--->|  rule, fixed-precision    |
  | RFC 8785 |    |  decimals, no floats      |
  +----+-----+    +-------------+-------------+
       |                        |
       v                        v
   +------------------------------------------------+
   |  MERKLE LOG   append-only, Ed25519 checkpoints  |
   |  seals | attestations | ATTEMPT LEDGER          |
   |  stores digests and metadata only               |
   +--------+--------------------------+-------------+
            |                          |
            v                          v
   +------------------+     +------------------------+
   |  PUBLIC SITE     |     |  plimsoll verify       |
   |  + browser       |     |  offline, or against   |
   |    verifier      |     |  ANY log endpoint      |
   +------------------+     +------------------------+
```

Two things about this diagram matter more than the boxes.

**The eval stack is outside the system.** PLIMSOLL has no scorers, no metrics, no LLM judge, no "assessment framework." It is a notary, not a lab. This is a permanent architectural commitment, not a v1 limitation. See [docs/NON-GOALS.md](docs/NON-GOALS.md).

**The verifier points anywhere.** `plimsoll verify --log <any-url>` works against any conforming log, not just ours. A transparency log with exactly one operator is just a database with good manners. If we vanish, go rogue, or start rewriting history, it is detectable by anyone holding the CLI.

---

## Quick start

Install:

```bash
brew install GautamTalksDev/plimsoll/plimsoll     # macOS / Linux
scoop install plimsoll                            # Windows
pip install plimsoll                              # Python users
go install github.com/GautamTalksDev/plimsoll/cmd/plimsoll@latest
```

Write your pre-registration. This is the whole file:

```yaml
plimsoll_version: seal-v1
subject:
  name: support-agent-quality
  system_under_test:
    model: claude-sonnet-4-6
    prompt_sha256: sha256:...
dataset:
  path: ./eval-set.jsonl      # hashed locally, never uploaded
  held_out: true
harness:
  tool: deepeval
  version: 3.4.1
metrics:
  - id: acc
    name: answer_relevance
    direction: higher_is_better
decision_rule:
  expression: "acc.mean >= 0.82 AND acc.p10 >= 0.60"
  primary_metric: acc
  threshold: 0.82
  precision: 6
planned_attempts: 1
analysis_plan: "Single run. No re-runs. Failure is reported as failure."
```

Seal it, run your eval, attest:

```bash
plimsoll seal --file prereg.yaml --publish
# -> support-agent-quality.seal.json, with an inclusion proof

deepeval test run tests/            # your eval, your tool, your machine

plimsoll attest --seal support-agent-quality.seal.json \
                --results .deepeval-cache.json --publish
```

Output:

```
PASS   acc.mean >= 0.82 AND acc.p10 >= 0.60

  acc.mean   0.847  >=  0.82   ok
  acc.p10    0.612  >=  0.60   ok

Attempt 1 of this seal.
Published: sha256:9f2c...  https://plimsoll.dev/seal/sha256:9f2c...
```

Exit codes: `0` PASS, `1` FAIL, `2` INVALID, `3` operational error. Drop it in CI and it gates a release.

Anyone can now check your work:

```bash
plimsoll verify support-agent-quality.attest.json --log https://plimsoll.dev
```

Or they can open [plimsoll.dev/verify](https://plimsoll.dev/verify), paste the file, and read the answer. No install, no account, and the file never leaves their browser.

Longer walkthroughs for each harness are in [docs/QUICKSTART.md](docs/QUICKSTART.md).

---

## Three ideas that make this work

### 1. The attempt ledger

When you publish an attestation, **the log** assigns the attempt number inside a database transaction. The client cannot pick it. There is no API that sets it.

So a seal with five attestations shows five attempts, in order, with all five verdicts, forever. Verification reports `VERIFIED WITH DISCLOSURES` and lists them. There is no flag to suppress this.

**Iterating is normal. Hiding iteration is the problem.** A badge showing three attempts is blue, not red. That distinction is deliberate: if the tool shames iteration, nobody publishes anything and the log dies empty.

### 2. There is no override

A sealed decision rule cannot be edited. Not with a flag, not with an environment variable, not with a config file, not on a paid tier. We looked for a code path that mutates a sealed field and wrote a test that fails if one ever appears.

If your pre-registration turns out to be wrong, you issue a **superseding seal**. It references the old one, carries a required public reason, and every verification reports the whole chain. Amendment is impossible. Disclosure is mandatory.

This is not moralism. It is the only reason a sceptical third party would accept the output at all. The moment an override exists, the artifact is worth nothing to the person it was meant to convince.

### 3. Determinism, all the way down

Nothing in the trust path is probabilistic. No model, no heuristic, no score.

- Canonicalization is RFC 8785 JCS with Unicode NFC and LF normalization, version-tagged so a future change cannot silently invalidate history.
- Dataset hashing treats a dataset as an unordered multiset of canonicalized rows, so reordering your JSONL does not produce a false "dataset changed" alarm, while duplicating a row does change the hash.
- All comparisons use fixed-precision decimals. There is no `float64` in the value path. `0.82 >= 0.8200000000000001` returning the wrong answer is exactly the kind of bug that would destroy the tool's credibility, so the type system prevents it.
- The Merkle tree is RFC 6962 with domain separation: leaves hash with `0x00`, internal nodes with `0x01`.

Same seal plus same results equals the same verdict, on any machine, forever.

---

## What a verification actually checks

`plimsoll verify` runs nine independent checks and reports each one:

| Check | Question it answers |
|-------|--------------------|
| V1 | Is the attestation signature valid? |
| V2 | Is the seal signature valid? |
| V3 | Is the seal in the log? (this is what establishes its timestamp) |
| V4 | Is the attestation in the log? |
| V5 | Does the seal strictly predate the results? |
| V6 | Is the dataset the one that was sealed? |
| V7 | Re-running the decision engine on the attested terms, do we get the same verdict? |
| V8 | **How many attempts were there, and is this seal superseding another?** |
| V9 | Is the log itself internally consistent and unmodified? |

Top-line result is one of `VERIFIED`, `VERIFIED WITH DISCLOSURES`, or `NOT VERIFIED`.

V3 deserves a note. Your own signature on a timestamp proves nothing, because you control your own clock. What makes the "before" claim real is the log's inclusion proof against a signed checkpoint. This is why an unpublished seal prints a loud warning: it is a local note to yourself, not evidence.

---

## Repository map

```
cmd/
  plimsoll/          the CLI: seal, attest, verify, supersede, evidence
  plimsolld/         the public log server
  verifywasm/        the browser verifier, compiled to WASM

internal/
  canonical/         RFC 8785 canonicalization, dataset hashing, decimals
  expr/              decision-rule grammar (parser only, no evaluation)
  seal/              pre-registration schema, validation, signing
  adapt/             harness adapters. extract only, never compute
  decide/            the decision engine. applies the sealed rule
  log/               SQLite-backed append-only Merkle log
  logmerkle/         Merkle math, split out so WASM can use it without SQLite
  logd/              the public read API and /submit
  logserver/         a second, independent server used to prove Rule 9 in tests
  verify/            the nine checks, offline-capable
  evidence/          evidence packs, deterministic PDF output
  site/              static site and the browser verifier assets

SPEC-PREREG.md       the specification. CC0. the source of truth.
docs/
  NON-GOALS.md       five things this project will never do
  PRIOR-ART.md       where this sits relative to CT, in-toto, Sigstore, clinical trials
  THREAT-MODEL.md
  COMPLIANCE-MAPPING.md
  QUICKSTART.md
  GENERIC-FORMAT.md  use PLIMSOLL with a harness we do not have an adapter for
```

A few of these look redundant and are not. `logmerkle` is separate from `log` because the WASM verifier needs Merkle arithmetic and cannot link SQLite. `logserver` is a deliberately separate implementation that exists so the test suite can prove verification works against a log that is not ours. `internal/log/stub.go` is an empty type behind a `//go:build js` tag for the same WASM reason.

---

## Building from source

```bash
git clone https://github.com/GautamTalksDev/plimsoll
cd plimsoll
go build ./...
go test ./...
```

Go 1.23 or later. No cgo, so cross-compilation is a single environment variable. The only direct dependencies are cobra and a pure-Go SQLite driver, which is not an accident. Every dependency in a security tool is a question you will eventually have to answer.

For the browser verifier:

```bash
./scripts/build-wasm.sh
```

CI runs the full suite on Linux, macOS, and Windows on every push.

---

## Running your own log

The point of a transparency log is that you do not have to trust the operator. That only means something if running your own is realistic, so:

```bash
plimsolld -addr :8080 \
          -db ./log.sqlite \
          -key ./log-signing.key \
          -base-url https://log.example.com
```

Read endpoints: `/checkpoint`, `/entries`, `/proof/inclusion`, `/proof/consistency`, `/seal/{hash}`, `/seal/{hash}/badge.svg`. One write endpoint: `/submit`, which accepts a signed seal or attestation and rejects any payload containing a field outside the published schema. That allowlist is enforced server-side, which is how the "we never receive your data" promise stays true even if a client is buggy or hostile.

Publish your public key. Point verifiers at your URL. That is the whole operation.

---

## Design commitments

These are load-bearing, and pull requests that violate them will be declined regardless of how useful the feature is.

1. **We never receive, store, or transmit a dataset or a model.**
2. **We never define, select, or bundle an assessment framework.**
3. **We never compute a quality metric, score, or evaluation result.**
4. **We never combine a computed assessment result with a hash into a signed artifact we produced.**
5. **We are never the only party able to verify an attestation.**
6. **There is no override on a sealed decision rule.**
7. **Nothing in the trust path is probabilistic.**
8. **Zero network egress unless you explicitly asked for it.** No telemetry, no version check, no analytics.

Rules 1 through 5 also appear in [docs/NON-GOALS.md](docs/NON-GOALS.md) with fuller reasoning.

---

## Kill tests

This project is pre-registered against itself. These were written into this README in the first commit, before any application code existed, and they will not be moved.

**KT-1.** If, eight weeks after public launch, fewer than 25 distinct organizations have published a seal to the public log, nobody is being asked to prove their eval numbers. Publish and stop.

**KT-2.** If, across at least 100 sealed evaluations, fewer than 10% show either more than one attested attempt against the same seal or a superseding seal issued after a failed attempt, then post-hoc flexibility is not occurring in practice and this log adds nothing over a git commit. Publish and stop.

**KT-3.** If nobody has contacted us unprompted requesting a private log or evidence export within three months of launch, there is no business here. Keep the public log running and move on.

Current status is in [RESULTS.md](RESULTS.md). At the time of writing, KT-2 is **not evaluable**: the pilot has not run, N is zero, and the honest answer is neither PASS nor FAIL. Writing anything else would be the exact behaviour this tool exists to make visible.

---

## Where this sits

PLIMSOLL is not a new idea. It is an old idea applied somewhere new.

Medicine solved this in 2005. The ICMJE required trials to be registered before enrolment, because the literature had a garden of forking paths problem and selective reporting was distorting what everyone believed to be true. Certificate Transparency solved the log half in 2013: make issuance public and append-only, and misissuance becomes detectable without anyone having to be trusted. in-toto and Sigstore brought signed attestations to software supply chains.

PLIMSOLL is those two ideas pointed at machine learning evaluation. [docs/PRIOR-ART.md](docs/PRIOR-ART.md) lays out the lineage properly, with dates.

Notably, Certificate Transparency was not built by a Certificate Authority. A vendor attesting to its own numbers has the same conflict, which is why this is a neutral, open, independently verifiable layer rather than a feature inside an eval platform.

---

## A note on trust, since this is a security tool run by one person

Current security guidance tells organizations to avoid depending on single-maintainer projects for core functions, and that guidance is correct. So rather than asking you to trust me:

- **The log is auditable by anyone.** If history is rewritten, `plimsoll verify` detects it. Try it: edit the SQLite file by hand and watch verification fail.
- **Releases are signed** with cosign keyless via Sigstore, published with SHA256SUMS and SLSA build provenance. You can verify the binary matches this source.
- **The dependency surface is tiny** and every addition is deliberate.
- **The spec is CC0.** If this project is abandoned, someone else can implement it cleanly, and existing logs remain verifiable.
- **Anyone can run a log.** The verifier already points anywhere.

Security reports go to the address in [SECURITY.md](SECURITY.md) under a 90-day coordinated disclosure policy.

---

## Support

GitHub Issues only. No Discord, no Slack, no email support, no DMs. Best effort, no SLA, stated plainly and without apology. Issues without a reproduction get closed with a template. Feature requests go to Discussions and are answered in a monthly batch. Full details in [SUPPORT.md](SUPPORT.md).

One thing worth stating explicitly: we do not interpret your evaluation results, advise on metric selection, or assess whether your evidence satisfies any regulation. We verify that what you said before matches what you got after. That is the entire scope.

---

## Contributing

Contributions welcome, with a DCO sign-off (`git commit -s`) on every commit. Read [CONTRIBUTING.md](CONTRIBUTING.md) and the design commitments above before opening a pull request.

If you maintain an eval framework and want to emit PLIMSOLL attestations natively, please do. The spec is CC0 precisely so you do not have to ask.

## License

Code: Apache 2.0. Specification: CC0-1.0. Dataset, when published: CC-BY-4.0.

---

*A plumb line does not make a wall straight. It makes it obvious whether the wall is straight.*
