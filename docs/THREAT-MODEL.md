# Threat model

This is the intended threat model for the design. Week 1 has no application
logic; the mitigations below are architectural commitments, not claims about
running code.

## Assets

| ID | Asset | Why it matters |
| --- | --- | --- |
| A1 | Sealed decision rule | The rule is the pre-registration. If it can be amended after results are known, the log is theatre. |
| A2 | Attested attempts against a seal | Failed and superseded attempts are the evidence of post-hoc flexibility. Suppressing them makes the log equivalent to a git commit of the final number. |
| A3 | Merkle log consistency and inclusion | Verifiers must be able to check that an entry is in the same append-only history everyone else sees. |
| A4 | User eval artifacts (datasets, models, prompts, outputs) | These must never enter PLIMSOLL. Compromise of this project must not yield eval data, because we must not have it. |
| A5 | Offline verification | A third party holding the artifact and an inclusion proof must be able to verify without calling our log as the only authority. |

## Adversaries

| ID | Adversary | Goal |
| --- | --- | --- |
| Adv-Author | Evaluation author | Present a favorable number after seeing results: amend the rule, hide failed attempts, or swap digests. |
| Adv-Operator | Log operator (us) | Equivocate (split-view), omit entries, or become the only verifier. |
| Adv-Network | Network attacker | Tamper with submissions or queries; induce a network dependency in the trust path the user did not request. |
| Adv-Insider | Contributor or deployer | Add an override flag, env var, paid-tier bypass, heuristic, or LLM into the trust path. |

## Threats and mitigations

| ID | Threat | Mitigations |
| --- | --- | --- |
| T1 | Amend a sealed decision rule after seeing results | No flag, env var, setting, or paid tier may override a sealed rule. Seals are append-only; a new rule is a new seal, not an edit. |
| T2 | Publish only the successful attempt | The log records attested attempts against a seal, including failures. Kill test KT-2 exists because a log that never shows retries adds nothing over a git commit. |
| T3 | Split-view / equivocation by the log operator | Merkle inclusion and consistency proofs. Git-backed public log: clones detect rewritten history; `plimsoll verify-log` replays checkpoints (not a witness protocol — see TECHNICAL-NOTE §4). Verification must not require our log as the only endpoint (non-goal 5). |
| T4 | Receive, store, or transmit eval data | Digests and metadata only. Adapters and canonicalization are pure (no I/O). Testdata in this repo is fixtures, never a user's dataset. |
| T5 | Make our log the only verifier | `internal/verify` is offline-capable. Anyone with the artifact and a proof can verify. |
| T6 | Non-deterministic or unevaluable trust path | Decision engine is deterministic and unit-testable. No LLM calls, heuristic scores, or probabilistic classifiers. |
| T7 | Mix-and-match: bind a digest of one dataset to the result of another | Canonicalization and hashing bind the digests the user attests. We do not see the bytes, so we cannot "fix" a wrong digest; we can only verify what was sealed and attested. |
| T8 | Combine a score we computed with a hash into a signed artifact we produced | We never compute a quality metric or evaluation result (non-goals 3 and 4). Adapters consume results the user already produced. |

## Out of scope

- Preventing a user from lying about bytes they hashed on their own machine. We verify the seal and the attestation, not the unobserved experiment.
- Replacing the user's evaluation tools. We do not run evaluations.
- Defining what a "good" model is. We do not select or bundle an assessment framework.
