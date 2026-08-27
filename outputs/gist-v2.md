# How many times did they run it?

*A note on why evaluation claims are unverifiable, and one mechanism that makes part of the problem checkable.*

Gautam Khosla, August 2026

---

## The claim nobody can check

> Our model scores 0.87 on our internal eval, up from 0.81.

The number may be entirely accurate. What you cannot establish, as a reader, is any of the following:

- Was the acceptance threshold fixed before the result was observed?
- Is the evaluation set unchanged from last quarter, or has it been filtered or regenerated?
- Was the harness configuration held constant?
- **How many evaluation runs preceded the one being reported?**

The first question is the widely recognised one, and it is the least dangerous precisely because it is recognised. Moving a threshold after seeing a result requires stating two inconsistent thresholds at two points in time, which anyone comparing documents can spot.

The fourth question describes a failure mode requiring no inconsistency at all.

## The quiet version

Run the eval nine times: different seeds, decoding temperatures, retrieval configurations, prompt variants. Report the run that cleared the bar. Every published number is individually correct. The aggregate impression is unfounded.

This is the same structure as selective outcome reporting in clinical research, which is what motivated mandatory prospective trial registration. It is the same structure as the multiple comparisons problem, where the analytic freedom available to the analyst is invisible in the reported result.

## Why existing artifacts do not help

**Version control** records what the author chose to commit. A repository containing one evaluation result is indistinguishable from one whose author committed a single run out of nine.

**Signed results** establish that a result was not modified after signing. They say nothing about what was discarded before signing.

**A vendor's own evaluation platform** cannot resolve this structurally. The record of discarded attempts would be held by the party whose interest is served by its absence. This is the conflict that led to Certificate Transparency being designed as infrastructure external to certificate authorities rather than as a feature inside them.

The general shape: absence of evidence is indistinguishable from absence of the event. Addressing it requires that records be appended to a structure the claimant does not control and cannot retroactively edit.

## The mechanism

Two objects and a log.

**A seal** is a pre-registration, authored before results exist. It carries a decision rule, an acceptance threshold as a lexical decimal string, digests identifying the dataset and the system under test, harness identity, declared exclusions, and a prose analysis plan. It is canonicalized, hashed, signed, and appended to a public Merkle tree.

**An attestation** is authored after an attempt. It names a seal by digest and carries the observed aggregate values. It **must not** contain an attempt number; a conforming implementation rejects any attestation that includes one.

**The log** assigns the attempt number, inside a database transaction, as one greater than the current maximum for that seal. A uniqueness constraint on (seal, attempt number) prevents collision under concurrency.

The consequence is the whole point: the total number of attestations against a seal is a published property of the log, discoverable by anyone, independent of whatever the claimant chooses to publish.

## Iteration is not the target

If a system presents repeated attempts as evidence of misconduct, no rational actor publishes a seal and the log stays empty. Iteration is ordinary and necessary in machine learning.

What the mechanism targets is not iteration but *undisclosed* iteration. An attestation with multiple attempts verifies as `VERIFIED WITH DISCLOSURES`: a successful outcome carrying additional published context, not a failure. Three attempts renders blue, not red.

## There is no override

A seal cannot be edited. No flag, environment variable, configuration setting, or licensing tier permits amending a sealed decision rule.

Where a pre-registration proves inadequate, the author publishes a **new** seal referencing the digest of the one it supersedes, together with a required public reason. Self-supersession is rejected. The superseded seal and every attestation against it remain permanently. Verification reports the chain.

Amendment is impossible; disclosure is compulsory. That is not a moral stance. A mechanism offering any amendment path produces artifacts a sceptical reader has no reason to accept, and the entire value lies in being acceptable to a sceptical reader.

## Some engineering that turned out to matter

**Decimal comparison, never binary64.** The decimal 0.82 has no exact binary64 representation. A round trip may yield 0.8200000000000001, at which point `0.82 >= 0.8200000000000001` and the reverse disagree. A verification system whose verdict depends on which of two equivalent writings of the same number was parsed is not a verification system. The usual remedy, an epsilon tolerance, is a threshold that was not pre-registered, which reintroduces exactly the discretion the mechanism exists to remove.

**Canonicalization before hashing.** RFC 8785 JCS, Unicode NFC, CRLF to LF, version-tagged. Zero-width characters and bidirectional overrides are deliberately **preserved** rather than stripped: silently removing them would make two visually distinct documents hash identically, which is the property an adversary would exploit.

**Datasets as unordered multisets.** Each row canonicalized, sorted, joined, hashed. Shuffling a JSONL file does not produce a spurious "the dataset changed" alarm. Duplicating a row *does* change the digest, because duplicates alter the empirical distribution being measured.

**A decision rule language too small to be clever.** No arithmetic, no function calls, no variables. `acc.mean + 0.01 >= 0.82` does not parse. `mean(acc) >= 0.82` does not parse. A rule expressive enough to encode a post hoc rationalization is not a pre-registration.

## What it never does

Five permanent architectural commitments, not deferred features:

1. It never receives, stores, or transmits a dataset or a model.
2. It never defines, selects, or bundles an assessment framework.
3. It never computes a quality metric, score, or evaluation result.
4. It never combines a computed assessment result with a digest into a signed artifact of its own production.
5. It is never the only party able to verify an attestation.

Commitments 1 and 3 together mean the mechanism cannot evaluate a model even in principle. A verification layer that also performed measurement would be attesting to its own outputs, which relocates the conflict rather than resolving it.

## What it does not establish

Stated plainly, because a mechanism of this kind is worth less than nothing if its guarantees are overstated.

**It cannot verify that a digest corresponds to the claimed artifact.** Digests are computed on the author's machine. An author who hashes a dataset other than the one actually evaluated produces a record that verifies correctly and is nonetheless false. What is established is that a specific rule was fixed at a specific point in a published ordering, that specific digests were bound to it, and that a specific number of attempts occurred. Not that the unobserved experiment matched its description. No mechanism that declines to receive the underlying data can establish more.

**Attempts made without sealing are invisible.** Someone who evaluates repeatedly before creating a seal, then seals once satisfied, produces a record showing one attempt. The window narrows; it does not close.

**A single operator log can still equivocate.** Merkle consistency proofs make divergent tree heads detectable only among parties who compare what they received. Certificate Transparency closes more of that gap with gossip and witness protocols. None is specified here, and git mirroring is not a witness protocol. What git mirroring does give you: the log is a public git repository, every clone holds the complete history, and a rewritten history fails to fast forward for anyone holding a prior clone.

**No empirical evidence exists.** Whether post hoc flexibility occurs at a rate making such a log worthwhile, and whether its availability changes reporting behaviour, are open questions on which no data has been collected.

The strongest objections to building this at all — uptake without a mandate, backwards incentives, the pre-seal window — are written out in [docs/WHY-NOT-ALREADY.md](https://github.com/GautamTalksDev/plimsoll/blob/main/docs/WHY-NOT-ALREADY.md). One of them has no full answer.

## Pre-registered against itself

Three kill tests, written into the README in the first commit, before any application code existed. They will not be moved.

**KT-1.** If, eight weeks after public launch, fewer than 25 distinct organizations have published a seal, nobody is being asked to prove their eval numbers. Publish and stop.

**KT-2.** If, across at least 100 sealed evaluations, fewer than 10% show either more than one attested attempt against the same seal or a superseding seal issued after a failure, then post hoc flexibility is not occurring in practice and this log adds nothing over a git commit. Publish and stop.

**KT-3.** If nobody has asked unprompted for a private log or evidence export within three months of launch, there is no business here. Keep the public log running and move on.

**Pilot N = 0. The public log contains operator fixtures that do not count toward any kill test.** All three are currently **not evaluable**. `RESULTS.md` says so and refuses to report either a pass or a fail, because writing anything else would be the exact behaviour this tool exists to make visible.

## Try it

```bash
brew install GautamTalksDev/plimsoll/plimsoll
```

Or verify an attestation file in your browser with no install. The file never leaves your machine; verification runs locally in WebAssembly. Entries currently on the live log are the operator's own fixtures, authored and verified by the same person, against a five-row synthetic dataset — not third-party evaluations. They demonstrate that the mechanism runs; they are evidence of nothing about practice.

- Live log and browser verifier: https://plimsoll.gautamkhosla.com
- Source, Apache-2.0: https://github.com/GautamTalksDev/plimsoll
- Specification, CC0: https://github.com/GautamTalksDev/plimsoll/blob/main/SPEC-PREREG.md
- Technical note and DOI: https://doi.org/10.5281/zenodo.22107450
- Why this might not be worth building: https://github.com/GautamTalksDev/plimsoll/blob/main/docs/WHY-NOT-ALREADY.md

The specification is CC0 so that anyone can implement it, including commercially and including without reading the reference code. If you maintain an eval framework and want to emit these attestations natively, please do. You do not have to ask.

## What I am looking for

Three teams running real evaluations who will try this for eight weeks. It is free, I do the integration, you keep everything, and I publish aggregates only unless you consent by name in writing.

If you think the idea is wrong, I would rather hear that than agreement. Being told why it will not work is the more useful input right now.

---

*A plumb line does not make a wall straight. It makes it obvious whether the wall is straight.*
