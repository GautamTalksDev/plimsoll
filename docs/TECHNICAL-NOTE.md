# Pre-Registering Machine Learning Evaluations in a Public Append-Only Log

## A Technical Note on the PLIMSOLL Specification, Version 1

**Author:** Gautam Khosla
**Date:** 26 August 2026
**Specification version:** `prereg-v1`
**License:** CC0 1.0 Universal (CC0-1.0)
**Reference implementation:** https://github.com/GautamTalksDev/plimsoll (Apache-2.0)

To the extent possible under law, the author has waived all copyright and related or neighboring rights to this work under CC0 1.0. This note is published to place the mechanism it describes in the public domain and in the public record.

---

## Abstract

A reported machine learning evaluation result carries no evidence about the process that produced it. A reader cannot determine whether the acceptance threshold was chosen before or after the result was observed, whether the evaluation dataset is the one previously used, or how many attempts were made before the reported one. The third question is the most consequential and the least often asked: a party may run an evaluation repeatedly under varying conditions and report only the attempt that satisfied their claim, without falsifying any individual number.

This note describes a mechanism that makes such process facts checkable by a third party who trusts neither the claimant nor the operator of the verification service. Before an evaluation is executed, a **seal** is constructed containing the decision rule, the acceptance threshold, digests identifying the dataset and the system under test, and the declared analysis plan. The seal is canonicalized, hashed, signed, and appended to a public Merkle tree. After execution, an **attestation** binds the observed aggregate values to that seal by digest, and is itself appended. The log — not the client — assigns each attestation a monotonically increasing attempt number scoped to its seal, so the number of attempts made against a given pre-registration is a published fact rather than a disclosure the claimant may choose to omit.

The mechanism is deliberately narrow. It does not execute evaluations, define metrics, select assessment frameworks, or compute quality scores. It never receives datasets, models, prompts, or model outputs; only digests and metadata cross the boundary. Its decision procedure is deterministic and reproducible by any third party from the published artifact alone.

This note documents the mechanism, its cryptographic construction, and its limitations. It makes no empirical claims: at the time of writing no field study has been conducted, and the questions of how often post-hoc flexibility occurs in practice and whether such a log changes reporting behaviour remain open.

---

## 1. Motivation

### 1.1 The problem is process, not arithmetic

Consider the claim: *our model scores 0.87 on our internal evaluation, up from 0.81.*

The number may be entirely accurate. What a reader cannot establish is any of the following:

- Was the acceptance threshold fixed before the result was observed?
- Is the evaluation set unchanged from the previous measurement, or has it been modified, filtered, or regenerated?
- Was the harness configuration held constant?
- **How many evaluation runs preceded the one being reported?**

The first question is the widely recognized one, and it is the least dangerous, precisely because it is recognized. Moving a threshold after observing a result requires the claimant to state two inconsistent thresholds at two points in time, which is detectable by anyone comparing documents.

The fourth question describes a failure mode requiring no inconsistency at all. An evaluation may be run repeatedly across random seeds, decoding temperatures, retrieval configurations, or prompt variants. If the results are reported selectively, every published number is individually correct and the aggregate impression is unfounded. This is the same structure as selective outcome reporting in clinical research, which motivated mandatory prospective trial registration; and the same structure as the multiple comparisons problem, in which the analytic freedom available to the analyst is not visible in the reported result.

### 1.2 Why existing artifacts do not answer it

**Version control** records what the claimant chose to commit. A repository that contains one evaluation result is indistinguishable from one whose author committed a single run out of nine.

**Signed results** establish that a result was not modified after signing. They say nothing about what was discarded before signing.

**A vendor's own evaluation platform** cannot resolve the question structurally. The record of discarded attempts would be held by the party whose interest is served by its absence. This is the conflict that motivated Certificate Transparency being designed as infrastructure external to certificate authorities rather than as a feature within them.

The general shape of the problem is that absence of evidence is indistinguishable from absence of the event. A mechanism that addresses it must make the *absence* of a record detectable, which requires that records be appended to a structure the claimant does not control and cannot retroactively edit.

---

## 2. Mechanism

### 2.1 Objects

**Seal.** A pre-registration authored before results exist. It contains: a subject identifier and digests for the system under test (a model *identifier*, never model weights; digests of the prompt document and configuration document, both computed locally); a dataset digest, row count, sampling label, and held-out flag; a harness tool name, version, and configuration digest; metric declarations; a decision rule comprising an expression, a primary metric, a threshold expressed as a lexical decimal string, a comparator, and a decimal precision; declared exclusion criteria; a declared number of planned attempts; a prose analysis plan; and version tags for the specification and the canonicalization.

**Attestation.** Authored after an attempt. It names a seal by digest and carries the aggregate values observed, each as a lexical decimal string, together with the number of items evaluated. It **must not** contain an attempt number; a conforming implementation rejects any attestation that includes one.

**Log.** An append-only Merkle tree containing both seals and attestations, ordered by submission. It assigns attempt numbers and publishes signed tree heads.

### 2.2 Canonicalization

Any document that is hashed or signed is first reduced to a single deterministic byte sequence, in this order:

1. Reject input exceeding 1 MiB.
2. Parse the JSON, preserving numeric literals in their original lexical form rather than converting to a binary floating-point type.
3. Normalize every string value to Unicode NFC.
4. Within string values, replace CRLF with LF, then any remaining CR with LF.
5. Do **not** strip zero-width characters, bidirectional overrides, or control characters. These are preserved deliberately: silently removing them would make two visually distinct documents hash identically, which is the property an adversary would exploit.
6. Serialize under RFC 8785 JSON Canonicalization Scheme: lexicographic key ordering by UTF-16 code unit, no insignificant whitespace, JCS number serialization.
7. Prefix the result with the literal bytes `plimsoll-canon-v1\n`.

The digest is SHA-256 over the prefixed bytes. The version prefix is not decorative: it ensures that a future revision of the canonicalization rules produces a disjoint digest space rather than silently invalidating existing records.

Steps 3 and 4 exist because the same logical document authored on different platforms or in different editors produces different bytes. Without normalization, a substantial fraction of legitimate documents would produce spurious mismatches, and a verification tool that emits false alarms is discarded by its users.

### 2.3 Dataset identity

Dataset digests use a distinct construction, `plimsoll-dataset-v1`, because a dataset is not a document.

A dataset is treated as an **unordered multiset of rows**. Each row is canonicalized under `plimsoll-canon-v1`; the resulting byte sequences are sorted lexicographically; they are joined with `0x0A`; the result is prefixed with `plimsoll-dataset-v1\n` and hashed with SHA-256.

Two consequences follow, and both are intended. Reordering the rows of an evaluation set does not change its digest, so shuffling a JSONL file does not produce a spurious "the dataset changed" result. Duplicating a row *does* change the digest, because duplicate rows alter the empirical distribution being measured and a construction that treated the dataset as a set would conceal that.

Row count is recorded separately as metadata. It cannot be recovered from the digest, and a conforming implementation must not attempt to infer it.

This computation runs entirely on the author's machine. The rows are never transmitted.

### 2.4 The decision rule language

The decision rule is expressed in a language deliberately constructed to be too small to be clever.

```
expression   = or_expr ;
or_expr      = and_expr { "OR" and_expr } ;
and_expr     = not_expr { "AND" not_expr } ;
not_expr     = "NOT" not_expr | primary ;
primary      = "(" expression ")" | comparison ;
comparison   = identifier comparator literal ;
identifier   = metric_id "." aggregate ;
aggregate    = "mean" | "median" | "min" | "max"
             | "p10" | "p50" | "p90" | "p95"
             | "count" | "pass_rate" ;
comparator   = ">=" | "<=" | ">" | "<" | "==" | "!=" ;
literal      = ["-"] digits ["." digits] ;
```

There is no arithmetic, no function-call syntax, no variables, and no assignment. `acc.mean + 0.01 >= 0.82` does not parse. `mean(acc) >= 0.82` does not parse. A hyphen-minus is part of a decimal literal only when immediately followed by a digit; in any other position it is an error, because it is not a subtraction operator.

An aggregate is a *name* following a period, not a call. This distinction matters: a language admitting call syntax invites argument syntax, argument syntax invites expressions as arguments, and the rule ceases to be mechanically comparable across implementations.

The restriction is a design position rather than an implementation limit. A pre-registered decision rule must be simple enough that a reader can determine, by inspection, what would count as success. A rule expressive enough to encode a post-hoc rationalization is not a pre-registration.

Percentiles use the **nearest-rank** method without interpolation. For `n` sorted observations `x[1..n]` and percentile `p`, the rank is `ceil(p/100 × n)`, clamped to `[1, n]`, and the result is `x[rank]`. `median` is defined as nearest-rank `p50` and is therefore **not** the mean of the two central values when `n` is even. This is stated explicitly because percentile conventions differ between statistical packages, and an unstated convention is a portability defect: two conforming implementations would otherwise disagree on the same data.

### 2.5 Decimal comparison

Metric values are compared using fixed-precision decimal arithmetic derived from their **original lexical representation**. They are never parsed through IEEE 754 binary64.

The reason is concrete. The decimal 0.82 has no exact binary64 representation. A round trip through binary64 may yield a neighbouring value such as 0.8200000000000001, at which point `0.82 >= 0.8200000000000001` and `0.8200000000000001 >= 0.82` disagree. A verification system whose verdict depends on which of two equivalent writings of the same reported number was parsed is not a verification system. The alternative common remedy — an epsilon tolerance — is a threshold that was not pre-registered, and therefore reintroduces exactly the discretion the mechanism exists to remove.

The reference implementation represents a decimal as an arbitrary-precision integer coefficient with a declared scale, parses via exact rational arithmetic, and rounds half away from zero. Comparison across differing scales is performed by exact cross-multiplication rather than by conversion. The parser rejects inputs containing `/` and `_`, which the underlying rational parser would otherwise accept as fraction and digit-separator syntax not present in the specified decimal grammar.

### 2.6 The log

The log is an RFC 6962-style Merkle tree over both seals and attestations in submission order. Leaves are hashed as `SHA-256(0x00 ‖ entry)` and internal nodes as `SHA-256(0x01 ‖ left ‖ right)`. The domain separation prefixes prevent an internal node hash from being presented as a leaf hash. The reference implementation supports inclusion proofs and consistency proofs, and exports verification functions that operate on proofs alone without access to the log's storage.

Tree heads are signed with Ed25519 over a canonical text payload comprising a version tag, tree size, root hash, and timestamp.

In the reference implementation, append-only behaviour is enforced at two levels. The package exposes no update or delete operation. Independently, the underlying database carries triggers that abort any `UPDATE` or `DELETE` against either table. The second is not redundant: it constrains an operator who bypasses the application and edits storage directly, and it is a property a reviewer can confirm from the schema without auditing the application code.

### 2.7 The attempt ledger

The mechanism's distinguishing property is here.

When an attestation is accepted, the log assigns its attempt number within a database transaction, as one greater than the current maximum for that seal. A uniqueness constraint on the pair (seal, attempt number) prevents collision under concurrency. The client submits no attempt number and cannot influence the assigned value.

The consequence is that the total number of attestations against a seal is a published property of the log, discoverable by anyone, independent of whatever the claimant chooses to publish. Verification reports it unconditionally; the specification requires the attempt number to be recoverable from the log entry itself rather than only through an operator API, so that an operator cannot suppress it by withholding a query endpoint.

An important design consideration follows. If a system presents repeated attempts as evidence of misconduct, no rational actor publishes a seal, and the log remains empty. Iteration is ordinary and necessary practice in machine learning. What the mechanism targets is not iteration but *undisclosed* iteration. The reference implementation reflects this: an attestation with multiple attempts verifies as `VERIFIED WITH DISCLOSURES`, a successful outcome that carries additional published context, rather than as a failure.

### 2.8 Supersession

A seal cannot be edited. There is no flag, environment variable, configuration setting, or licensing tier that permits amending a sealed decision rule.

Where a pre-registration proves inadequate, the author publishes a **new** seal carrying a reference to the digest of the seal it supersedes together with a non-empty, publicly visible reason. Self-supersession is rejected. The superseded seal and all attestations against it remain in the log permanently. Verification reports the supersession chain.

Amendment is impossible; disclosure is compulsory. This is not a moral stance but a structural requirement: a mechanism offering any amendment path produces artifacts that a sceptical reader has no reason to accept, and the mechanism's entire value lies in being acceptable to a sceptical reader.

### 2.9 Verification

Verification comprises nine independent checks, each reported separately with its reason:

| Check | Property established |
|---|---|
| V1 | The attestation signature is valid under the stated public key |
| V2 | The seal signature is valid |
| V3 | The seal is included in the log under a signed tree head |
| V4 | The attestation is included in the log under a signed tree head |
| V5 | The seal precedes the attestation in log order |
| V6 | The attestation binds to the seal's digest, row count, harness, and harness version |
| V7 | Re-executing the decision procedure on the attested terms reproduces the recorded verdict |
| V8 | Attempt number, total attempts and their verdicts, and any supersession chain |
| V9 | The proof's tree head is consistent with the latest published tree head |

The aggregate outcome is one of `VERIFIED`, `VERIFIED WITH DISCLOSURES`, or `NOT VERIFIED`.

Two properties of the verification design are load-bearing.

**Verification is not designated.** It operates against any conforming log endpoint, not solely the endpoint that issued the record, and operates fully offline from a bundle containing the necessary proofs and tree heads. A verification mechanism in which one party is the only party able to verify has reproduced the trust relationship it was intended to remove. In the reference implementation, verification is additionally compiled to WebAssembly so it may be performed in a browser with no installation and without transmitting the artifact.

**V7 is a re-execution, not a lookup.** The verdict is recomputed from the attested terms under the sealed expression. A recorded verdict inconsistent with its own recorded inputs is therefore detectable.

---

## 3. Non-goals

The following are permanent architectural commitments of the specification, not deferred features:

1. The mechanism never receives, stores, or transmits a dataset or a model.
2. It never defines, selects, or bundles an assessment framework.
3. It never computes a quality metric, score, or evaluation result.
4. It never combines a computed assessment result with a digest into a signed artifact of its own production.
5. It is never the only party able to verify an attestation.

Commitments 1 and 3 together mean that the mechanism cannot evaluate a model even in principle. This is not a limitation to be relaxed. A verification layer that also performed measurement would be attesting to its own outputs, which is the conflict identified in §1.2 relocated rather than resolved.

---

## 4. Limitations

The following are genuine and are stated because a mechanism of this kind is worth less than nothing if its guarantees are overstated.

**The mechanism cannot verify that the digest corresponds to the claimed artifact.** Digests are computed on the author's machine. An author who computes a digest over a dataset other than the one actually evaluated produces a record that verifies correctly and is nonetheless false. What is established is that a specific rule was fixed at a specific point in a published ordering, that specific digests were bound to it, and that a specific number of attempts occurred. What is not established is that the unobserved experiment matched its description. No mechanism that declines to receive the underlying data can establish more, and receiving the underlying data is excluded for the reasons in §3.

**Temporal ordering rests on log ordering, and absolute timestamps rest on the operator's clock.** What is cryptographically established is that the seal precedes the attestation in the append-only structure. The wall-clock timestamps carried on tree heads are asserted by the operator. Binding to an external time authority — for example, an RFC 3161 timestamp authority — would strengthen this and is not implemented in version 1.

**A single-operator log admits equivocation.** An operator could in principle present different tree heads to different verifiers. Merkle consistency proofs make this detectable only among parties that compare the tree heads they received. Certificate Transparency addresses this with gossip and witness protocols; no equivalent is specified here. Until such a protocol exists, the practical mitigation is that the specification and the verifier permit any party to operate their own log, and verification is not tied to any particular endpoint.

**Attempts made without sealing are invisible.** The mechanism records attempts attested against a seal. An author who evaluates repeatedly before creating a seal, and seals only once satisfied, produces a record showing a single attempt. The mechanism narrows the window in which undisclosed flexibility can occur; it does not eliminate it. The `planned_attempts` field records declared intent but is not enforced by the log.

**No empirical evidence exists.** This note describes a mechanism. Whether post-hoc flexibility occurs at a rate that makes such a log worthwhile, whether the availability of such a log alters reporting behaviour, and whether practitioners will adopt a mechanism that publishes their failed attempts are all open empirical questions on which no data has been collected. The reference implementation's documentation states pre-registered conditions under which the project would be discontinued and reported as a negative result.

---

## 5. Relation to prior work

The mechanism combines two established ideas and applies them to a domain where, to the author's knowledge, their combination has not previously been deployed.

**Prospective registration of analysis plans.** ClinicalTrials.gov (2000) and the ICMJE mandatory registration policy (effective 2005) require trial protocols and outcome measures to be declared before enrolment as a condition of publication, in response to documented outcome switching and publication bias. The present mechanism adopts this structure and differs in enforcement: registration is a cryptographic commitment in an append-only log verifiable by any third party offline, rather than an institutional registry verified by journals and regulators.

**Public append-only logs for detecting undisclosed events.** RFC 6962 Certificate Transparency (2013) establishes that publishing issuance records to an append-only Merkle log renders misissuance detectable without requiring any party to be trusted. The present mechanism adopts the tree construction, the domain-separated hashing, and the inclusion and consistency proof machinery. It differs in what is logged and when: Certificate Transparency logs an artifact after issuance, whereas the present mechanism logs a decision rule before the results it governs exist, and subsequently logs each attempt against that rule.

**Signed attestations over process metadata.** in-toto (2019) and DSSE, together with Sigstore and Rekor (2021) and SLSA provenance (2021), established signed statements about how software artifacts were produced, recorded in transparency logs. The present mechanism resembles these in construction and differs in payload: the subject is an evaluation protocol committed in advance, not a build process; and the mechanism never attests to a quality measurement it computed.

The specific contribution claimed here is narrow and is the combination: **an ex-ante commitment to an evaluation decision rule, held in a public append-only log, with attempt counts assigned by the log rather than the claimant, verifiable offline by any party, in a system that never receives the evaluation data.**

---

## 6. Status and availability

The specification `prereg-v1` is published under CC0 1.0 to permit unrestricted implementation, including commercial implementation and implementation by parties who have not read the reference code. A conformance checklist is included in the specification.

The reference implementation is available under Apache-2.0 at https://github.com/GautamTalksDev/plimsoll. It is written in Go with no cgo dependency, tested on Linux, macOS, and Windows, and released with signed binaries and build provenance.

This note and the accompanying specification are deposited as a defensive publication. The mechanism described is placed in the public domain; the author asserts no exclusive rights over it and intends that it remain freely implementable.

---

## References

RFC 2119, *Key words for use in RFCs to Indicate Requirement Levels*, IETF, March 1997.

RFC 6962, *Certificate Transparency*, IETF, June 2013.

RFC 8785, *JSON Canonicalization Scheme (JCS)*, IETF, June 2020.

Torres-Arias, S., Afzali, H., Kuppusamy, T. K., Curtmola, R., and Cappos, J., *in-toto: Providing farm-to-table guarantees for bits and bytes*, USENIX Security Symposium, August 2019.

Dead Simple Signing Envelope (DSSE), protocol version 1.0.0, 3 March 2021.

Sigstore, announced by the Linux Foundation, 9 March 2021. Rekor v0.2.0, 17 June 2021.

*Supply-chain Levels for Software Artifacts (SLSA)*, 16 June 2021.

ClinicalTrials.gov, launched by the U.S. National Institutes of Health, 29 February 2000.

International Committee of Medical Journal Editors, prospective trial registration as a condition of publication, effective 1 July 2005.
