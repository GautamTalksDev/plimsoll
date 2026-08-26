# Evidence pack — regulatory mapping

This document maps contents of a PLIMSOLL evidence pack (`plimsoll evidence
--seal …`) to clauses cited in common AI governance frameworks. It is
descriptive, not normative.

PLIMSOLL is an integrity and verification tool. It is **not** a notified body,
auditor, certification scheme, or legal advisor. Nothing in this document
states or implies that using PLIMSOLL satisfies legal or regulatory obligations
on its own. Each mapping uses the form: *this evidence pack is designed to
support documentation of X*.

---

## What the evidence pack contains

| Section | Content |
|---------|---------|
| Pre-registration (YAML) | Full signed pre-registration: subject, dataset digest, harness, metrics, decision rule, planned attempts |
| Seal inclusion proof | Merkle inclusion proof and signed checkpoint for the seal |
| Attempts (ordered) | Each attestation with verdict, timestamp, result digest, inclusion proof, checkpoint |
| Verification (V1–V9) | Deterministic checks: signatures, log inclusion, ordering, dataset binding, verdict replay, disclosures, consistency |
| Supersede chain | Prior seals superseded by this pre-registration, if any |
| Instructions | Steps to reproduce verification via CLI or browser verifier |
| Log public key | Key used to verify signed checkpoints |

Timestamps in the pack are taken from the transparency log, not the generator's wall clock.

---

## EU AI Act

### Article 11 — Technical documentation

This evidence pack is designed to support documentation of:

- The **evaluation design** fixed before running the harness (pre-registration YAML: metrics, decision rule, dataset digest, planned attempts).
- **Traceability** from a published claim to a signed, log-indexed record (seal hash, inclusion proofs, checkpoints).
- **Reproducible verification** that a third party can run without access to raw evaluation data (V1–V9 results and instructions).

The pack does **not** substitute for complete technical documentation of the AI system itself (architecture, training data, risk management file, etc.).

### Article 12 — Record-keeping

This evidence pack is designed to support documentation of:

- **Immutable, time-ordered records** of pre-registration and attested outcomes (append-only log entries with `submitted_at` and Merkle proofs).
- **Attempt history** without selective disclosure (all attempts listed with verdicts; V8 disclosure check).
- **Supersession history** when a seal replaces a prior pre-registration (supersede chain).

The pack does **not** guarantee retention periods, access controls, or organizational record-keeping policies.

### Article 15 — Accuracy, robustness, and cybersecurity

This evidence pack is designed to support documentation of:

- **Pre-specified accuracy (or metric) criteria** and the rule used to pass or fail (decision rule and V7 verdict replay).
- **Evidence that reported results match the pre-registered rule** (V6 dataset binding, V7 deterministic replay).
- **Integrity of published results** (Ed25519 signatures V1–V2, log inclusion V3–V5, consistency V9).

The pack documents **claims about evaluations the submitter ran locally**. It does not perform evaluation, adversarial testing, or robustness measurement.

### Article 55 — GPAI systemic risk (model evaluation and adversarial testing documentation)

This evidence pack is designed to support documentation of:

- **Pre-registered evaluation protocol** for a named system-under-test (model identifier and config/prompt digests in pre-registration).
- **Published attestation outcomes** with full attempt history (relevant where providers document evaluation and red-teaming runs).
- **Independent verification path** for reviewers who did not run the original harness.

The pack does **not** satisfy GPAI systemic risk assessment obligations by itself and does **not** document adversarial test cases unless the submitter included them in their pre-registration and attestation terms.

---

## ISO/IEC 42001 — AI management system

### Performance evaluation (Clause 8.x — operational planning and control)

This evidence pack is designed to support documentation of:

- **Defined performance criteria** before measurement (decision rule, metrics, thresholds in pre-registration).
- **Evidence of measurement against those criteria** (attestation results and verdicts).
- **Reviewability** via deterministic verification checks.

Mapping is to **documented information about a specific evaluation event**, not to ISO 42001 certification or conformity assessment.

### Documented information (Clause 7.5)

This evidence pack is designed to support documentation of:

- **Controlled, integrity-protected records** (signed artifacts, log proofs).
- **Version/supersession lineage** (supersede chain).
- **Availability to interested parties** (self-contained JSON/PDF export and public log URLs).

Organizations remain responsible for their document control procedures, retention, and scope of documented information.

---

## NIST AI RMF — MEASURE function

The MEASURE function covers identifying and applying methods to assess AI risks
and impacts. This evidence pack is designed to support documentation of:

| MEASURE theme | Pack support |
|---------------|--------------|
| **M-1** Appropriate methods and metrics are identified | Pre-registration lists metrics, definitions (URIs), direction, and decision rule |
| **M-2** Methods are documented and reproducible | YAML pre-registration, harness identity, adapter binding (V6) |
| **M-3** Evaluation results are analyzed | Attestation terms, verdict, V7 replay |
| **M-4** Trustworthiness characteristics are evaluated | Only to the extent the submitter declared metrics and rules; PLIMSOLL does not evaluate trustworthiness |
| **MEASURE tracking** | Log timestamps, attempt order, inclusion proofs |

The pack supports **integrity and verifiability of submitted measurement records**. It is not a NIST AI RMF assessment tool and does not produce RMF maturity scores.

---

## Gaps and reviewer questions

A reviewer using this pack should still ask:

1. Is the pre-registration **complete** for the claim being made (metrics, dataset scope, exclusions)?
2. Does the **dataset digest** correspond to the dataset actually used (PLIMSOLL verifies binding, not dataset contents)?
3. Are **all attempts** included, including failures before a pass?
4. Is the **transparency log** operated with acceptable governance (key custody, availability, monitoring)?
5. Does the organization maintain **other documentation** required by applicable law or standards beyond this pack?

---

## Wording policy

In PLIMSOLL documentation, site copy, and marketing, do not write or imply
that PLIMSOLL satisfies regulatory obligations, provides third-party
certification, or guarantees readiness for external audit. Write only that
artifacts are **designed to support documentation of** specific
record-keeping or evaluation-integrity needs.

See `.cursor/rules/CP-11-wording.mdc` for the enforced authoring rule.
