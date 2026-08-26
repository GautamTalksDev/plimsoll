# PLIMSOLL Pre-Registration and Attestation Specification

**Version:** prereg-v1
**Date:** 2026-08-25
**License:** [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/)
**SPDX-License-Identifier:** CC0-1.0
**DOI:** [10.5281/zenodo.22107451](https://doi.org/10.5281/zenodo.22107451) (this version) · [10.5281/zenodo.22107450](https://doi.org/10.5281/zenodo.22107450) (all versions)

This document is a specification. It is not a user guide and not a
description of one codebase. A conforming implementation MAY be written
in any language. Normative keywords are as in RFC 2119: MUST, MUST NOT,
SHOULD, MAY.

To the extent possible under law, the author has waived all copyright
and related or neighboring rights to this specification under CC0 1.0.

---

## 1. Purpose

A **seal** is a pre-registration: a decision rule and the identities of
the dataset, harness, and system under test, declared **before** results
are known. An **attestation** is a later claim that a particular attempt
was run against a named seal. A **log** records seals and attestations
in append-only order and assigns attempt numbers.

This specification defines the objects, the decision-rule language, the
percentile method, canonicalization, signing, attempt numbering, and
supersession. It does not define how to run an evaluation, how to score
a model, or which metrics are "correct."

A conforming implementation MUST transmit only digests and metadata. It
MUST NOT receive, store, or transmit datasets, models, prompts, or
outputs. See §10.

---

## 2. Terminology

| Term | Meaning |
| --- | --- |
| digest | The string `sha256:` followed by 64 lowercase hex characters. This is the SHA-256 of named canonical bytes, not of raw user files. |
| seal | The pre-registration object in §4. Once hashed and logged, it is immutable. |
| attestation | The attempt object in §7. It names a seal by digest. |
| attempt number | A positive integer assigned **only** by the log, monotonically per seal. Clients MUST NOT choose it. |
| primary metric | The metric named as the public claim. It MUST appear in `metrics[]` and in `decision_rule.expression`. |

---

## 3. Canonicalization

Seals and attestations that are hashed or signed MUST first be converted
to UTF-8 JSON, then canonicalized as **plimsoll-canon-v1**:

1. Reject documents larger than 1 MiB.
2. Parse JSON.
3. NFC-normalize every JSON **string value** (not required of keys).
4. In string values, replace CRLF with LF, then remaining CR with LF.
5. Do not strip zero-width, bidi, or control characters.
6. Serialize with RFC 8785 JCS (UTF-16 code-unit key order, no
   insignificant whitespace, JCS number serialization).
7. Prefix the JCS bytes with the eight-bit string `plimsoll-canon-v1\n`.

The **canonical hash** of a JSON document is `sha256:` plus the lowercase
hex SHA-256 of those prefixed bytes.

Dataset identity MUST use **plimsoll-dataset-v1**, not plimsoll-canon-v1:
canonicalize each row as plimsoll-canon-v1, sort those byte sequences
lexicographically as a **multiset** (duplicate rows are retained), join
with `0x0A`, prefix `plimsoll-dataset-v1\n`, then SHA-256. Row order
MUST NOT affect the digest. A dataset that contains a duplicated row
MUST hash differently from the same rows with that duplicate removed.
Callers MUST record row count `n` as separate metadata; it is not
inferred from the digest.

JSON numbers in JCS follow IEEE 754 binary64. Metric **values** used in
comparisons MUST NOT be parsed through binary64; they MUST be exact
decimals from their original lexical form (see §6.3).

---

## 4. Seal object

`plimsoll_version` for this document is the string `prereg-v1`.
`canon_version` MUST be `plimsoll-canon-v1`.

Unknown **top-level** members MUST be rejected. v1 has no forward
compatibility. Nested objects in the schema below also use
`additionalProperties: false`.

Optional member `supersedes` is omitted unless this seal replaces
another (see §9).

### 4.1 JSON Schema (normative)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://plimsoll.dev/spec/prereg-v1/seal.json",
  "title": "PLIMSOLL seal (prereg-v1)",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "plimsoll_version",
    "created_at",
    "subject",
    "dataset",
    "harness",
    "metrics",
    "decision_rule",
    "exclusions",
    "planned_attempts",
    "analysis_plan",
    "canon_version"
  ],
  "properties": {
    "plimsoll_version": { "const": "prereg-v1" },
    "canon_version": { "const": "plimsoll-canon-v1" },
    "created_at": {
      "type": "string",
      "description": "RFC 3339 timestamp in UTC, suffix Z."
    },
    "subject": {
      "type": "object",
      "additionalProperties": false,
      "required": ["name", "system_under_test"],
      "properties": {
        "name": { "type": "string", "minLength": 1 },
        "system_under_test": {
          "type": "object",
          "additionalProperties": false,
          "required": ["model", "prompt_sha256", "config_sha256"],
          "properties": {
            "model": {
              "type": "string",
              "minLength": 1,
              "description": "A name or identifier, never model weights."
            },
            "prompt_sha256": { "$ref": "#/$defs/digest" },
            "config_sha256": { "$ref": "#/$defs/digest" }
          }
        }
      }
    },
    "dataset": {
      "type": "object",
      "additionalProperties": false,
      "required": ["sha256", "n", "sampling", "held_out"],
      "properties": {
        "sha256": { "$ref": "#/$defs/digest" },
        "n": { "type": "integer", "minimum": 1 },
        "sampling": {
          "type": "string",
          "enum": ["exhaustive", "random", "stratified", "other"]
        },
        "held_out": { "type": "boolean" }
      }
    },
    "harness": {
      "type": "object",
      "additionalProperties": false,
      "required": ["tool", "version", "config_sha256"],
      "properties": {
        "tool": { "type": "string", "minLength": 1 },
        "version": { "type": "string", "minLength": 1 },
        "config_sha256": { "$ref": "#/$defs/digest" }
      }
    },
    "metrics": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "name", "definition_uri", "direction"],
        "properties": {
          "id": {
            "type": "string",
            "pattern": "^[A-Za-z][A-Za-z0-9_]*$",
            "not": { "enum": ["AND", "OR", "NOT"] }
          },
          "name": { "type": "string", "minLength": 1 },
          "definition_uri": { "type": "string", "minLength": 1 },
          "direction": {
            "type": "string",
            "enum": ["higher_is_better", "lower_is_better"]
          }
        }
      }
    },
    "decision_rule": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "expression",
        "primary_metric",
        "threshold",
        "comparison",
        "precision"
      ],
      "properties": {
        "expression": { "type": "string", "minLength": 1 },
        "primary_metric": { "type": "string", "minLength": 1 },
        "threshold": {
          "type": "string",
          "description": "Lexical decimal. MUST be a JSON string, never a JSON number.",
          "pattern": "^-?(0|[1-9][0-9]*)(\\.[0-9]+)?$"
        },
        "comparison": {
          "type": "string",
          "enum": [">=", "<=", ">", "<", "==", "!="]
        },
        "precision": { "type": "integer", "minimum": 1, "maximum": 12 }
      }
    },
    "exclusions": {
      "type": "array",
      "items": { "type": "string" }
    },
    "planned_attempts": { "type": "integer", "minimum": 1 },
    "analysis_plan": { "type": "string" },
    "supersedes": {
      "type": "object",
      "additionalProperties": false,
      "required": ["seal_hash", "reason"],
      "properties": {
        "seal_hash": { "$ref": "#/$defs/digest" },
        "reason": { "type": "string", "minLength": 1 }
      }
    }
  },
  "$defs": {
    "digest": {
      "type": "string",
      "pattern": "^sha256:[0-9a-f]{64}$"
    }
  }
}
```

### 4.2 Field semantics

- `created_at` is when the seal was authored, not when it was logged.
- `subject.system_under_test.model` identifies a system. It is not the
  model file. `prompt_sha256` is the plimsoll-canon-v1 digest of the
  prompt document the user hashed locally. `config_sha256` is the same
  for the non-prompt configuration document.
- `dataset.sha256` is a **plimsoll-dataset-v1** digest computed on the
  user's machine. `n` is the row count of that dataset and MUST be ≥ 1.
- `metrics[].id` MUST be unique within the array.
- `decision_rule.expression` is the complete predicate (§5). Evaluation
  of the predicate against results is out of scope for this document
  (it is a later conformance point). Parse and reference checks are in
  scope.
- `decision_rule.primary_metric` MUST equal some `metrics[].id` and MUST
  occur as a metric identifier in `expression`.
- `decision_rule.threshold` is the lexical decimal of the public claim,
  compared using `decision_rule.comparison` at `decision_rule.precision`.
  It is metadata for the claim. The expression is still the full rule.
- `decision_rule.precision` is the number of digits after the decimal
  point used when interpreting metric values and `threshold` as fixed-
  precision decimals. It MUST be an integer in `1..12` inclusive.
- `exclusions` are planned, human-readable exclusion rules. They are
  not a programming language.
- `analysis_plan` is prose. Implementations MUST NOT execute it.
- `planned_attempts` is the author's declared maximum number of
  attempts they intend to log. The log MAY still accept further
  attestations; the field is evidence of intent, not a cap the log
  enforces unless an operator policy says otherwise.

### 4.3 Example (informative)

```json
{
  "plimsoll_version": "prereg-v1",
  "created_at": "2026-08-25T00:00:00Z",
  "subject": {
    "name": "example-claim",
    "system_under_test": {
      "model": "example-model-id",
      "prompt_sha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "config_sha256": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
  },
  "dataset": {
    "sha256": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "n": 100,
    "sampling": "exhaustive",
    "held_out": true
  },
  "harness": {
    "tool": "example-harness",
    "version": "1.0.0",
    "config_sha256": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  },
  "metrics": [
    {
      "id": "acc",
      "name": "accuracy",
      "definition_uri": "https://example.invalid/metrics/accuracy",
      "direction": "higher_is_better"
    }
  ],
  "decision_rule": {
    "expression": "acc.mean >= 0.82",
    "primary_metric": "acc",
    "threshold": "0.82",
    "comparison": ">=",
    "precision": 6
  },
  "exclusions": [],
  "planned_attempts": 3,
  "analysis_plan": "Report acc.mean against the sealed threshold. No post-hoc metric swap.",
  "canon_version": "plimsoll-canon-v1"
}
```

---

## 5. Decision-rule expression grammar

The language is deliberately too small to express anything clever. A
conforming parser MUST reject anything not generated by this grammar.
There is **no arithmetic**, **no function calls**, and **no variables**.

### 5.1 Lexer

Input is Unicode. Implementations SHOULD reject the expression if it is
not valid UTF-8.

Tokens:

- whitespace: `U+0020`, `U+0009`, `U+000A`, `U+000D` — skipped
- `AND`, `OR`, `NOT` — exactly those bytes, case-sensitive
- `>=` `<=` `==` `!=` `>` `<` — two-character operators are maximal munch
- `(` `)` `.`
- identifier: `[A-Za-z][A-Za-z0-9_]*` that is not `AND`, `OR`, or `NOT`
- decimal literal: `-?(0|[1-9][0-9]*)(\.[0-9]+)?`

A hyphen-minus is part of a decimal literal if and only if it is
immediately followed by a digit. A hyphen in any other position is an
error (it is not subtraction).

The characters `+`, `*`, `/`, `%`, `^`, `[`, `]`, `{`, `}`, `,`, `'`,
`"` and the ASCII letters of a call like `mean(` after an identifier
are errors.

### 5.2 Grammar (EBNF)

```
expression   = or_expr ;
or_expr      = and_expr { "OR" and_expr } ;
and_expr     = not_expr { "AND" not_expr } ;
not_expr     = "NOT" not_expr | primary ;
primary      = "(" expression ")" | comparison ;
comparison   = identifier comparator literal ;
identifier   = metric_id "." aggregate ;
metric_id    = letter { letter | digit | "_" } ;
aggregate    = "mean" | "median" | "min" | "max"
             | "p10" | "p50" | "p90" | "p95"
             | "count" | "pass_rate" ;
comparator   = ">=" | "<=" | ">" | "<" | "==" | "!=" ;
literal      = ["-"] digits ["." digits] ;
digits       = digit { digit } ;
letter       = "A"…"Z" | "a"…"z" ;
digit        = "0"…"9" ;
```

Precedence, tightest first: `NOT`, then `AND`, then `OR`. All binary
boolean operators are left-associative. Comparisons do not chain:
`a.mean >= 1 >= 0` is invalid.

`metric_id` MUST match some `metrics[].id` when the expression is
validated in the context of a seal. The parser itself only checks
the grammar.

### 5.3 What is forbidden (normative examples)

Invalid:

```
acc.mean + 0.01 >= 0.82
acc.mean >= 0.8 + 0.02
mean(acc) >= 0.82
acc.mean() >= 0.82
acc.mean >= 0.82 * 1
x = 0.82
acc.mean >= 0.82 AND
```

Valid:

```
acc.mean >= 0.82
acc.mean >= 0.82 AND loss.max <= 1.0
NOT acc.pass_rate < 0.5
(acc.p50 >= 0.7 OR acc.p90 >= 0.8)
```

---

## 6. Aggregates and percentiles

Aggregates name a reduction over per-row metric values the user already
computed. This specification does not compute those per-row values.

| Aggregate | Meaning |
| --- | --- |
| `mean` | Arithmetic mean of the finite values |
| `median` | Nearest-rank 50th percentile (§6.1) |
| `min` | Minimum |
| `max` | Maximum |
| `p10` `p50` `p90` `p95` | Nearest-rank percentile (§6.1) |
| `count` | Number of finite values used |
| `pass_rate` | Fraction of rows whose per-row pass bit is true, in `[0, 1]` |

### 6.1 Nearest-rank percentile (normative)

Let `n ≥ 1` be the number of finite observations, sorted in
non-decreasing order as `x[1] … x[n]` (1-based). For percentile `p`
in `{10, 50, 90, 95}`:

```
r = ceil(p / 100 * n)
if r < 1 then r = 1
if r > n then r = n
result = x[r]
```

`ceil` is the mathematical ceiling on real numbers. There is **no
interpolation** and **no averaging of adjacent ranks**.

Boundary cases:

| n | p | r | result |
| --- | --- | --- | --- |
| 0 | any | undefined | MUST NOT produce a percentile. A later evaluator MUST fail closed. |
| 1 | 10, 50, 90, 95 | 1 | `x[1]` (`ceil(0.10)=1`, …, `ceil(0.95)=1`) |
| 2 | 50 | 1 | `x[1]`, **not** the mean of `x[1]` and `x[2]` |
| 10 | 10 | 1 | `x[1]` |
| 10 | 50 | 5 | `x[5]` |
| 10 | 90 | 9 | `x[9]` |
| 10 | 95 | 10 | `x[10]` |

Equal values: any stable or unstable sort of equal elements is
conforming; `x[r]` is the same number.

### 6.2 `median`

`median` is defined as nearest-rank `p50`. It is not the mid-mean of
the two central values for even `n`.

### 6.3 Decimal comparison

When a later evaluator compares an aggregate to `decision_rule.threshold`,
both sides MUST be interpreted with `decision_rule.precision` using
fixed-precision decimal arithmetic from the **original lexical** decimal
strings, never via binary64 `float64`. Rounding is half away from zero.

This document does not require an implementation to evaluate expressions
(that is a later conformance point). It DOES require that a seal
validator parse `threshold` as such a decimal.

---

## 7. Attestation object

An attestation is authored on the user's machine after an attempt. It
names a seal by digest. It MUST NOT contain an attempt number.

### 7.1 JSON Schema (normative)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://plimsoll.dev/spec/prereg-v1/attestation.json",
  "title": "PLIMSOLL attestation (prereg-v1)",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "plimsoll_version",
    "seal_hash",
    "created_at",
    "results",
    "n_evaluated",
    "canon_version"
  ],
  "properties": {
    "plimsoll_version": { "const": "prereg-v1" },
    "canon_version": { "const": "plimsoll-canon-v1" },
    "seal_hash": {
      "type": "string",
      "pattern": "^sha256:[0-9a-f]{64}$"
    },
    "created_at": { "type": "string" },
    "n_evaluated": { "type": "integer", "minimum": 0 },
    "results": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["metric_id", "aggregate", "value"],
        "properties": {
          "metric_id": { "type": "string" },
          "aggregate": {
            "type": "string",
            "enum": [
              "mean", "median", "min", "max",
              "p10", "p50", "p90", "p95",
              "count", "pass_rate"
            ]
          },
          "value": {
            "type": "string",
            "description": "Lexical decimal. MUST be a JSON string."
          }
        }
      }
    }
  }
}
```

If a client submits an attestation containing `attempt` or any other
unknown top-level member, a conforming implementation MUST reject it.

`seal_hash` MUST equal the canonical hash of a previously logged seal.

`results[].value` MUST be a lexical decimal string. Implementations
MUST NOT coerce JSON numbers into `value`.

---

## 8. Attempt ledger

The log stores, for each `seal_hash`, an ordered sequence of accepted
attestations.

1. Attempt numbers are **assigned by the log**, not by the client.
2. The first accepted attestation for a seal receives attempt `1`.
   Each subsequent accepted attestation for that seal receives `n+1`.
3. Numbers are monotonic and have no gaps among **accepted** entries.
   A rejected submission MUST NOT consume a number.
4. A client MUST NOT include `attempt` on the attestation. If present,
   reject.
5. Replaying the same attestation bytes MAY be rejected as a duplicate;
   it MUST NOT be assigned a new attempt number if rejected.
6. Anyone verifying an inclusion proof MUST be able to check the
   assigned attempt number against the log entry. The operator's API
   MUST NOT be the only way to learn the attempt number (the entry
   itself carries it).

---

## 9. Superseding seals

A seal cannot be edited. To change a decision rule after a failed
attempt, the author publishes a **new** seal with:

```json
"supersedes": {
  "seal_hash": "sha256:…",
  "reason": "human-readable reason"
}
```

Rules:

1. `supersedes.seal_hash` MUST be the canonical hash of an existing
   seal. It MUST NOT equal the canonical hash of the new seal (no
   self-supersession).
2. `reason` MUST be non-empty.
3. The superseded seal remains in the log. Attestations against it
   remain. Supersession is an edge, not a delete, not an amendment.
4. No flag, environment variable, or paid tier MAY treat the old
   decision rule as rewritten in place.

---

## 10. Transmission constraint (normative)

A conforming implementation MUST NOT receive, store, or transmit:

- dataset rows or files
- model weights or model files
- prompt text
- model outputs or traces

It MAY receive, store, or transmit digests, metadata (names, counts,
sampling labels, metric ids, lexical decimal result strings, verdicts),
signatures, and log inclusion proofs.

Prompt text and configuration files are hashed locally with
plimsoll-canon-v1. Dataset rows are hashed locally with
plimsoll-dataset-v1. Only the digests appear in seals.

---

## 11. Signing

A **signed seal** is:

```json
{
  "seal": { "…": "the seal object of §4" },
  "signature": "<base64>"
}
```

`signature` is 64 raw Ed25519 signature bytes, encoded as unpadded or
padded Base64 (implementations MUST accept standard Base64). The
signed message is the **plimsoll-canon-v1 canonical bytes** of `seal`
(the prefixed JCS of the seal object), not the `sha256:` string.

Verification: canonicalize `seal`, then `Ed25519.verify(public_key,
canonical_bytes, signature)`. Verification MUST succeed using only
the signed object and a public key; it MUST NOT require the operator's
log.

---

## 12. Conformance checklist

An independent implementation of **prereg-v1** is conforming when it
can demonstrate all of the following.

**Seal**

- [ ] Accepts the example in §4.3 (JSON) and an equivalent YAML encoding.
- [ ] Rejects any unknown top-level member.
- [ ] Rejects `planned_attempts < 1`.
- [ ] Rejects `dataset.n <= 0` or missing `dataset.sha256`.
- [ ] Rejects `decision_rule.precision` outside `1..12`.
- [ ] Rejects an expression that does not parse under §5.
- [ ] Rejects an expression whose `metric_id` is not in `metrics[]`.
- [ ] Computes `CanonicalHash` as §3 plimsoll-canon-v1 over the seal JSON.
- [ ] Ed25519 sign/verify over canonical seal bytes as §11.

**Expression language**

- [ ] Parses the valid examples in §5.3.
- [ ] Rejects every invalid example in §5.3.
- [ ] Lexer treats `>=` as one token (not `>` then `=`).
- [ ] No code path implements `+`, `-` (binary), `*`, `/`, or calls.

**Dataset identity**

- [ ] Implements plimsoll-dataset-v1 as a sorted multiset of
      plimsoll-canon-v1 rows.
- [ ] Reordering rows does not change the digest.
- [ ] Duplicating a row does change the digest.

**Attestation and log**

- [ ] Rejects attestations that include `attempt`.
- [ ] Assigns attempt numbers only on the log, starting at 1 per seal.
- [ ] Stores `supersedes` as a new seal, leaving the old seal intact.

**Privacy**

- [ ] No API accepts dataset bytes, model bytes, prompt text, or outputs.

---

## 13. Test vectors (informative)

Expression parse → OK: `acc.mean >= 0.82`

Expression parse → fail: `acc.mean + 1 >= 0.82`

Nearest-rank: `n=2`, `p=50` → rank `1`.

Decimal (precision 6): `0.82` equals `0.8200000000000001`; `0.82` does
not equal `0.821`.

---

## 14. Defensive publication

This file was deposited as:

**Title:** PLIMSOLL Pre-Registration and Attestation Specification, v1
**License:** CC0-1.0
**Version identifier:** prereg-v1
**Git tag:** v0.1.0-spec
**Date:** 26 August 2026
**DOI (all versions):** 10.5281/zenodo.22107450
**DOI (this version):** 10.5281/zenodo.22107451
**Record:** https://zenodo.org/records/22107451

Archive the public URL of this file in the Internet Archive Wayback Machine.
