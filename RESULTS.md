# RESULTS.md — Kill-test evaluation (CP-14)

**Status:** Incomplete. CP-13 (three-team, eight-week pilot) was not run. This file records that fact honestly. No numbers below are invented, refitted, or backfilled from synthetic fixtures.

**Spec / canon:** evaluation intended against SPEC-PREREG **prereg-v1** and canon version as shipped at evaluation time. Spec changes, if any, are future work (v2); v1 is not rewritten to fit outcomes.

**KT-2 threshold (unchanged from README / CP-0):** across at least 100 sealed evaluations, if fewer than **10%** show either more than one attested attempt against the same seal or a superseding seal issued after a failed attempt → publish and stop.

---

## 1. Method

| Field | Value |
| --- | --- |
| Teams | None recruited. CP-13 required exactly three teams (AI vendor → regulated buyer; mid-size internal platform; OSS model/agent with published benchmarks). No written consents exist. |
| Period | Not started. Required duration: 8 weeks of hand recording after integration. |
| Harnesses | None observed in a pilot. Intended coverage: whatever each team already ran (e.g. DeepEval, Inspect, custom). |
| Spec | prereg-v1 |
| Canon | As implemented in-tree at pilot time (not applied; no pilot seals). |
| Data sources | No lab notebook, no override log, no aggregate pilot statistics. Fixture / CI seals are **not** counted toward KT-2. |

Offer that would have applied (for the record): free integration by us; teams keep everything; publish only aggregates unless named consent in writing. That offer was not made.

---

## 2. KT-2

**N = 0** sealed evaluations from the CP-13 pilot. **X = 0** seals with >1 attempt or a post-failure supersede (undefined rate; no sample).

No confidence interval is reported: there is no pilot sample.

**KT-2: NOT EVALUABLE — N=0 sealed evaluations from the required pilot (minimum N=100); the 10% bar from the README at CP-0 is unchanged and is neither PASS nor FAIL.**

Until N≥100 from consented pilot (or later public-log) seals, do not treat absence of retries as evidence that post-hoc flexibility is rare, and do not treat this document as a kill-test result.

---

## 2a. Entries currently in the public log

The public log at `https://plimsoll.gautamkhosla.com` went live on 26 August
2026 and contains seals published by the operator while testing the deployment
end to end. As of that date: 3 seals, 2 attestations.

**None of these count toward KT-2.** They are the operator's own fixtures,
authored and verified by the same person, against a five-row synthetic dataset.
They demonstrate that the mechanism runs; they are evidence of nothing about
whether post-hoc flexibility occurs in practice. Counting them would be the
exact behaviour this project exists to make visible.

The first entry a reader should treat as data is a seal published by a party
other than the operator.

---

## 3. Override log

**Count:** 0 override requests recorded.

No team asked for an override. No verbatim wording exists. No reply wording exists.

This section is empty on purpose. It is the section that would be most valuable after a real pilot; fabricating quotes would make this document worthless.

---

## 4. INVALID analysis

**INVALID rate:** unknown (no pilot runs).

**Predicted dominant causes (hypothesis only — not observed):** mismatched `n` / sample-size fields vs harness output; harness or adapter version drift between seal and attestation.

No empirical confirmation or refutation. Do not cite this section as a finding.

---

## 5. Limitations

- **Harness coverage:** none measured.
- **Pilot self-selection:** no pilot; selection bias not estimable.
- **Small N:** N=0; far below the KT-2 requirement of ≥100 sealed evaluations (and CP-13 DoD of ≥30 seals / ≥100 attestations).
- **Consent:** zero named teams with written consent; no team may be named in any publication derived from this file.
- **Self-selection of timing:** CP-14 was executed before CP-13 produced data; this RESULTS.md is a process checkpoint, not a study.

---

## Disposition

Do not adjust the 10% threshold. Do not report fixture or demo numbers as pre-registered pilot results.

When CP-13 completes with written consents, replace this document with a full RESULTS.md that:

1. Names only consenting teams (or keeps them anonymous).
2. States **PASS** or **FAIL** for KT-2 in one sentence against the same 10% bar.
3. Publishes the override log with verbatim request and response wording.
4. Reports INVALID rates and causes from the hand notebook.

If KT-2 then **FAIL**s: publish that negative result, keep the public log running as a public good, archive with a clear README, and move on. That remains a successful integrity outcome.
