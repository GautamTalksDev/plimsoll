# Why nobody already does this

This document is the strongest available argument that this mechanism should
**not** exist, written in the objector's voice, followed by what can honestly
be said in reply. Where there is no reply, the text says so.

It is not an IP survey. For what related systems bind and how PLIMSOLL differs
from them by construction, see [PRIOR-ART.md](PRIOR-ART.md).

---

## 1. Normal practice already covers it

**Objection.** Papers already state experimental settings. Repositories already
release configs, seeds, and harness code. Anyone who wants to check a claim
can read the paper and re-run the eval. A cryptographic log adds process
theatre on top of documentation that already answers the question.

**Response.** Documentation records what the author chose to publish. A repo
with one committed result is indistinguishable from a repo whose author
committed one run out of nine. Re-running an evaluation shows whether *you*
can reproduce a number under *your* conditions; it does not show how many
attempts the claimant discarded before publishing. The log does not replace
papers or configs. It answers a different question: whether a named decision
rule was fixed before the attested result, and how many attested attempts
exist against that rule.

---

## 2. Voluntary pre-registration has thin uptake without a mandate

**Objection.** ClinicalTrials.gov worked because journals made registration a
condition of publication. Wherever pre-registration is voluntary, uptake is
thin and the registries fill with empty protocols and abandoned studies. No
conference, journal, buyer, or regulator requires a sealed evaluation rule
before an ML claim is published. Building the log before the mandate is
backwards: the useful artifact follows the rule that makes using it compulsory.

**Response.** That is a real adoption constraint, not a design flaw in the
mechanism. The kill tests in the README exist because of it: if nobody seals,
the project stops. The mechanism can still be useful to a party that wants a
claim a sceptical counterparty can check — a vendor selling into a regulated
buyer, an open evaluation with public attempts — without waiting for an ICMJE
equivalent. It cannot create that demand by existing. Whether demand appears
is an empirical question; [RESULTS.md](../RESULTS.md) records that no field
data exists yet.

---

## 3. Runs before the seal are invisible

**Objection.** Nothing stops someone from exploring freely — many seeds,
prompts, thresholds — and sealing only once they know the shape of the
result. The log then shows a single clean attempt. The failure mode you care
about has already happened, off-camera. You have not closed the window; you
have moved it.

**Response.** There is no full answer to this. Digests are computed on the
author's machine; attempts made before any seal are not logged; a party who
seals only after exploratory runs produces a record that verifies correctly
and understates the search. The mechanism narrows the window in which
undisclosed flexibility can occur after a seal exists. It does not eliminate
pre-seal search, and no mechanism that declines to receive the underlying
evaluation can. Claiming otherwise would be the overstatement this project
refuses.

---

## 4. The incentive is backwards

**Objection.** The party best placed to publish an attempt count is the party
least motivated to. Selective reporting helps the claimant. A tool that makes
failed attempts public asks them to pay a reputational cost for a benefit that
accrues to readers and counterparties. Rational actors will not opt in. The
log stays empty of real evaluations, filled at best with the operator's own
fixtures.

**Response.** The incentive problem is real. The design does not pretend
otherwise: multiple attempts verify as `VERIFIED WITH DISCLOSURES`, not as
failure, precisely so iteration is not punished as misconduct — but publishing
failures still costs more than hiding them. Adoption therefore depends on a
counterparty who demands a seal (a buyer, a reviewer, a grant condition), or
on a claimant who values checkability more than selective silence. Kill tests
KT-1 and KT-3 are the admission that neither may appear. The public log's
current entries are operator fixtures and do not count as evidence that the
incentive has been solved ([RESULTS.md §2a](../RESULTS.md#2a-entries-currently-in-the-public-log)).

---

## 5. Adjacent things people believe already cover this

**Objection.** OSF and registered reports already pre-register analysis plans.
Conference reproducibility checklists already force authors to state seeds and
data availability. Model cards and EvalCards already standardise disclosure of
what was evaluated. Experiment trackers already timestamp every run. You are
rebuilding a thinner version of infrastructure the field already has.

**Response.** Those tools bind *documentation* or *local experiment history*.
They do not, by themselves, put an un-amendable decision rule and a
log-assigned attempt count into a public append-only structure that a third
party can verify offline without trusting the claimant or a single operator.
Registered reports are closest in spirit and still rely on institutional
enforcement rather than cryptographic attempt ledgers. Checklists and cards
improve what is *said*; trackers record what the author *chose to keep*. The
gap this log targets is the absence of a public, claimant-independent count of
attempts against a sealed rule. Whether that gap matters in practice is still
unevaluated — see [RESULTS.md](../RESULTS.md).
