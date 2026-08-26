# Prior art

This document is the day-one IP position. PLIMSOLL is a pre-registration log
for evaluation decision rules, plus independently verifiable attestations of
later attempts against those rules. It does not run evaluations and does not
see eval data.

Every date in the table precedes 2022-05-12.

| System | What it binds | What it proves | Date | How PLIMSOLL differs |
| --- | --- | --- | --- | --- |
| RFC 6962 Certificate Transparency | Issued (or pre-issued) X.509 certificates, as submitted to a public Merkle log | That a certificate was logged in an append-only tree, so mis-issuance is detectable by monitors and auditable via inclusion and consistency proofs | 2013-06 | CT logs a certificate *after* issuance. It does not pre-register a decision rule, and it does not record attempts against that rule. PLIMSOLL seals the rule *before* results exist, then logs attested attempts (including failures). CT binds a certificate; PLIMSOLL binds a sealed decision rule and digests the operator never sees. |
| in-toto attestations / DSSE | Supply-chain steps: materials and products of authorized functionaries, wrapped in a signed envelope (in-toto metadata; later DSSE) | That a software artifact was produced according to a declared layout by authorized parties, and that the signed statement has not been altered | 2019-08 (in-toto, USENIX Security); 2020-09 (DSSE repo); 2021-03-03 (DSSE protocol v1.0.0) | in-toto attests a *build/supply-chain* layout. It does not pre-commit an evaluation decision rule or detect post-hoc flexibility in reported eval numbers. PLIMSOLL's payload is a sealed rule plus later attempts against it. PLIMSOLL never attests a quality score it computed. |
| Sigstore + Rekor | Signatures over software artifacts (and related metadata) submitted to a public transparency log | That a given signature existed at a point in time in a publicly auditable log | 2021-03-09 (Sigstore announced); 2021-06-17 (Rekor v0.2.0) | Rekor is *ex post* signature transparency: it records that a signature existed. It does not require a prior sealed decision rule that later results are checked against. PLIMSOLL's log is of seals (ex ante) and attested attempts (ex post) with a deterministic, un-overridable decision. |
| SLSA provenance | Build provenance: who built an artifact, from what source, with what builder | Integrity properties of the *build* process (provenance of a software artifact), at a stated SLSA level | 2021-06-16 | SLSA is a supply-chain integrity framework for how software is built. It does not seal an evaluation protocol or verdict. PLIMSOLL is not a build-integrity framework and does not issue provenance about models or datasets beyond user-supplied digests. |
| Clinical trial pre-registration (ClinicalTrials.gov; ICMJE mandatory registration policy) | Trial protocol and outcomes declared in a public registry before (or as a condition of) enrollment and publication | That endpoints and analysis plans were declared independently of the eventual results, reducing outcome switching and publication bias | 2000-02-29 (ClinicalTrials.gov launch); 2005-07-01 (ICMJE policy effective for trials starting enrollment) | Closest analogue: declare the rule before seeing the data. ClinicalTrials.gov is an institutional registry, not a cryptographic log; verification is by journals and regulators, not by an offline third party holding only the artifact. PLIMSOLL takes pre-registration into a Merkle log with sealed, un-amendable decision rules and independently verifiable attestations, for evaluations the user ran with their own tools, without ever receiving the dataset or the model. |

## Notes on dates

- RFC 6962, *Certificate Transparency*, IETF, June 2013.
- Torres-Arias et al., *in-toto: Providing farm-to-table guarantees for bits and bytes*, USENIX Security, August 2019. Dead Simple Signing Envelope (DSSE) repository created 2020-09-01; protocol v1.0.0 dated 2021-03-03.
- Linux Foundation announcement of Sigstore, 2021-03-09. Rekor v0.2.0, 2021-06-17.
- Google, *Introducing SLSA, an End-to-End Framework for Supply Chain Integrity*, 2021-06-16.
- NIH launch of ClinicalTrials.gov, 2000-02-29. ICMJE mandatory prospective registration as a condition of publication, effective 2005-07-01.

## Defensive publication

The specification [SPEC-PREREG.md](../SPEC-PREREG.md) is versioned
`prereg-v1` and licensed CC0-1.0 so a third party can reimplement it
without reading this repository's Go code.

Deposited 26 August 2026:

- **Title:** PLIMSOLL Pre-Registration and Attestation Specification, v1
- **License:** CC0-1.0
- **Git tag:** `v0.1.0-spec`
- **DOI (all versions):** 10.5281/zenodo.22107450
- **DOI (this version):** 10.5281/zenodo.22107451
- **Record:** https://zenodo.org/records/22107451
- **Wayback archive:** *pending*

