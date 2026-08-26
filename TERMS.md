# Terms of use

**Last updated:** 26 August 2026
**Operator:** Gautam Khosla, Canada
**Contact:** the address in [SECURITY.md](SECURITY.md)

These terms cover the public Plimsoll Log at `https://plimsoll.gautamkhosla.com`.
The `plimsoll` software itself is licensed separately: the code under
Apache-2.0 (see [LICENSE](LICENSE)), the specification under CC0-1.0 (see
[SPEC-PREREG.md](SPEC-PREREG.md)). Nothing here restricts those licences.

## The service

The public log is a free, best-effort public good operated by one person. It
has no uptime commitment, no support commitment and no service level
agreement. It may be slow, unavailable, or discontinued.

**It is provided "as is", without warranty of any kind**, express or implied,
including merchantability, fitness for a particular purpose and
non-infringement. To the fullest extent permitted by law, the operator is not
liable for any claim, damage or other liability arising from the service or
its use.

If the service disappearing would be a problem for you, do not depend on it:
run your own log. `plimsolld` ships in this repository, the specification is
CC0, and `plimsoll verify --log <url>` works against any conforming endpoint.
That is a deliberate design property, not a disclaimer. See
[docs/SUCCESSION.md](docs/SUCCESSION.md) for what happens to the signing key
and the log if the operator stops.

## What publishing means

Submissions are appended to a public, append-only, cryptographically verifiable
log and to a public git repository that anyone may clone and mirror.

**Publication is permanent and irreversible.** There is no delete, no edit and
no override — not by flag, configuration, paid tier, or request. Read
[PRIVACY.md](PRIVACY.md) before you publish, in particular the warning about
free-text fields.

By publishing you confirm that you have the right to publish what you submit
and that it contains no personal data, confidential information, or anything
you are not permitted to disclose.

## Acceptable use

Do not use the endpoint to publish unlawful content, to attempt to overwhelm
the service, or to probe or attack the infrastructure. The operator may block
traffic and may decline to append a submission.

Submissions are content-validated: signatures must verify and the payload must
match the published allowlist. A rejected submission is not appended and
consumes no attempt number.

## What this service does not do

We do not interpret your evaluation results, advise on metric selection, or
assess whether your evidence satisfies any regulation, standard, or audit.
Verification establishes that a specific rule was fixed at a specific point in
a published ordering, that specific digests were bound to it, and how many
attempts occurred. It establishes nothing about whether the underlying
experiment matched its description. The limits are set out in
[docs/TECHNICAL-NOTE.md](docs/TECHNICAL-NOTE.md) §4 and
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

Nothing here is legal, compliance, or professional advice.

## Governing law

These terms are governed by the laws of the Province of Ontario and the
federal laws of Canada applicable therein, without regard to conflict of law
rules.

## Changes

Material changes will be noted here with a new date and are recorded in this
file's public git history.
