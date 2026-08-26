# Privacy

**Last updated:** 26 August 2026
**Operator:** Gautam Khosla, Canada
**Contact:** the address in [SECURITY.md](SECURITY.md)

This describes the public Plimsoll Log at `https://plimsoll.gautamkhosla.com`
and the `plimsoll` command-line tool. It is a factual description of what the
software does, not a legal opinion.

## The short version

The CLI makes no network request unless you pass `--publish` or `--log-url`.
There is no telemetry, no version check, and no analytics, in the CLI or on
the website. Your datasets, models, prompts and model outputs never leave your
machine, by design and enforced server-side.

Anything you *do* publish is public and permanent. The log is append-only.
**Nothing published to it can ever be deleted, by you or by us.**

## What the CLI sends, and only when you ask it to

Without `--publish`, nothing. With `--publish`, one HTTPS request containing:

| Field | What it is |
| --- | --- |
| `seal_hash` | SHA-256 digest |
| `canonical_b64` | The canonical bytes of your seal or attestation |
| `submitter_id` | **The `subject.name` you chose.** Free text. See the warning below. |
| `submitted_at` | Unix timestamp |
| `supersedes` | A digest, if this seal replaces another |
| `signature_b64`, `public_key_b64` | Your Ed25519 signature and public key |

The receiving endpoint rejects any field outside that list, and rejects any
object at any depth containing a key named `rows`, `raw`, `input`, `output`,
`prompt`, `dataset`, `weights`, `completion` or `messages`. That allowlist is
enforced on the server, so the promise holds even if a client is buggy or
hostile.

Dataset, prompt and configuration digests are computed on your machine. The
underlying files are never transmitted.

## The warning that matters

Your seal's `subject.name`, `analysis_plan` and `exclusions` are free text
that you write, and they are published verbatim, permanently, in a public git
repository.

**Do not put a person's name, an email address, a customer name, or anything
confidential in those fields.** Use a project label. Once appended, an entry
cannot be edited or removed: no flag, no request to us, and no legal demand
can change that, because the log's integrity guarantee is precisely that
history cannot be rewritten. This is the same trade-off Certificate
Transparency makes.

If you publish something you regret, the only available remedy is to issue a
superseding seal with a corrected name. The original remains visible.

## What the website collects

Nothing that we control. The site is static files with no cookies, no
accounts, no analytics, no third-party scripts and no web fonts. The browser
verifier runs entirely in your browser; the file you paste is never uploaded.

Two infrastructure providers process request metadata on our behalf:

- **Cloudflare** serves the site and the `/submit` endpoint. Like any CDN it
  processes connection metadata, including IP addresses, to route and protect
  traffic. See Cloudflare's privacy policy.
- **GitHub** hosts the repositories and runs the workflow that appends to the
  log. See GitHub's privacy statement.

We do not run our own analytics, we do not build profiles, and we do not have
a database of visitors. We do not sell or share data with anyone, because we
do not have any to sell.

## Legal basis and your rights

Where the GDPR or similar law applies, our lawful basis for processing the
connection metadata described above is legitimate interest in operating and
protecting a public service.

You may contact us to ask what is held about you. Be aware of the structural
limit: for anything published to the log, **the right to erasure cannot be
satisfied**, because the log is append-only and mirrored by anyone who has
cloned it. We disclose this before you publish rather than after, which is why
the warning above exists. If that is unacceptable for your use case, run your
own log — `plimsolld` is in this repository and verification works against any
endpoint.

## Changes

Material changes will be noted here with a new date and recorded in the git
history of this file, which is public and append-only in practice.
