# Submit Worker

Cloudflare Worker for `POST https://plimsoll.gautamkhosla.com/submit`.

**This Worker is not the trust boundary.** It is a shape check and a forwarder.
Signature verification, `canon_version` checks, and the field allowlist that
matters for integrity run in the `plimsoll-log` Action (`plimsoll-append`).
Rate limiting is configured in the Cloudflare dashboard, not in this source.

Source of truth for the allowlist: `internal/payload` in the main plimsoll repo.
Keep the sets in `src/index.ts` in sync when that package changes.

## What it does

1. Accepts only `POST /submit` with `Content-Type: application/json`.
2. Caps the body at **256 KiB**.
3. Parses JSON; rejects any top-level field outside the seal or attestation
   publish allowlist (mirrors `internal/payload`).
4. Rejects any object (any depth) whose keys include: `rows`, `raw`, `input`,
   `output`, `prompt`, `dataset`, `weights`, `completion`, `messages`.
5. `POST`s `repository_dispatch` (`plimsoll-submit`) to
   `GautamTalksDev/plimsoll-log` with `client_payload.submit` set to the body.
6. Responds **202** with
   `{"status":"accepted","note":"Appended within ~60s. Poll /seal/…"}`.
   Never 200 — the entry is not in the log yet.

All other methods → **405**. All other paths → **404**.

## Deploy

Requires Node 20+, a Cloudflare account that already serves
`gautamkhosla.com`, and a fine-grained GitHub PAT with `contents: write`
on `GautamTalksDev/plimsoll-log` only.

```bash
cd workers/submit
npm install
npx wrangler login

# PAT used only to call repository_dispatch (not the log signing key)
npx wrangler secret put LOG_DISPATCH_TOKEN

npx wrangler deploy
```

`wrangler.toml` already binds route
`plimsoll.gautamkhosla.com/submit` on zone `gautamkhosla.com`. Cloudflare
Pages continues to serve every other path from the `plimsoll-log` static tree.
If the route conflicts with a Pages catch-all, prefer a Worker route with
higher specificity on `/submit` only (Workers routes win over Pages for the
matched path when configured that way in the dashboard).

Confirm:

```bash
curl -i -X POST https://plimsoll.gautamkhosla.com/submit \
  -H 'Content-Type: application/json' \
  --data-binary @seal-submit.json
# expect HTTP/2 202 and a plimsoll-log commit within ~60s
```

## Rate limiting — what is and is not in place

**Measured, not assumed:** a Cloudflare rate-limiting rule matching
`http.request.uri.path eq "/submit"` was created on the free plan, set to
Block at 10 requests / 10 seconds by IP, and **did not fire**. Twenty-five
parallel `POST /submit` requests all returned 400 from the Worker and the
rule's Events counter stayed at 0. A Worker route handles the request before
free-plan WAF rate limiting evaluates it, so the rule matches on paper and
never sees the traffic. The rule is left in place, inert, in case this
changes on a paid plan.

Do not claim rate limiting as a control until an Events count above zero has
been observed.

### The limits that do exist

| Limit | Value | Enforced by |
| --- | --- | --- |
| Worker requests | 100k/day, hard stop | Cloudflare free tier |
| Appends | ~1/min, serialised | Actions `concurrency: plimsoll-log-append` |
| Body size | 256 KiB | Worker, streaming cap |
| Dispatch size | 65,000 bytes | Worker, before `repository_dispatch` |
| Integrity | Ed25519 + allowlist | `plimsoll-append` in the Action |

### The residual exposure

An attacker sending well-shaped but cryptographically invalid payloads cannot
write to the log — `plimsoll-append` rejects them and a rejected submission
consumes no attempt number. They can, however, consume GitHub Actions minutes
on the public repo. This is accepted for v1. If it is ever exercised, the
mitigation is to move the shape check into the Worker's dispatch decision or
require a submitter token.

## Secrets

| Name | Where | Purpose |
| --- | --- | --- |
| `LOG_DISPATCH_TOKEN` | Worker secret | Fine-grained PAT, `contents: write` on `plimsoll-log` only |
| `LOG_SIGNING_KEY` | **Not here** | Lives only on the `plimsoll-log` Actions secret |

## Local check

```bash
npm test
npm run typecheck
```
