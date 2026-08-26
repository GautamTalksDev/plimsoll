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

## Dashboard rate-limit rules (required)

Do **not** implement counters in Worker code. Create these under
**Security → WAF → Rate limiting rules** (or **Security → Rate limiting**)
for the zone `gautamkhosla.com`:

### Rule A — burst

| Field | Value |
| --- | --- |
| Name | `plimsoll-submit-burst` |
| If incoming requests match | `(http.request.uri.path eq "/submit")` |
| With the same characteristics | IP |
| Then | Block |
| Period | 1 minute |
| Requests | 10 |
| Mitigation timeout | 60 seconds |
| Response | 429 (optional custom body: `rate limit exceeded`) |

### Rule B — daily

| Field | Value |
| --- | --- |
| Name | `plimsoll-submit-daily` |
| If incoming requests match | `(http.request.uri.path eq "/submit")` |
| With the same characteristics | IP |
| Then | Block |
| Period | 1 day (86400 seconds) |
| Requests | 100 |
| Mitigation timeout | 3600 seconds (or dashboard default) |
| Response | 429 |

Verify by hand: eleven `POST /submit` requests from one IP within a minute
should see the 11th rejected with **429** by Rule A (the Worker never sees it).

Free / included rate-limiting entitlements vary by Cloudflare plan; if the
dashboard will not save a 1-day window, use the longest available period and
document the effective daily ceiling in this file.

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
