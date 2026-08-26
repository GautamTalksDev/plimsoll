# Static log (CP-10b.1)

`plimsoll-static` turns a `log.sqlite` into a directory of files that a CDN
can serve as the public Plimsoll Log read API. The generator is deterministic:
two runs on the same database produce byte-identical trees (`diff -r`).

```bash
plimsoll-static -db log.sqlite -out ./public -key log-signing.json \
                -base-url https://plimsoll.gautamkhosla.com
```

`-key` accepts the raw Ed25519 private key bytes used by `plimsolld`, the
32-byte public key, or a JSON object with `public_key` / `private_key`
(base64). Only the public half is written to the tree.

## Tree layout

| Path | Contents |
| --- | --- |
| `/checkpoint` | Latest signed tree head (JSON), same shape as logd |
| `/checkpoints/{tree_size}` | Every historical checkpoint (one file per size) |
| `/entries/{idx}` | One Merkle leaf |
| `/entries/index.json` | First page of entries (100 per page); further pages are `index-N.json` |
| `/proof/inclusion/{idx}` | Inclusion proof + latest checkpoint |
| `/proof/consistency/{old}-{new}` | Consistency proofs (see limitation below) |
| `/seal/{urlsafe_hash}/index.json` | Seal record + attempts + verdicts |
| `/seal/{urlsafe_hash}/badge.svg` | Badge (CP-10 semantics; labels XML-escaped) |
| `/seal/{urlsafe_hash}/index.html` | Per-seal HTML (html/template escaped) |
| `/key` | Log public key: PKIX PEM plus raw base64 Ed25519 |
| `/index.html`, `/seals/`, `/spec/`, `/run-your-own/` | Static site (reuses `internal/site`) |
| `/verify/` | Browser WASM verifier assets |
| `/_headers` | Cloudflare Pages cache policy |
| `/_redirects` | Exact-path rewrites for a few HTML routes |

`urlsafe_hash` is the seal digest with `:` percent-encoded (`site.SealPath`),
matching logd URLs.

## Endpoint map (logd ↔ static)

The read surface implemented by `internal/logd` is what clients and
`internal/logfetch` speak. How each endpoint is served from the static tree:

| logd endpoint | Static file | Notes |
| --- | --- | --- |
| `GET /checkpoint` | `/checkpoint` | Identical JSON |
| `GET /entries?from=&to=` | `/entries/index.json` (+ `index-N.json`), `/entries/{idx}` | See **Pagination** |
| `GET /proof/inclusion?idx=` | `/proof/inclusion/{idx}` | Path form preferred; see **Query URLs** |
| `GET /proof/consistency?old=&new=` | `/proof/consistency/{old}-{new}` | Only published→latest; see **Consistency** |
| `GET /seal/{hash}` (JSON) | `/seal/{hash}/index.json` | Prefer `…/index.json` on static hosts that default directories to HTML |
| `GET /seal/{hash}/badge.svg` | same path | Identical SVG |
| `GET /key` | `/key` | PEM + raw base64 (static). logd still serves HTML at `/key` |
| Site HTML (`/`, `/seals`, …) | matching `index.html` files | Escaped via `html/template` |
| `POST /submit` | **not static** | Worker → Actions append (CP-10b.2+). Documented latency applies |

Nothing in this table is silently dropped. Where the static shape differs
from logd's query-string form, clients use the path form (and `logfetch`
already tries path URLs first).

## Known limitations

### Consistency proofs

Files are generated **from every published checkpoint size to the current
tree size only**. The full O(n²) matrix of historical pairs is not written.

A verifier that needs a consistency proof between two unpublished sizes can
recompute it from the published entries (leaf hashes are in `/entries/{idx}`)
using `logmerkle.ConsistencyAuditPath` / `VerifyConsistency`. That is the
intended recovery path; it does not require trusting the operator's server.

### Pagination and arbitrary `/entries?from=&to=`

Static hosting cannot evaluate arbitrary query ranges. The tree exposes:

- every single entry at `/entries/{idx}`
- fixed 100-entry pages at `/entries/index.json`, `/entries/index-1.json`, …

A client that needs `[from, to)` assembles it from those files. `logfetch`
`EntryAt` uses `/entries/{idx}` first.

### Query-string proof URLs

Cloudflare Pages `_redirects` cannot rewrite `/proof/inclusion?idx=3` onto
`/proof/inclusion/3` for arbitrary indices. Use the path form. The reference
client does.

### `/submit`

Write path remains dynamic. Publish latency is one Actions run (typically
30–60s). A sealed digest is not queryable on the CDN until that run finishes
and Pages deploys. Acceptable for pre-registration: evaluation runs take
minutes to hours. CLI `--publish` output and the README must state this.

### Public key HTML vs PEM

logd's `/key` is an HTML page showing base64. The static log's `/key` is the
machine-readable PEM + raw base64 file required by CP-10b.1. HTML key copy
remains available via the site nav only on a self-hosted `plimsolld`.

## Cache headers (`/_headers`)

```
/checkpoint         public, max-age=60
/checkpoints/*      public, max-age=31536000, immutable
/entries/*          public, max-age=31536000, immutable
/proof/*            public, max-age=31536000, immutable
/seal/*             public, max-age=300
```

Historical entries and proofs never change once written. Seal pages and
badges refresh when new attestations land, so they stay short-lived.

## Security notes

- Seal subject names and supersede reasons are attacker-controlled. Every
  HTML and SVG emission goes through escaping (`html/template` / `badge`
  XML escape).
- Output contains digests and metadata only. No dataset rows, prompts, or
  model outputs appear in the tree (enforced by tests).
- The generator never signs. Checkpoints already stored in the DB are
  published as-is. Signing happens at append time (Actions), with the private
  key held only as the plimsoll-log Actions secret (see `docs/SUCCESSION.md`).
