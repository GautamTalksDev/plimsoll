# Checkpoints (build ledger)

Status for PLIMSOLL build checkpoints. Mark closed only when the Definition of
Done is met with recorded evidence.

---

## CP-10 — Public log service (`plimsolld`)

**Status: superseded for the public log by CP-10b.**

CP-10 delivered `cmd/plimsolld` + `internal/logd` + site/badge. That stack
**remains** the self-hosting reference: anyone running their own log uses it;
tests and releases still cover it.

It is **not** what operates the public Plimsoll Log at
`https://plimsoll.gautamkhosla.com`.
Entries currently there are the operator's own fixtures against a five-row
synthetic dataset; they do not count toward KT-2 (see RESULTS.md §2a).

---

## CP-10b — Serverless static public log

**Status: code complete (CP-10b.0–CP-10b.6); ops hand-steps may remain.**

| Slice | Role |
| --- | --- |
| CP-10b.0 | Offline log signing key + `docs/SUCCESSION.md` (human-only) |
| CP-10b.1 | `plimsoll-static` → CDN tree (`docs/STATIC-LOG.md`) |
| CP-10b.2 | `plimsoll-log` scaffold + append Action (`plimsoll-append`) |
| CP-10b.3 | Cloudflare Worker `POST /submit` (shape only; not trust gate) |
| CP-10b.4 | Async client: 202, `await`, `--wait` |
| CP-10b.5 | Pages + DNS `plimsoll.gautamkhosla.com` (live entries: operator fixtures only; RESULTS.md §2a) |
| CP-10b.6 | `docs/MIRRORING.md`, `plimsoll verify-log`, daily mirror workflow |

**Public path:** Worker → Actions → git (`GautamTalksDev/plimsoll-log`) → Pages.

**Self-host path:** unchanged — `plimsolld` / `internal/logd`.

**Cost of the public path:** $0/month (see README cost table).
