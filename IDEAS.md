
## UX gap: no way to hash a prompt or config file

`seal` computes `dataset.sha256` from `dataset.path` automatically, but
`subject.system_under_test.prompt_sha256` and `config_sha256` must be supplied
as literal `plimsoll-canon-v1` digests. There is no `prompt_path` field and no
`plimsoll hash <file>` command, so a first-time user has to implement RFC 8785
canonicalization themselves to fill in two required fields.

Found while sealing the first real entry on the public log (26 Aug 2026).
A pilot team hits this inside their first five minutes.

Fix: add `plimsoll hash <file>` printing the canonical digest, and/or accept
`prompt_path` / `config_path` in the seal file like `dataset.path`.

## BUG (blocking pilots): seal paths are unreachable over HTTP

`site.SealDir` writes a literal `%3A` into the directory name:

    internal/site/site.go:78  strings.ReplaceAll(hash, ":", "%3A")

Cloudflare Pages percent-decodes the request path once before matching, so a
client requesting `/seal/sha256%3A<hex>/index.json` is looking for a directory
called `sha256:<hex>`, which does not exist. Pages then serves the site's HTML
fallback **with HTTP 200**. Only double-encoding (`%253A`) reaches the file.

Consequences, all confirmed against the live log on 26 Aug 2026:
- `plimsoll seal --publish --wait` times out with exit 4 even though the
  append succeeded, because `logfetch.Client.Seal` polls a path that returns
  HTML and never parses.
- Every seal page, `index.json` and `badge.svg` is unreachable by any normal
  client. The browser verifier and any third party hit the same wall.
- 200 + HTML instead of 404 is the worst form: clients hang instead of erroring.

Fix: stop encoding. Use a path segment with no reserved characters, e.g.
`seal/sha256-<hex>/`, and keep accepting the canonical `sha256:<hex>` form in
the CLI. Update SealDir/SealPath, the badge URL, the site templates, logfetch,
the WASM verifier, docs/STATIC-LOG.md, and add a test asserting the generated
path contains no '%'. The existing seal at idx=0 keeps its old directory;
regenerating the tree produces the new one.

## Pages serves the HTML fallback with HTTP 200 for every unknown path

`/anything-at-all` returns the site's HTML under a 200, not a 404. Nothing is
exposed (only `public/` is deployed), but it means a client cannot distinguish
"not found" from "found" by status code. This is what made the %3A seal-path
bug invisible: the CLI polled a path that did not exist and got 200 + HTML,
so it hung parsing HTML as JSON instead of failing fast.

Mitigation already in place: clients should request the explicit `index.json`
and treat a non-JSON body as an error rather than trusting the status code.
Worth adding a real 404 page and, if Pages allows it, a proper status.
