# REPLACE BEFORE GOING LIVE

`log-public.pem` in this scaffold is a throwaway placeholder generated so the empty tree builds.

1. Generate the real key offline (see plimsoll `docs/SUCCESSION.md` / CP-10b.0).
2. Overwrite this file with the PKIX PEM of the **public** half only.
3. Put the private half (base64 of 64 raw bytes) in Actions secret `LOG_SIGNING_KEY`.
4. Regenerate `public/` with `plimsoll-static -key keys/log-public.pem` so `/key` matches.
5. Never commit the private half.
