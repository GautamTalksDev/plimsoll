# Mirroring the public log

The public Plimsoll Log is a git repository. CDN copies are for convenience;
they are not the only way to hold the history. Anyone can mirror the log and
detect operator equivocation without trusting this project’s machines.

```bash
git clone https://github.com/GautamTalksDev/plimsoll-log
```

You now hold the complete log and its full history. To check that the
operator has not rewritten it:

```bash
git log --oneline            # every append is one commit
git fetch && git status      # a rewritten history fails to fast-forward
```

Replay the SQLite Merkle tree offline:

```bash
plimsoll verify-log --dir ./plimsoll-log
```

`verify-log` recomputes every leaf from stored canonical bytes, rebuilds each
checkpoint root, and verifies every Ed25519 signature against
`keys/log-public.pem`. Hand-editing an entry in a clone makes it fail.

A scheduled workflow in the main plimsoll repository clones the log daily and
runs the same check so a third party can see an independent result in public
Actions logs.
