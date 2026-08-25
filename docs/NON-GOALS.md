# Non-goals

These are permanent architectural commitments, not backlog items. They are not
to be relaxed by a flag, a setting, a paid tier, or a future roadmap item.

1. We never receive, store or transmit a dataset or a model.
2. We never define, select or bundle an assessment framework.
3. We never compute a quality metric, score or evaluation result.
4. We never combine a computed assessment result with a hash into a
   signed artifact we produced.
5. We are never the only party able to verify an attestation.

Corollaries:

- Digests and metadata only. Prompts and outputs never leave the user's machine.
- The trust path is deterministic and unit-testable. No LLM call, heuristic
  score, or probabilistic classifier belongs in it.
- A sealed decision rule cannot be overridden.
- Verification must work offline, against the artifact and the log inclusion
  proof, without calling our log as the sole authority.
