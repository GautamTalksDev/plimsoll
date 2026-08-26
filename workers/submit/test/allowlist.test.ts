import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  assertSubmitShape,
  findForbiddenKey,
  type Json,
} from "../src/index.ts";

describe("assertSubmitShape", () => {
  it("accepts a seal-shaped allowlist body", () => {
    const body: Record<string, Json> = {
      seal_hash: "sha256:" + "a".repeat(64),
      canonical_b64: "e30=",
      submitter_id: "t",
      submitted_at: 1,
      supersedes: "",
      signature_b64: "AA==",
      public_key_b64: "AA==",
    };
    assert.equal(assertSubmitShape(body), null);
  });

  it("rejects an extra top-level field", () => {
    const body: Record<string, Json> = {
      seal_hash: "sha256:" + "a".repeat(64),
      canonical_b64: "e30=",
      submitter_id: "t",
      submitted_at: 1,
      supersedes: "",
      signature_b64: "AA==",
      public_key_b64: "AA==",
      extra: true,
    };
    const err = assertSubmitShape(body);
    assert.ok(err && err.includes("extra"));
  });

  it("accepts an attestation-shaped allowlist body", () => {
    const body: Record<string, Json> = {
      seal_hash: "sha256:" + "a".repeat(64),
      result_digest: "sha256:" + "b".repeat(64),
      verdict: "pass",
      canonical_b64: "e30=",
      signature_b64: "AA==",
    };
    assert.equal(assertSubmitShape(body), null);
  });
});

describe("findForbiddenKey", () => {
  it("rejects nested rows", () => {
    assert.equal(findForbiddenKey({ seal_hash: "x", nest: { rows: [] } }), "rows");
  });

  it("rejects top-level prompt", () => {
    assert.equal(findForbiddenKey({ prompt: "nope" }), "prompt");
  });

  it("allows a clean seal body", () => {
    assert.equal(
      findForbiddenKey({
        seal_hash: "sha256:" + "a".repeat(64),
        canonical_b64: "e30=",
        submitter_id: "t",
        submitted_at: 1,
        supersedes: "",
        signature_b64: "AA==",
        public_key_b64: "AA==",
      }),
      null,
    );
  });
});
