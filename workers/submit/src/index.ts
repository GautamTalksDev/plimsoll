/**
 * PLIMSOLL submit Worker — shape check and forwarder only.
 *
 * THIS IS NOT THE TRUST BOUNDARY.
 * Cryptographic verification (Ed25519 signatures, canon_version, seal_hash
 * integrity) happens in the plimsoll-log GitHub Action via plimsoll-append.
 * Anyone who obtains LOG_DISPATCH_TOKEN can call repository_dispatch
 * directly. This Worker only: checks Content-Type and size, enforces the
 * same top-level field allowlist as internal/payload, rejects obvious
 * eval-data key names, and forwards to GitHub. Rate limits are Cloudflare
 * dashboard rules, not application code.
 */

export interface Env {
  LOG_DISPATCH_TOKEN: string;
  /** owner/name, default GautamTalksDev/plimsoll-log */
  LOG_REPO?: string;
}

const MAX_BODY = 256 * 1024;

/** Mirrors internal/payload sealPublishAllowed. */
export const SEAL_ALLOWED = new Set([
  "seal_hash",
  "canonical_b64",
  "submitter_id",
  "submitted_at",
  "supersedes",
  "signature_b64",
  "public_key_b64",
]);

/** Mirrors internal/payload attestPublishAllowed. */
export const ATTEST_ALLOWED = new Set([
  "seal_hash",
  "result_digest",
  "verdict",
  "canonical_b64",
  "signature_b64",
]);

/** Defence-in-depth: never-receive-eval-data key names (any depth). */
export const FORBIDDEN_KEYS = new Set([
  "rows",
  "raw",
  "input",
  "output",
  "prompt",
  "dataset",
  "weights",
  "completion",
  "messages",
]);

export type Json =
  | null
  | boolean
  | number
  | string
  | Json[]
  | { [k: string]: Json };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname !== "/submit") {
      return text(404, "not found");
    }
    if (request.method !== "POST") {
      return text(405, "method not allowed");
    }
    return handleSubmit(request, env);
  },
};

async function handleSubmit(request: Request, env: Env): Promise<Response> {
  const ct = request.headers.get("content-type") || "";
  if (!ct.toLowerCase().startsWith("application/json")) {
    return text(400, "Content-Type must be application/json");
  }

  const buf = await readBodyCapped(request, MAX_BODY);
  if (buf instanceof Response) {
    return buf;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(buf));
  } catch {
    return text(400, "invalid json");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return text(400, "submit body must be a JSON object");
  }
  const top = parsed as Record<string, Json>;

  const shapeErr = assertSubmitShape(top);
  if (shapeErr) {
    return text(400, shapeErr);
  }
  const forbidden = findForbiddenKey(top);
  if (forbidden) {
    return text(400, `forbidden key ${JSON.stringify(forbidden)}`);
  }

  if (!env.LOG_DISPATCH_TOKEN) {
    return text(500, "misconfigured: LOG_DISPATCH_TOKEN missing");
  }
  const repo = env.LOG_REPO || "GautamTalksDev/plimsoll-log";
  const dispatchBody = JSON.stringify({
    event_type: "plimsoll-submit",
    client_payload: { submit: top },
  });
  // GitHub repository_dispatch client_payload budget is ~64 KiB total.
  if (dispatchBody.length > 65000) {
    return text(400, "payload too large for log dispatch");
  }

  const gh = await fetch(`https://api.github.com/repos/${repo}/dispatches`, {
    method: "POST",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${env.LOG_DISPATCH_TOKEN}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "plimsoll-submit-worker",
      "Content-Type": "application/json",
    },
    body: dispatchBody,
  });
  if (gh.status !== 204 && gh.status !== 200) {
    const detail = await gh.text();
    console.error("repository_dispatch failed", gh.status, detail.slice(0, 200));
    return text(502, "log dispatch failed");
  }

  const pathHash = safeSealPath(top.seal_hash);
  const note =
    pathHash.length > 0
      ? `Appended within ~60s. Poll /seal/${pathHash} to confirm inclusion.`
      : "Appended within ~60s. Poll /seal/{hash} to confirm inclusion.";

  // Never 200: the entry is not in the log yet.
  return json(202, { status: "accepted", note });
}

/**
 * seal_hash is attacker-controlled and is echoed back in the 202 note. Only
 * echo it when it matches the digest grammar exactly; otherwise return "" so
 * no submitter-supplied text ever reaches a client's terminal.
 */
export function safeSealPath(v: Json | undefined): string {
  if (typeof v !== "string" || !/^sha256:[0-9a-f]{64}$/.test(v)) {
    return "";
  }
  return v.replace(/:/g, "%3A");
}

/** Strict top-level allowlist; mirrors internal/payload.AssertSubmit. */
export function assertSubmitShape(top: Record<string, Json>): string | null {
  const keys = Object.keys(top);
  const isSeal = Object.prototype.hasOwnProperty.call(top, "public_key_b64");
  const isAttest =
    Object.prototype.hasOwnProperty.call(top, "result_digest") &&
    Object.prototype.hasOwnProperty.call(top, "verdict");

  if (isSeal) {
    for (const k of keys) {
      if (!SEAL_ALLOWED.has(k)) {
        return `forbidden field ${JSON.stringify(k)}`;
      }
    }
    return null;
  }
  if (isAttest) {
    for (const k of keys) {
      if (!ATTEST_ALLOWED.has(k)) {
        return `forbidden field ${JSON.stringify(k)}`;
      }
    }
    return null;
  }
  return "unrecognized submit shape";
}

/**
 * Returns the first forbidden eval-data key name found at any depth, or the
 * sentinel "__too_deep__" past MAX_DEPTH. Untrusted JSON must not be able to
 * drive unbounded recursion, even under the body cap.
 */
export const MAX_DEPTH = 64;

export function findForbiddenKey(v: Json, depth = 0): string | null {
  if (depth > MAX_DEPTH) {
    return "__too_deep__";
  }
  if (v === null || typeof v !== "object") {
    return null;
  }
  if (Array.isArray(v)) {
    for (const item of v) {
      const hit = findForbiddenKey(item, depth + 1);
      if (hit) return hit;
    }
    return null;
  }
  for (const [k, child] of Object.entries(v)) {
    if (FORBIDDEN_KEYS.has(k.toLowerCase())) {
      return k;
    }
    const hit = findForbiddenKey(child, depth + 1);
    if (hit) return hit;
  }
  return null;
}

async function readBodyCapped(
  request: Request,
  max: number,
): Promise<Uint8Array | Response> {
  const cl = request.headers.get("content-length");
  if (cl !== null) {
    const n = Number(cl);
    if (Number.isFinite(n) && n > max) {
      return text(413, "body too large");
    }
  }
  const reader = request.body?.getReader();
  if (!reader) {
    return text(400, "empty body");
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > max) {
      try {
        await reader.cancel();
      } catch {
        /* ignore */
      }
      return text(413, "body too large");
    }
    chunks.push(value);
  }
  if (total === 0) {
    return text(400, "empty body");
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

function text(status: number, message: string): Response {
  return new Response(message + "\n", {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body) + "\n", {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}
