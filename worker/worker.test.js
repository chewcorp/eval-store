import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { handle } from "./worker.js";

const sha = (v) => createHash("sha256").update(v).digest("hex");

// Workers' crypto.DigestStream, which Node lacks.
globalThis.crypto.DigestStream = class extends WritableStream {
  constructor() {
    const h = createHash("sha256");
    let done;
    super({ write: (c) => void h.update(c), close: () => done(h.digest().buffer) });
    this.digest = new Promise((r) => (done = r));
  }
};

const stream = (v) => new Response(v).body;
const text = async (v) => (v instanceof ReadableStream ? new Response(v).text() : v);

const enc = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");

const { publicKey, privateKey } = await crypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true,
  ["sign", "verify"],
);
const jwk = { ...(await crypto.subtle.exportKey("jwk", publicKey)), kid: "k1" };
const certs = async () => new Response(JSON.stringify({ keys: [jwk] }));

async function jwt(claims) {
  const head = `${enc({ alg: "RS256", kid: "k1" })}.${enc(claims)}`;
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, new TextEncoder().encode(head));
  return `${head}.${Buffer.from(sig).toString("base64url")}`;
}

function bucket() {
  const m = new Map();
  const obj = (v) => ({ body: stream(v), httpMetadata: {}, json: async () => JSON.parse(v) });
  return {
    m,
    head: async (k) => (m.has(k) ? { size: String(m.get(k)).length } : null),
    get: async (k) => (m.has(k) ? obj(m.get(k)) : null),
    put: async (k, v, opts) => {
      if (opts?.onlyIf?.etagDoesNotMatch === "*" && m.has(k)) return null;
      v = await text(v);
      if (opts?.sha256 && sha(v) !== opts.sha256) throw new TypeError("checksum mismatch");
      m.set(k, v);
      return {};
    },
    delete: async (k) => m.delete(k),
    list: async ({ prefix, limit }) => ({
      objects: [...m.keys()].filter((k) => k.startsWith(prefix)).slice(0, limit).map((key) => ({ key })),
      truncated: false,
    }),
  };
}

const env = () => ({
  BUCKET: bucket(),
  ACCOUNT_ID: "acct",
  BUCKET_NAME: "chewcorp-evals",
  ACCESS_TEAM_DOMAIN: "team.cloudflareaccess.com",
  ACCESS_AUD: "aud1",
  RUNNERS: JSON.stringify({ "cid-howork2.access": "howork2", "cid-cursor.access": "cursor" }),
  CF_API_TOKEN: "t",
  R2_PARENT_ACCESS_KEY_ID: "parent",
});

const minted = [];
globalThis.fetch = async (url, init) => {
  minted.push(JSON.parse(init.body));
  return new Response(JSON.stringify({ success: true, result: { accessKeyId: "a", secretAccessKey: "s", sessionToken: "x" } }));
};

const claims = (cn, extra = {}) => ({
  aud: ["aud1"], iss: "https://team.cloudflareaccess.com", common_name: cn, exp: Date.now() / 1000 + 60, ...extra,
});

async function call(e, method, path, body, cn = "cid-howork2.access", extra) {
  const headers = { "cf-access-jwt-assertion": await jwt(claims(cn, extra)) };
  const r = await handle(new Request(`https://evals.hamsterwheel.wtf${path}`, { method, headers, body: body && JSON.stringify(body) }), e, certs);
  return [r.status, await r.json()];
}

test("refuses missing, foreign-audience, expired and unknown tokens", async () => {
  const e = env();
  const r = await handle(new Request("https://x/runs", { method: "POST" }), e, certs);
  assert.equal(r.status, 403);
  assert.equal((await call(e, "POST", "/runs", {}, "cid-howork2.access", { aud: ["other"] }))[0], 403);
  assert.equal((await call(e, "POST", "/runs", {}, "cid-howork2.access", { exp: 1 }))[0], 403);
  assert.equal((await call(e, "POST", "/runs", {}, "nobody"))[0], 403);
});

test("submit, done, retain, read", async () => {
  const e = env();
  const [s, grant] = await call(e, "POST", "/runs", { harness: "rule-ablation", slug: "sm-ccp" });
  assert.equal(s, 201);
  assert.match(grant.run_id, /^\d{8}T\d{4}Z-rule-ablation-sm-ccp$/);
  assert.equal(grant.prefix, `runs/${grant.run_id}/`);
  assert.deepEqual(minted.at(-1).prefixes, [grant.prefix]);
  assert.equal(minted.at(-1).permission, "object-read-write");
  assert.equal((await call(e, "POST", "/runs", { harness: "rule-ablation", slug: "sm-ccp" }))[0], 409);

  e.BUCKET.m.set(`${grant.prefix}run.tar.gz`, "tar");
  assert.equal((await call(e, "POST", `/runs/${grant.run_id}/done`, { runner: "forged", files: [] }, "cid-cursor.access"))[0], 403);
  const files = [{ path: "run.tar.gz", bytes: 3, sha256: sha("tar") }];
  assert.equal((await call(e, "POST", `/runs/${grant.run_id}/done`, { files: [{ ...files[0], sha256: sha("tab") }] }))[0], 422, "same size, wrong hash");
  for (const bad of [{ path: "manifest.json", bytes: 3, sha256: "a".repeat(64) }, { path: 7, bytes: 3 }, { path: "run.tar.gz", bytes: "3", sha256: "a".repeat(64) }]) {
    assert.equal((await call(e, "POST", `/runs/${grant.run_id}/done`, { files: [bad] }))[0], 400);
  }
  assert.equal((await call(e, "POST", `/runs/${grant.run_id}/retain`, {}))[0], 404, "an open run cannot be retained");
  assert.equal((await call(e, "GET", `/runs/${grant.run_id}/`))[0], 404, "an open run cannot be read");
  assert.equal((await call(e, "POST", `/runs/${grant.run_id}/done`, { files: [{ path: "run.tar.gz", bytes: 9, sha256: "a".repeat(64) }] }))[0], 422);
  assert.equal((await call(e, "POST", `/runs/${grant.run_id}/done`, { files: [{ path: "nope", bytes: 3, sha256: "a".repeat(64) }] }))[0], 422);
  const [d, manifest] = await call(e, "POST", `/runs/${grant.run_id}/done`, { runner: "forged", models: ["m"], files });
  assert.equal(d, 200);
  assert.equal(manifest.runner, "howork2");
  assert.equal(manifest.retain, false);
  assert.ok(!e.BUCKET.m.has(`_open/${grant.run_id}`));

  const [r] = await call(e, "POST", `/runs/${grant.run_id}/retain`, {}, "cid-cursor.access");
  assert.equal(r, 200);
  assert.equal(e.BUCKET.m.get(`retained/${grant.run_id}/run.tar.gz`), "tar");
  assert.equal(JSON.parse(e.BUCKET.m.get(`retained/${grant.run_id}/manifest.json`)).retain, true);
  assert.ok(e.BUCKET.m.has(`runs/${grant.run_id}/run.tar.gz`), "retain copies; it never deletes");

  // A runner overwriting the prefix copy after /done does not change what readers trust.
  e.BUCKET.m.set(`retained/${grant.run_id}/manifest.json`, JSON.stringify({ files: [] }));
  const [g, read] = await call(e, "GET", `/runs/${grant.run_id}/`);
  assert.deepEqual(read.manifest.files, files);
  assert.equal(g, 200);
  assert.equal(read.prefix, `retained/${grant.run_id}/`);
  assert.equal(minted.at(-1).permission, "object-read-only");
});

test("retain at submit writes straight to retained/", async () => {
  const [, grant] = await call(env(), "POST", "/runs", { harness: "kilo", slug: "f8", retain: true });
  assert.equal(grant.prefix, `retained/${grant.run_id}/`);
});

test("rejects bad names and run ids", async () => {
  const e = env();
  assert.equal((await call(e, "POST", "/runs", { harness: "../x", slug: "a" }))[0], 400);
  assert.equal((await call(e, "GET", "/runs/..%2Fruns/"))[0], 400);
});

test("a failed mint frees the id; a concurrent create gets 409", async () => {
  const e = env();
  const real = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ success: false, errors: ["boom"] }));
  await assert.rejects(call(e, "POST", "/runs", { harness: "h", slug: "s" }));
  globalThis.fetch = real;
  const [ok] = await call(e, "POST", "/runs", { harness: "h", slug: "s" });
  assert.equal(ok, 201);
  assert.equal((await call(e, "POST", "/runs", { harness: "h", slug: "s" }, "cid-cursor.access"))[0], 409);
});

test("retain refuses a file rewritten after /done; GET on an expired run is 410", async () => {
  const e = env();
  const [, grant] = await call(e, "POST", "/runs", { harness: "h", slug: "x" });
  e.BUCKET.m.set(`${grant.prefix}run.tar.gz`, "tar");
  assert.equal((await call(e, "POST", `/runs/${grant.run_id}/done`, { files: [{ path: "run.tar.gz", bytes: 3, sha256: sha("tar") }] }))[0], 200);
  e.BUCKET.m.set(`${grant.prefix}run.tar.gz`, "bad"); // the runner's credential is still live
  assert.equal((await call(e, "POST", `/runs/${grant.run_id}/retain`, {}))[0], 409);
  assert.ok(!e.BUCKET.m.has(`retained/${grant.run_id}/run.tar.gz`));
  e.BUCKET.m.set(`${grant.prefix}run.tar.gz`, "tar");
  const put = e.BUCKET.put;
  e.BUCKET.put = async () => { throw new Error("R2 down"); };
  await assert.rejects(call(e, "POST", `/runs/${grant.run_id}/retain`, {}), /R2 down/, "a storage error is not a 409");
  e.BUCKET.put = put;
  e.BUCKET.m.delete(`${grant.prefix}run.tar.gz`); // lifecycle expiry
  assert.equal((await call(e, "GET", `/runs/${grant.run_id}/`))[0], 410);
});
