// eval-store submit Worker. Sits behind Cloudflare Access on evals.hamsterwheel.wtf.
// Swaps a runner's Access service token for a 1-hour R2 credential scoped to one run.
// Never deletes a run: runs/ expires by lifecycle rule, retained/ is Russell's to prune.
//
// Bindings: BUCKET (R2, chewcorp-evals). Vars: ACCOUNT_ID, BUCKET_NAME, ACCESS_TEAM_DOMAIN,
// ACCESS_AUD, RUNNERS (JSON: service-token client id -> runner name).
// Secrets: CF_API_TOKEN (R2 parent token), R2_PARENT_ACCESS_KEY_ID (that token's id).

const TTL = 3600;
const NAME = /^[a-z0-9][a-z0-9-]{0,47}$/;
const RUN_ID = /^\d{8}T\d{4}Z-[a-z0-9][a-z0-9-]{0,96}$/;
const SERVER_FIELDS = ["run_id", "runner", "created"];

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

const b64url = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

// Access already checked the token at the edge; re-verify its JWT so a request that
// reaches the Worker another way (workers.dev, a misrouted path) is refused.
async function runnerFor(request, env, fetchCerts = fetch) {
  const jwt = request.headers.get("cf-access-jwt-assertion");
  if (!jwt) return null;
  const [h, p, s] = jwt.split(".");
  if (!s) return null;
  const header = JSON.parse(new TextDecoder().decode(b64url(h)));
  const certs = await (await fetchCerts(`https://${env.ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`)).json();
  const jwk = certs.keys.find((k) => k.kid === header.kid);
  if (!jwk || header.alg !== "RS256") return null;
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64url(s), new TextEncoder().encode(`${h}.${p}`));
  if (!ok) return null;
  const claims = JSON.parse(new TextDecoder().decode(b64url(p)));
  const aud = [].concat(claims.aud);
  if (!aud.includes(env.ACCESS_AUD) || claims.exp * 1000 < Date.now()) return null;
  if (claims.iss !== `https://${env.ACCESS_TEAM_DOMAIN}`) return null;
  return JSON.parse(env.RUNNERS)[claims.common_name] || null;
}

async function mint(env, prefix, permission) {
  const r = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.ACCOUNT_ID}/r2/temp-access-credentials`, {
    method: "POST",
    headers: { authorization: `Bearer ${env.CF_API_TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify({
      bucket: env.BUCKET_NAME,
      parentAccessKeyId: env.R2_PARENT_ACCESS_KEY_ID,
      permission,
      ttlSeconds: TTL,
      prefixes: [prefix],
    }),
  });
  const body = await r.json();
  if (!body.success) throw new Error(`temp credential: ${JSON.stringify(body.errors)}`);
  return {
    bucket: env.BUCKET_NAME,
    endpoint: `https://${env.ACCOUNT_ID}.r2.cloudflarestorage.com`,
    prefix,
    credentials: { ...body.result, region: "auto" },
    expires_in: TTL,
  };
}

// The Worker's own copy of each finished run's manifest. It sits outside every run
// prefix, so a runner's credential (live for an hour after /done) cannot rewrite it,
// and its `prefix` says where the run lives now. A run without one is not finished.
const record = async (env, id) => (await env.BUCKET.get(`_manifests/${id}.json`))?.json();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function sha256Of(env, key) {
  const o = await env.BUCKET.get(key);
  if (!o) return null;
  const ds = new crypto.DigestStream("SHA-256"); // Workers-only; streams, so size is unbounded
  await o.body.pipeTo(ds);
  return hex(await ds.digest);
}

const FILE = /^(?!manifest\.json$)[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/;

async function create(request, env, runner) {
  const { harness, slug, retain = false } = await request.json();
  if (!NAME.test(harness || "") || !NAME.test(slug || "")) return json({ error: "harness and slug: [a-z0-9-], max 48" }, 400);
  const stamp = new Date().toISOString().replace(/[-:]/g, "").slice(0, 13) + "Z";
  const id = `${stamp}-${harness}-${slug}`;
  const prefix = `${retain ? "retained" : "runs"}/${id}/`;
  const exists = json({ error: `run ${id} exists` }, 409);
  if (await env.BUCKET.head(`_manifests/${id}.json`)) return exists;
  // Conditional put: of two concurrent creates of one id, only one gets the marker.
  const open = JSON.stringify({ runner, prefix, created: new Date().toISOString() });
  if (!(await env.BUCKET.put(`_open/${id}`, open, { onlyIf: { etagDoesNotMatch: "*" } }))) return exists;
  try {
    return json({ run_id: id, ...(await mint(env, prefix, "object-read-write")) }, 201);
  } catch (e) {
    await env.BUCKET.delete(`_open/${id}`); // our own marker, so a retry can reuse the id
    throw e;
  }
}

async function done(request, env, runner, id) {
  const open = await env.BUCKET.get(`_open/${id}`);
  if (!open) return json({ error: `run ${id} is not open` }, 404);
  const meta = await open.json();
  if (meta.runner !== runner) return json({ error: `run ${id} belongs to another runner` }, 403);
  const manifest = await request.json();
  if (!Array.isArray(manifest.files) || !manifest.files.length) return json({ error: "manifest has no files" }, 400);
  for (const f of manifest.files) {
    if (typeof f.path !== "string" || !FILE.test(f.path) || !Number.isInteger(f.bytes) || !/^[0-9a-f]{64}$/.test(f.sha256)) {
      return json({ error: `bad file entry ${JSON.stringify(f).slice(0, 200)}` }, 400);
    }
    const o = await env.BUCKET.head(`${meta.prefix}${f.path}`);
    if (!o || o.size !== f.bytes) return json({ error: `${f.path}: missing or not ${f.bytes} bytes` }, 422);
    if ((await sha256Of(env, `${meta.prefix}${f.path}`)) !== f.sha256) return json({ error: `${f.path}: sha256 mismatch` }, 422);
  }
  for (const f of SERVER_FIELDS) delete manifest[f];
  const stamped = { ...manifest, run_id: id, runner, created: meta.created, retain: meta.prefix.startsWith("retained/") };
  await env.BUCKET.put(`${meta.prefix}manifest.json`, JSON.stringify(stamped, null, 2));
  await env.BUCKET.put(`_manifests/${id}.json`, JSON.stringify({ ...stamped, prefix: meta.prefix }));
  await env.BUCKET.delete(`_open/${id}`); // the marker only; run objects are never deleted
  return json(stamped);
}

// Copies the files the finished manifest lists, then flips the record last, so a
// failed copy leaves the run where it was and a retry redoes it.
async function retain(env, id) {
  const rec = await record(env, id);
  if (!rec) return json({ error: `no finished run ${id}` }, 404);
  const to = `retained/${id}/`;
  if (rec.prefix === to) return json({ run_id: id, prefix: to });
  for (const f of rec.files) {
    const body = await env.BUCKET.get(`${rec.prefix}${f.path}`);
    if (!body) return json({ error: `${f.path}: gone from ${rec.prefix}` }, 410);
    // R2 checks the sha256 on write and refuses a file rewritten since /done.
    try {
      await env.BUCKET.put(`${to}${f.path}`, body.body, { httpMetadata: body.httpMetadata, sha256: f.sha256 });
    } catch (e) {
      // Only a confirmed rewrite is a 409; anything else is a storage error worth retrying.
      if ((await sha256Of(env, `${rec.prefix}${f.path}`)) === f.sha256) throw e;
      return json({ error: `${f.path}: changed since /done, not retained` }, 409);
    }
  }
  const { prefix, ...manifest } = { ...rec, retain: true };
  await env.BUCKET.put(`${to}manifest.json`, JSON.stringify(manifest, null, 2));
  await env.BUCKET.put(`_manifests/${id}.json`, JSON.stringify({ ...manifest, prefix: to }));
  return json({ run_id: id, prefix: to });
}

async function read(env, id) {
  const rec = await record(env, id);
  if (!rec) return json({ error: `no finished run ${id}` }, 404);
  for (const f of rec.files) {
    if (!(await env.BUCKET.head(`${rec.prefix}${f.path}`))) return json({ error: `run ${id} has expired` }, 410);
  }
  const { prefix, ...manifest } = rec;
  return json({ run_id: id, manifest, ...(await mint(env, prefix, "object-read-only")) });
}

export async function handle(request, env, fetchCerts) {
  const runner = await runnerFor(request, env, fetchCerts).catch(() => null); // malformed JWT
  if (!runner) return json({ error: "unknown runner" }, 403);
  const { pathname } = new URL(request.url);
  const m = pathname.match(/^\/runs(?:\/([^/]+)(\/[a-z]*)?)?$/);
  if (!m) return json({ error: "not found" }, 404);
  const [, id, action] = m;
  if (!id) return request.method === "POST" ? create(request, env, runner) : json({ error: "method" }, 405);
  if (!RUN_ID.test(id)) return json({ error: "bad run id" }, 400);
  if (request.method === "POST" && action === "/done") return done(request, env, runner, id);
  if (request.method === "POST" && action === "/retain") return retain(env, id);
  if (request.method === "GET" && (action === "/" || action === undefined)) return read(env, id);
  return json({ error: "not found" }, 404);
}

export default { fetch: (request, env) => handle(request, env) };
