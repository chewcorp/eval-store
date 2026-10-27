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

// Where a run lives now; retained/ wins if a retain copy exists.
async function locate(env, id) {
  for (const prefix of [`retained/${id}/`, `runs/${id}/`]) {
    if ((await env.BUCKET.list({ prefix, limit: 1 })).objects.length) return prefix;
  }
  return null;
}

async function create(request, env, runner) {
  const { harness, slug, retain = false } = await request.json();
  if (!NAME.test(harness || "") || !NAME.test(slug || "")) return json({ error: "harness and slug: [a-z0-9-], max 48" }, 400);
  const stamp = new Date().toISOString().replace(/[-:]/g, "").slice(0, 13) + "Z";
  const id = `${stamp}-${harness}-${slug}`;
  if ((await env.BUCKET.head(`_open/${id}`)) || (await locate(env, id))) return json({ error: `run ${id} exists` }, 409);
  const prefix = `${retain ? "retained" : "runs"}/${id}/`;
  // Kept outside the run prefix so the runner's own credential cannot rewrite it.
  await env.BUCKET.put(`_open/${id}`, JSON.stringify({ runner, prefix, created: new Date().toISOString() }));
  return json({ run_id: id, ...(await mint(env, prefix, "object-read-write")) }, 201);
}

async function done(request, env, runner, id) {
  const open = await env.BUCKET.get(`_open/${id}`);
  if (!open) return json({ error: `run ${id} is not open` }, 404);
  const meta = await open.json();
  if (meta.runner !== runner) return json({ error: `run ${id} belongs to another runner` }, 403);
  const manifest = await request.json();
  if (!Array.isArray(manifest.files) || !manifest.files.length) return json({ error: "manifest has no files" }, 400);
  for (const f of manifest.files) {
    const o = await env.BUCKET.head(`${meta.prefix}${f.path}`);
    if (!o || o.size !== f.bytes) return json({ error: `${f.path}: missing or not ${f.bytes} bytes` }, 422);
  }
  for (const f of SERVER_FIELDS) delete manifest[f];
  const stamped = { ...manifest, run_id: id, runner, created: meta.created, retain: meta.prefix.startsWith("retained/") };
  await env.BUCKET.put(`${meta.prefix}manifest.json`, JSON.stringify(stamped, null, 2));
  await env.BUCKET.delete(`_open/${id}`); // the marker only; run objects are never deleted
  return json(stamped);
}

async function retain(env, id) {
  const prefix = await locate(env, id);
  if (!prefix) return json({ error: `no run ${id}` }, 404);
  if (prefix.startsWith("retained/")) return json({ run_id: id, prefix });
  let cursor;
  do {
    const page = await env.BUCKET.list({ prefix, cursor });
    for (const o of page.objects) {
      const name = o.key.slice(prefix.length);
      if (name === "manifest.json") continue;
      const body = await env.BUCKET.get(o.key);
      await env.BUCKET.put(`retained/${id}/${name}`, body.body, { httpMetadata: body.httpMetadata });
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  const old = await env.BUCKET.get(`${prefix}manifest.json`);
  const manifest = old ? await old.json() : { run_id: id };
  await env.BUCKET.put(`retained/${id}/manifest.json`, JSON.stringify({ ...manifest, retain: true }, null, 2));
  return json({ run_id: id, prefix: `retained/${id}/` });
}

async function read(env, id) {
  const prefix = await locate(env, id);
  if (!prefix) return json({ error: `no run ${id}` }, 404);
  return json({ run_id: id, ...(await mint(env, prefix, "object-read-only")) });
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
