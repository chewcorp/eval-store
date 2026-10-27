# eval-store

Eval runs go in one private R2 bucket, `chewcorp-evals`. `runs/<run-id>/`
expires after 30 days; `retained/<run-id>/` is kept. Runners never hold an R2
key: they present a Cloudflare Access service token to the submit Worker on
`evals.hamsterwheel.wtf`, which returns a 1-hour R2 credential scoped to that
one run. Design: [CPB-114](https://linear.app/chewcorp/issue/CPB-114) and the
eval run storage proposal linked there.

| Path | What |
|---|---|
| `eval_store.py` | `eval-store` client CLI, Python stdlib only |
| `worker/worker.js` | Submit Worker. homecode deploys a pinned release |

## Client

```bash
pip install git+https://github.com/chewcorp/eval-store@v0.1.0
# or one file: gh release download v0.1.0 -R chewcorp/eval-store -p eval_store.py
```

```bash
eval-store submit runs/2026-10-27-sm-ccp --harness rule-ablation --slug sm-ccp --model gpt-5 --card CCP-123
eval-store retain runs/2026-10-27-sm-ccp      # or a run id
eval-store fetch runs/2026-10-27-sm-ccp       # or: fetch <uri|run-id> <dest>
eval-store pack runs/2026-10-27-sm-ccp --harness rule-ablation   # offline: run.tar.gz + manifest.json
```

`submit` tars every file in the run dir except its record (`result.json`, or
`metadata*.json` for kilo-mms f8; narrow with `--include GLOB`), uploads it,
and writes `artifacts: {uri, sha256}` into the record: the same field kilo-mms
`runs.sh` writes. The uri names the run, not its prefix, so it stays valid
after `retain`. `fetch` refuses to unpack on a sha256 mismatch.

Auth: `EVAL_STORE_CLIENT_ID` and `EVAL_STORE_CLIENT_SECRET` (the Access service
token), from the environment or `~/.config/evals/env` (mode 0600, `KEY=value`
lines). With neither set the client sends no Access headers, for Claude Code
web where the proxy injects them. `EVAL_STORE_URL` overrides the endpoint.

## Worker

| Route | Does |
|---|---|
| `POST /runs` `{harness, slug, retain}` | Run id `<UTC yyyymmddThhmmZ>-<harness>-<slug>`; read-write credential for `runs/<id>/` or `retained/<id>/` |
| `POST /runs/<id>/done` manifest | Checks each listed file exists at its size, writes `manifest.json`, stamps `runner` from the Access identity |
| `POST /runs/<id>/retain` | Copies `runs/<id>/` to `retained/<id>/`, sets `retain: true`. Any runner |
| `GET /runs/<id>/` | Read-only credential for wherever the run lives (retained wins) |

The Worker re-verifies the Access JWT (`Cf-Access-Jwt-Assertion`) and maps its
`common_name` (the service token's client id) to a runner name through
`RUNNERS`. It never deletes a run. R2 temporary credentials offer no write-only
permission, so a submit credential is `object-read-write` on its one prefix.
Configuration is in `worker/wrangler.toml`; secrets `CF_API_TOKEN` and
`R2_PARENT_ACCESS_KEY_ID` are set at deploy, never in this repo.

## Tests

```bash
python3 -m unittest discover -s tests
cd worker && node --test
```

A `v*` tag runs both and publishes `eval_store.py`, `worker/worker.js` and
`SHA256SUMS` as release assets.
