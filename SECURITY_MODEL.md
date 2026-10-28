# eval-store security model

## Scope and evidence

This model covers the whole `chewcorp/eval-store` repository, with no path
exclusions. It describes checked-in code, not verified production state.
The baseline is [eval-store 12e7a17](https://github.com/chewcorp/eval-store/tree/12e7a17).
Infrastructure evidence is [homecode dc20c59](https://github.com/chewcorp/homecode/tree/dc20c59449de6e0e8bba3baf028d40c8bad6bb23),
especially `terraform/cloudflare/evals.tf`, `terraform/README.md`, and its
`SECURITY_MODEL.md`. Homecode is a separate repository and authorization boundary;
using it as evidence does not make it part of an eval-store-only scan.

The [README](README.md) supplies the intended authentication, shared-run access,
credential scope and retention policy. Observed controls below are not acceptance
of additional risk.

## System overview and components

Runners package evaluation outputs locally, authenticate to a Cloudflare Worker
with Access service tokens, and receive one-hour R2 credentials scoped to one run
prefix. They upload directly to private R2. The Worker finalizes an authoritative
manifest outside that prefix. Readers receive read-only credentials and verify
the archive hash before extraction. Retain copies a run to a non-expiring prefix.

| Stable component | Code covered | Boundary and assets |
|---|---|---|
| **Eval Client** | `eval_store.py`, `tests/test_eval_store.py`, `pyproject.toml` | Local filesystem, environment/config, shared artifact records and downloaded archives cross into a credential-bearing CLI. Assets include local files, transcripts and runner credentials. |
| **Submit Worker** | `worker/worker.js`, `worker/worker.test.js` | HTTPS callers cross JWT and runner-registry checks into a bucket-authorized service. It owns creation, finalization, read/retain and authoritative metadata. |
| **R2 Store** | Storage contracts in the Worker/client; homecode bucket/lifecycle resources in `terraform/cloudflare/evals.tf` | Private `chewcorp-evals` bucket: `runs/<id>/`, `retained/<id>/`, `_open/<id>`, `_manifests/<id>.json`. Runner credentials must not reach other run prefixes or authoritative metadata. |
| **Edge and Secrets** | `worker/wrangler.toml`; homecode `terraform/cloudflare/{evals,main,infisical}.tf`, `terraform/README.md` | Access, allowed runner tokens, Worker bindings and Infisical/HCP deployment identities are separate authorization boundaries. Long-lived parent credentials stay Worker-side. |
| **Release Automation** | `.github/workflows/test.yml`, `.github/workflows/release.yml`; homecode release-download/deployment resources | Source/tag permissions, CI actions, release artifacts and the separately pinned deployment determine shipped code. |

## Entry points and reachability

- Intended hostname: `https://evals.hamsterwheel.wtf`, behind Cloudflare Access
  service authentication. Reference Worker config disables `workers.dev`.
  Homecode config provisions the custom domain and disables `workers.dev` and
  preview URLs; effective live routing is unverified.
- `POST /runs`: any mapped runner creates a run, optionally retained, and gets
  read/write credentials for its prefix. IDs combine UTC minute, harness and slug.
- `POST /runs/<id>/done`: requires the creating runner identity, validates listed
  file paths, sizes and streamed SHA-256 hashes, and stamps server identity/time.
- `GET /runs/<id>/`: any mapped runner gets the authoritative manifest and
  read-only credentials; missing listed objects return 410 before minting.
- `POST /runs/<id>/retain`: any mapped runner can retain a finished run. R2 checks
  hashes during copy; the authoritative prefix changes only after copies finish.
  There is no runner-facing deletion route.
- CLI inputs include local run directories, `result.json`/`metadata*.json` artifact
  records, run IDs/URIs, destination paths, `--include` globs and `EVAL_STORE_URL`.
  Access credentials come from environment or `~/.config/evals/env`; when absent,
  the Claude Code web proxy can inject authentication headers.
- Runners contact R2 directly with SigV4-signed requests. The Worker fetches Access
  public keys and signs R2 temporary credentials locally: HS256 claims constrain
  account, bucket, endpoint audience, permissions, prefix and one-hour expiry.
  It does not call the Cloudflare temporary-credential REST endpoint in this
  baseline. Signing authority derives from the bucket-scoped parent token;
  clients receive derived session credentials, not the parent token.

## Assets and attackers

Evaluation transcripts, prompts, outputs and archives may contain secrets:
homecode explicitly gives this as the reason for private storage. Disclosure can
expose credentials beyond eval-store. Long-lived Access tokens, the R2 parent
token, and Infisical/HCP/deployment credentials are sensitive persistent authority.
Temporary session credentials remain sensitive during their lifetime.

Run contents, authoritative manifests, hashes, runner attribution, local client
files, repository records and release assets need integrity. Availability and
storage cost also matter, particularly for retained runs; their relative business
priority is not separately confirmed. A valid manifest/hash does not establish
that a submitting runner is honest.

Relevant attackers include:
- Unauthenticated internet callers, including callers of unintended Worker URLs.
- Malicious or compromised permitted runners, and thieves of their Access tokens.
- Holders of stolen temporary R2 credentials during their validity window.
- Malicious shared artifact records, run inputs or archives consumed by a runner.
- Unauthorized local processes and source/tag/release/CI supply-chain attackers.

Provider or host-admin compromise is a distinct trust dependency, not implicitly
accepted risk. No attacker class is otherwise excluded by operator instruction.

## Existing controls and documented limits

- The Worker verifies Access JWT RS256 signature, issuer, audience, expiry and
  `common_name` membership in `RUNNERS`. Malformed/unmapped tokens are refused.
  A runner name identifies a runner class, not an individual agent seat.
- R2 grants last one hour and constrain object authority to a run prefix. R2 has
  no write-only temporary permission and no early revoke at `/done`: uploaders
  deliberately get `object-read-write`, not upload-only or immediately revoked
  access. This does not authorize access to other prefixes or parent secrets.
- Conditional `_open` creation and a second finished-record check prevent
  reopening a concurrently finalized run. Creator checks, server-stamped fields
  and separate `_manifests` protect metadata. File paths reject `.`/`..` segments.
- Finalization streams object hashes; retention uses checksum-enforced copies.
  The client verifies SHA-256 before extraction and uses `tarfile`'s data filter.
  These controls do not rule out all resource-exhaustion or archive hazards.
- **All permitted runners may read and retain any finished run by design.**
  Only finalization is creator-restricted. Cross-runner read/retain alone is not
  an isolation defect; unauthorized outsiders or access beyond these capabilities
  remain separate threats.
- Homecode creates a bucket-scoped parent token and individual Access service
  tokens for runner classes (`howork2`, `howork3`, `claude-code-web`, `cursor`),
  publishes secrets through Infisical, and binds parent secrets to the Worker.
- `runs/` expires after 30 days; `retained/` persists until human deletion;
  incomplete multipart uploads expire after one day. The Worker never deletes
  run objects. Metadata outside `runs/` does not inherit its expiry rule.
- Tagged release CI runs Python/Node tests and publishes the client, Worker and
  SHA256SUMS. Homecode downloads a pinned Worker artifact and verifies its expected
  hash before deployment. Its reviewed pin is `v0.1.1`; eval-store source includes
  newer local-signing changes. A source merge is not proof of deployed behavior.

## Priority policy, accepted risk and open questions

Protect secret-bearing transcripts, credentials, run/manifest integrity and client
filesystem safety. Apart from the documented capabilities/trade-offs above, no
additional eval-store exclusions or accepted risks have been supplied. Do not
infer acceptance from missing controls or transfer unrelated homecode policies
(such as identity-broker cross-seat access) to this service.

Start finding priorities from the scanner's exploitability and impact assessment.
Change them only where operator policy changes the relevant attacker, asset or
surface. Code-derived emphasis alone is not grounds to raise severity, and a
hard-to-exploit or unverified issue is not raised merely for mentioning secrets.
Judge findings against their scanned revision; a later source fix does not prove
that the scanned revision or live deployment is safe.

Open questions are the relative importance of confidentiality/integrity versus
cost/availability, and whether the operator wants any narrower attacker scope or
additional explicit accepted risks. Until clarified, retain the attackers above.
Optional finding-tag choices remain unconfirmed; components use the stable names
in this model, without inventing ownership or CVE IDs.

This is not a live Cloudflare, Infisical, HCP or runner-host audit. Effective token
scopes/rotation, private bucket settings, network exposure, deployed Worker
version, credential delivery and repository protections need separate evidence.
Update this model when those boundaries or operator policy change.
