#!/usr/bin/env python3
"""eval-store: put eval runs in the chewcorp-evals R2 bucket and get them back.

  eval-store pack <run-dir> --harness H [-o DIR]   write run.tar.gz and manifest.json, offline
  eval-store submit <run-dir> --harness H --slug S [--retain] [--card ID] [--model M]...
                                                   pack, upload, record artifacts {uri, sha256}
                                                   in the run's result.json
  eval-store retain <run-dir|run-id>               copy the run to retained/ (never expires)
  eval-store fetch <run-dir|uri|run-id> [dest]     download, check sha256, unpack

Auth is a Cloudflare Access service token: EVAL_STORE_CLIENT_ID and
EVAL_STORE_CLIENT_SECRET, from the environment or ~/.config/evals/env. With
neither set, no Access headers are sent (Claude Code web's proxy injects them).
The Worker at EVAL_STORE_URL swaps the token for a 1-hour R2 credential scoped
to one run; this client never holds an R2 key.
"""
import argparse
import datetime
import fnmatch
import gzip
import hashlib
import hmac
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

ENV_FILE = pathlib.Path("~/.config/evals/env").expanduser()
TARBALL = "run.tar.gz"
PART = 64 << 20  # multipart above this; R2 parts must be equal-sized except the last


def load_env():
    if ENV_FILE.is_file():
        for line in ENV_FILE.read_text().splitlines():
            key, sep, value = line.strip().partition("=")
            if sep and not key.startswith("#"):
                os.environ.setdefault(key.removeprefix("export ").strip(), value.strip().strip("'\""))


def base_url():
    return os.environ.get("EVAL_STORE_URL", "https://evals.hamsterwheel.wtf").rstrip("/")


def record(run):
    """The small json a run keeps in git: result.json, or metadata*.json (kilo-mms f8)."""
    for f in [run / "result.json", *sorted(run.glob("metadata*.json"))]:
        if f.is_file():
            return f
    return run / "result.json"


def api(method, path, body=None):
    # Cloudflare's Browser Integrity Check refuses urllib's default UA (error 1010)
    headers = {"Content-Type": "application/json", "User-Agent": "eval-store"}
    if os.environ.get("EVAL_STORE_CLIENT_ID"):
        headers["CF-Access-Client-Id"] = os.environ["EVAL_STORE_CLIENT_ID"]
        headers["CF-Access-Client-Secret"] = os.environ.get("EVAL_STORE_CLIENT_SECRET", "")
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base_url() + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        sys.exit(f"eval-store: {method} {path}: {e.code} {e.read().decode(errors='replace')[:500]}")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pack(run, out, include=None):
    """Tar the run's files (all but its record, or only --include globs). Returns sha256."""
    keep = record(run)
    files = sorted(
        p.relative_to(run).as_posix()
        for p in run.rglob("*")
        if p.is_file() and p != keep
        and (not include or any(fnmatch.fnmatch(p.relative_to(run).as_posix(), g) for g in include))
    )
    if not files:
        sys.exit(f"eval-store: {run}: no files to pack")

    def clean(info):  # same bytes in, same sha out
        info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, "", ""
        return info

    with open(out, "wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as gz, tarfile.open(fileobj=gz, mode="w") as tar:
        for f in files:
            tar.add(run / f, arcname=f, filter=clean)
    return sha256_file(out)


def sigv4_headers(method, url, cred, payload_sha, now=None, extra=None):
    """AWS SigV4 headers for one S3 request, region auto (R2)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    amz_date, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    region = cred.get("region", "auto")
    u = urllib.parse.urlsplit(url)
    headers = {"host": u.netloc, "x-amz-content-sha256": payload_sha, "x-amz-date": amz_date, **(extra or {})}
    if cred.get("sessionToken"):
        headers["x-amz-security-token"] = cred["sessionToken"]
    names = sorted(headers)
    query = sorted(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
    canonical = "\n".join([
        method,
        u.path or "/",
        "&".join(f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}" for k, v in query),
        "".join(f"{k}:{headers[k].strip()}\n" for k in names),
        ";".join(names),
        payload_sha,
    ])
    scope = f"{day}/{region}/s3/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = ("AWS4" + cred["secretAccessKey"]).encode()
    for part in (day, region, "s3", "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={cred['accessKeyId']}/{scope}, "
        f"SignedHeaders={';'.join(names)}, Signature={sig}"
    )
    del headers["host"]  # urllib sets it
    return headers


def object_url(grant, name):
    key = urllib.parse.quote(grant["prefix"] + name)
    return f"{grant['endpoint'].rstrip('/')}/{grant['bucket']}/{key}"


def s3(grant, method, url, data=b""):
    """One signed S3 request with an in-memory body. Returns the response body."""
    headers = sigv4_headers(method, url, grant["credentials"], hashlib.sha256(data).hexdigest())
    req = urllib.request.Request(url, data=data if method in ("PUT", "POST") else None, method=method, headers=headers)
    with urllib.request.urlopen(req) as resp:
        return resp.read(), resp.headers


def s3_put(grant, name, path):
    url = object_url(grant, name)
    size = os.path.getsize(path)
    if size <= PART:
        s3(grant, "PUT", url, pathlib.Path(path).read_bytes())
        return
    body, _ = s3(grant, "POST", url + "?uploads")
    upload_id = ET.fromstring(body).findtext("{*}UploadId")
    parts = []
    with open(path, "rb") as f:
        for n, chunk in enumerate(iter(lambda: f.read(PART), b""), 1):
            q = urllib.parse.urlencode({"partNumber": n, "uploadId": upload_id})
            _, headers = s3(grant, "PUT", f"{url}?{q}", chunk)
            parts.append(f"<Part><PartNumber>{n}</PartNumber><ETag>{headers['ETag']}</ETag></Part>")
    done = f"<CompleteMultipartUpload>{''.join(parts)}</CompleteMultipartUpload>".encode()
    s3(grant, "POST", f"{url}?{urllib.parse.urlencode({'uploadId': upload_id})}", done)


def s3_get(grant, name, dest):
    url = object_url(grant, name)
    headers = sigv4_headers("GET", url, grant["credentials"], hashlib.sha256(b"").hexdigest())
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers)) as resp, open(dest, "wb") as f:
        for chunk in iter(lambda: resp.read(1 << 20), b""):
            f.write(chunk)


def parse_uri(uri):
    """<base>/runs/<run-id>/<file> -> (run-id, file)."""
    parts = urllib.parse.urlsplit(uri).path.split("/")
    if len(parts) != 4 or parts[1] != "runs" or any(p in ("", ".", "..") for p in parts[2:]):
        sys.exit(f"eval-store: not an eval-store uri: {uri}")  # result.json is shared data; keep its names out of local paths
    return parts[2], parts[3]


def harness_sha():
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def pack_dir(a, out):
    """Write run.tar.gz and manifest.json into out; return the manifest."""
    tarball = out / TARBALL
    sha = pack(pathlib.Path(a.run), tarball, a.include)
    manifest = {
        "run_id": None,  # the Worker assigns it on submit
        "harness": a.harness,
        "harness_sha": harness_sha(),
        "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "models": a.model,
        "card": a.card,
        "retain": a.retain,
        "files": [{"path": TARBALL, "bytes": tarball.stat().st_size, "sha256": sha}],
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def cmd_pack(a):
    out = pathlib.Path(a.output or f"{pathlib.Path(a.run).name}.pack")
    if out.resolve().is_relative_to(pathlib.Path(a.run).resolve()):
        sys.exit("eval-store: pack output must be outside the run dir")  # else the next pack swallows it
    out.mkdir(parents=True, exist_ok=True)
    m = pack_dir(a, out)
    print(out / TARBALL, m["files"][0]["sha256"])


def cmd_submit(a):
    run = pathlib.Path(a.run)
    with tempfile.TemporaryDirectory() as tmp:
        manifest = pack_dir(a, pathlib.Path(tmp))
        grant = api("POST", "/runs", {"harness": a.harness, "slug": a.slug, "retain": a.retain})
        manifest["run_id"] = grant["run_id"]
        s3_put(grant, TARBALL, pathlib.Path(tmp) / TARBALL)
        api("POST", f"/runs/{grant['run_id']}/done", manifest)
    rec = record(run)
    data = json.loads(rec.read_text()) if rec.exists() else {}
    data["artifacts"] = {"uri": f"{base_url()}/runs/{grant['run_id']}/{TARBALL}", "sha256": manifest["files"][0]["sha256"]}
    rec.write_text(json.dumps(data, indent=2) + "\n")
    print(f"submitted {run} -> {grant['run_id']}")


def cmd_retain(a):
    # The uri names the run, not its prefix, so result.json needs no rewrite after retain.
    run = pathlib.Path(a.run)
    run_id = parse_uri(json.loads(record(run).read_text())["artifacts"]["uri"])[0] if run.is_dir() else a.run
    api("POST", f"/runs/{run_id}/retain", {})
    print(f"retained {run_id}")


def cmd_fetch(a):
    """<run-dir> reads uri and sha256 from its result.json; <uri|run-id> takes sha256 from the Worker."""
    src = pathlib.Path(a.source)
    if src.is_dir():
        art = json.loads(record(src).read_text())["artifacts"]
        (run_id, name), sha = parse_uri(art["uri"]), art["sha256"]
    else:
        run_id, name = parse_uri(a.source) if "://" in a.source else (a.source, TARBALL)
        sha = None
    dest = pathlib.Path(a.dest) if a.dest else src
    if not src.is_dir() and not a.dest:
        sys.exit("eval-store: fetch <uri|run-id> needs a dest")
    grant = api("GET", f"/runs/{run_id}/")
    with tempfile.TemporaryDirectory() as tmp:
        if sha is None:  # the Worker's own copy, not the one in the run prefix
            sha = next(f["sha256"] for f in grant["manifest"]["files"] if f["path"] == name)
        got = pathlib.Path(tmp) / name
        s3_get(grant, name, got)
        if sha256_file(got) != sha:
            sys.exit(f"eval-store: {run_id}/{name}: sha256 mismatch, not unpacked")
        dest.mkdir(parents=True, exist_ok=True)
        with tarfile.open(got) as tar:
            tar.extractall(dest, filter="data")
    print(f"fetched {run_id} -> {dest}")


def main(argv=None):
    load_env()
    p = argparse.ArgumentParser(prog="eval-store", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, func, text in (("pack", cmd_pack, "tar a run and write its manifest, offline"),
                             ("submit", cmd_submit, "pack, upload, record artifacts in result.json")):
        s = sub.add_parser(name, help=text)
        s.add_argument("run")
        s.add_argument("--harness", required=True)
        s.add_argument("--slug", required=name == "submit")
        s.add_argument("--retain", action="store_true")
        s.add_argument("--card", help="Linear id")
        s.add_argument("--model", action="append", default=[])
        s.add_argument("--include", action="append", help="glob of files to pack (repeatable); default all but the record")
        if name == "pack":
            s.add_argument("-o", "--output", help="output dir (default <run>.pack)")
        s.set_defaults(func=func)
    s = sub.add_parser("retain", help="keep a run past the 30-day expiry")
    s.add_argument("run", help="run dir (reads its result.json) or run id")
    s.set_defaults(func=cmd_retain)
    s = sub.add_parser("fetch", help="download, verify and unpack a run")
    s.add_argument("source", help="run dir, uri or run id")
    s.add_argument("dest", nargs="?", help="where to unpack (default: the run dir)")
    s.set_defaults(func=cmd_fetch)
    a = p.parse_args(argv)
    a.func(a)


if __name__ == "__main__":
    main()
