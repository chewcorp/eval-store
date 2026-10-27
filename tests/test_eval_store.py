import datetime
import hashlib
import http.server
import json
import os
import pathlib
import re
import sys
import tempfile
import threading
import unittest
import urllib.parse
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import eval_store  # noqa: E402


class SigV4(unittest.TestCase):
    def test_aws_get_object_example(self):
        # AWS SigV4 docs, "Example: GET Object" (examplebucket/test.txt, Range bytes=0-9).
        cred = {"accessKeyId": "AKIAIOSFODNN7EXAMPLE", "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "region": "us-east-1"}
        h = eval_store.sigv4_headers(
            "GET", "https://examplebucket.s3.amazonaws.com/test.txt", cred,
            hashlib.sha256(b"").hexdigest(),
            now=datetime.datetime(2013, 5, 24, tzinfo=datetime.timezone.utc),
            extra={"range": "bytes=0-9"},
        )
        self.assertTrue(h["authorization"].endswith("Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"))

    def test_session_token_is_signed(self):
        cred = {"accessKeyId": "a", "secretAccessKey": "b", "sessionToken": "t"}
        h = eval_store.sigv4_headers("PUT", "https://x/b/k", cred, "0" * 64)
        self.assertEqual(h["x-amz-security-token"], "t")
        self.assertIn("x-amz-security-token", h["authorization"])


class Pack(unittest.TestCase):
    def test_excludes_record_and_is_reproducible(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = pathlib.Path(tmp, "run")
            (run / "sub").mkdir(parents=True)
            (run / "result.json").write_text("{}")
            (run / "export.json").write_text("x")
            (run / "sub" / "session1.txt").write_text("y")
            (run / "sub" / "result.json").write_text("{}")  # only the top-level record stays out
            a = eval_store.pack(run, pathlib.Path(tmp, "a.tgz"))
            os.utime(run / "export.json", (0, 12345))
            b = eval_store.pack(run, pathlib.Path(tmp, "b.tgz"))
            self.assertEqual(a, b)
            import tarfile
            with tarfile.open(pathlib.Path(tmp, "a.tgz")) as t:
                self.assertEqual(t.getnames(), ["export.json", "sub/result.json", "sub/session1.txt"])
            only = eval_store.pack(run, pathlib.Path(tmp, "c.tgz"), include=["session*.txt", "sub/*"])
            self.assertNotEqual(only, a)


class Fake(http.server.BaseHTTPRequestHandler):
    """Worker API plus S3 object store, in one, without auth."""
    objects, calls, parts, manifests = {}, [], {}, {}

    def log_message(self, *a):
        pass

    def body(self):
        return self.rfile.read(int(self.headers.get("Content-Length", 0)))

    def reply(self, obj, status=200):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def grant(self, run_id, prefix):
        return {"run_id": run_id, "bucket": "b", "endpoint": f"http://127.0.0.1:{self.server.server_port}/s3",
                "prefix": prefix, "credentials": {"accessKeyId": "k", "secretAccessKey": "s", "sessionToken": "t"}}

    def do_POST(self):
        if self.path.startswith("/s3/"):
            return self.multipart()
        body = json.loads(self.body() or b"{}")
        Fake.calls.append((self.path, body, self.headers.get("CF-Access-Client-Id")))
        if self.path == "/runs":
            run_id = f"20261027T2300Z-{body['harness']}-{body['slug']}"
            return self.reply(self.grant(run_id, f"runs/{run_id}/"), 201)
        if self.path.endswith("/done"):
            Fake.manifests[body["run_id"]] = body
        return self.reply({"ok": True})

    def multipart(self):
        key, _, query = self.path.partition("?")
        data = self.body()
        if query == "uploads":
            Fake.parts[key] = {}
            out = b"<InitiateMultipartUploadResult xmlns='http://s3.amazonaws.com/doc/2006-03-01/'><UploadId>u/1+=</UploadId></InitiateMultipartUploadResult>"
        else:
            assert b"<PartNumber>2</PartNumber>" in data
            Fake.objects[key] = b"".join(v for _, v in sorted(Fake.parts.pop(key).items()))
            out = b"<CompleteMultipartUploadResult/>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_PUT(self):
        assert "x-amz-security-token" in self.headers["Authorization"]
        key, _, query = self.path.partition("?")
        if query:
            q = dict(urllib.parse.parse_qsl(query))
            assert q["uploadId"] == "u/1+="
            Fake.parts[key][int(q["partNumber"])] = self.body()
            self.send_response(200)
            self.send_header("ETag", f'"{q["partNumber"]}"')
            self.send_header("Content-Length", "0")
            return self.end_headers()
        Fake.objects[key] = self.body()
        self.reply({})

    def do_GET(self):
        if self.path.startswith("/runs/"):
            run_id = self.path.split("/")[2]
            return self.reply({**self.grant(run_id, f"runs/{run_id}/"), "manifest": Fake.manifests[run_id]})
        data = Fake.objects[self.path]
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.env = dict(os.environ)
        os.environ.update(EVAL_STORE_URL=f"http://127.0.0.1:{self.server.server_port}", EVAL_STORE_CLIENT_ID="cid", EVAL_STORE_CLIENT_SECRET="sec")

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        os.environ.clear()
        os.environ.update(self.env)

    def test_submit_retain_fetch(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = pathlib.Path(tmp, "run")
            run.mkdir()
            (run / "result.json").write_text(json.dumps({"score": 3}))
            (run / "export.json").write_text("raw")
            eval_store.main(["submit", str(run), "--harness", "rule-ablation", "--slug", "sm-ccp", "--model", "m1"])
            rec = json.loads((run / "result.json").read_text())
            self.assertEqual(rec["score"], 3)
            run_id = "20261027T2300Z-rule-ablation-sm-ccp"
            self.assertEqual(rec["artifacts"]["uri"], f"{os.environ['EVAL_STORE_URL']}/runs/{run_id}/run.tar.gz")
            self.assertEqual(rec["artifacts"]["sha256"], hashlib.sha256(Fake.objects[f"/s3/b/runs/{run_id}/run.tar.gz"]).hexdigest())
            done = [c for c in Fake.calls if c[0].endswith("/done")][-1]
            self.assertEqual(done[1]["models"], ["m1"])
            self.assertEqual(done[2], "cid")

            eval_store.main(["retain", str(run)])
            self.assertEqual(Fake.calls[-1][0], f"/runs/{run_id}/retain")

            (run / "export.json").unlink()
            eval_store.main(["fetch", str(run)])
            (run / "export.json").unlink()
            other = pathlib.Path(tmp, "by-id")
            eval_store.main(["fetch", run_id, str(other)])
            self.assertEqual((other / "export.json").read_text(), "raw")

            rec["artifacts"]["sha256"] = "0" * 64
            (run / "result.json").write_text(json.dumps(rec))
            with self.assertRaises(SystemExit):
                eval_store.main(["fetch", str(run)])
            self.assertFalse((run / "export.json").exists(), "a bad sha256 unpacks nothing")

    def test_multipart_upload(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(eval_store, "PART", 1024):
            run = pathlib.Path(tmp, "run")
            run.mkdir()
            (run / "big.bin").write_bytes(os.urandom(3000))
            eval_store.main(["submit", str(run), "--harness", "h", "--slug", "big"])
            sha = json.loads((run / "result.json").read_text())["artifacts"]["sha256"]
            self.assertEqual(hashlib.sha256(Fake.objects["/s3/b/runs/20261027T2300Z-h-big/run.tar.gz"]).hexdigest(), sha)

    def test_pack_writes_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = pathlib.Path(tmp, "run")
            run.mkdir()
            (run / "export.json").write_text("raw")
            out = pathlib.Path(tmp, "out")
            eval_store.main(["pack", str(run), "--harness", "h", "--card", "CCP-1", "-o", str(out)])
            m = json.loads((out / "manifest.json").read_text())
            self.assertEqual(m["files"][0]["sha256"], eval_store.sha256_file(out / "run.tar.gz"))
            self.assertEqual((m["card"], m["retain"], m["run_id"]), ("CCP-1", False, None))
            self.assertNotIn("runner", m)
            with self.assertRaises(SystemExit):
                eval_store.main(["pack", str(run), "--harness", "h", "-o", str(run / "out")])


if __name__ == "__main__":
    unittest.main()
