import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from recon_ai import db
from recon_ai.config import load_settings
from recon_ai.control import run_job
from recon_ai.har import MAX_HAR_BYTES, HarError, ingest_har, iter_har_entries
from recon_ai.ingest import read_findings, read_urls
from recon_ai.job import spec_from_settings
from recon_ai.ui import _read_run_post
from recon_ai.view import run_view

from tests.test_phase7 import FixtureAI, fixture_runner

SAMPLE = Path(__file__).parent / "data" / "sample.har"


def _object_har(url):
    return json.dumps(
        {
            "log": {
                "entries": [
                    {
                        "request": {"method": "GET", "url": url, "headers": []},
                        "response": {"status": 200, "headers": [], "content": {}},
                    }
                ]
            }
        }
    )


class HarIngestTests(unittest.TestCase):
    def test_scope_keeps_js_and_cors_and_drops_third_party(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "out"
            (output / "urls").mkdir(parents=True)
            (output / "urls" / "all_urls.txt").write_text("https://example.com/\n", encoding="utf-8")
            stats = ingest_har(SAMPLE, output, "example.com", ["example.com"], [])
            self.assertEqual(stats["skipped"], 1)
            urls = read_urls(output)
            self.assertIn("https://www.example.com/app.js", urls)
            self.assertNotIn("https://cdn.third-party.test/track.js", urls)
            body = "fetch(\"/api/v1/users\");"
            digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
            self.assertTrue((output / "js" / "content" / f"{digest}.js").is_file())
            findings = read_findings(output)
            self.assertEqual(findings[0]["template_id"], "har/cors")
            self.assertEqual(findings[0]["severity"], "high")

    def test_invalid_and_oversize_har_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "out"
            broken = Path(tmp) / "bad.har"
            broken.write_text("{", encoding="utf-8")
            with self.assertRaises(HarError) as ctx:
                ingest_har(broken, output, "example.com")
            self.assertIn("HAR inválido", str(ctx.exception))
            huge = Path(tmp) / "huge.har"
            huge.write_bytes(b"x" * (MAX_HAR_BYTES + 1))
            with self.assertRaises(HarError) as ctx:
                ingest_har(huge, output, "example.com")
            self.assertIn("acima de", str(ctx.exception))

    def test_iter_har_entries_reads_one_object_at_a_time(self):
        entries = list(iter_har_entries(SAMPLE))
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["request"]["url"], "https://www.example.com/app.js")
        extra = Path(tempfile.mkdtemp()) / "keys.har"
        extra.write_text(
            json.dumps({"creator": {"name": "chrome"}, "log": {"entries": [{"request": {"url": "https://example.com/"}}]}}),
            encoding="utf-8",
        )
        found = list(iter_har_entries(extra))
        self.assertEqual(len(found), 1)
        truncated = Path(tempfile.mkdtemp()) / "cut.har"
        truncated.write_text('{"log":{"entries":[{"request":', encoding="utf-8")
        with self.assertRaises(HarError) as ctx:
            list(iter_har_entries(truncated))
        self.assertIn("HAR inválido", str(ctx.exception))


class HarJobTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        scope = self.root / "scopes.txt"
        scope.write_text("example.com\n", encoding="utf-8")
        os.environ["RECON_SCOPE"] = str(scope)
        os.environ["RECON_RESULTS"] = str(self.root)
        os.environ["RECON_DB"] = str(self.root / "recon.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_scan_without_har_skips_phase(self):
        spec = spec_from_settings("example.com", load_settings(None, 20))
        result = run_job(spec, verify=False, runner=fixture_runner, ai_client=FixtureAI())
        self.assertEqual(result["status"], "ok")
        connection = db.connect(self.root / "recon.db")
        view = run_view(connection, result["run_id"])
        har = next(item for item in view["flow"] if item["name"] == "har")
        self.assertEqual(har["status"], "skip")
        self.assertTrue(any(item["name"] == "ai" and item["status"] == "ok" for item in view["flow"]))

    def test_scan_with_har_ingests_and_analyzes_once(self):
        spec = spec_from_settings("example.com", load_settings(None, 20))
        spec["har_path"] = str(SAMPLE)
        client = FixtureAI()
        result = run_job(spec, verify=False, runner=fixture_runner, ai_client=client)
        self.assertEqual(result["status"], "ok")
        connection = db.connect(self.root / "recon.db")
        view = run_view(connection, result["run_id"])
        har = next(item for item in view["flow"] if item["name"] == "har")
        self.assertEqual(har["status"], "ok")
        templates = [
            row["template_id"]
            for row in connection.execute(
                "SELECT template_id FROM finding WHERE run_id = ?",
                (result["run_id"],),
            )
        ]
        self.assertIn("har/cors", templates)
        output = self.root / view["run"]["output_dir"]
        self.assertTrue((output / "har" / "capture.har").is_file())
        self.assertTrue((output / "har" / "a" / "requests.jsonl").is_file())
        self.assertFalse((output / "har" / "b" / "requests.jsonl").is_file())
        checklist = (output / "corr" / "checklist.txt").read_text(encoding="utf-8")
        self.assertIn("Confirmar IDOR com duas contas", checklist)
        self.assertTrue(any(path.suffix == ".js" for path in (output / "js" / "content").glob("*.js")))

    def test_two_accounts_compare_object_ids_without_storing_them(self):
        account_a = self.root / "a.har"
        account_b = self.root / "b.har"
        account_a.write_text(_object_har("https://www.example.com/users/1001"), encoding="utf-8")
        account_b.write_text(_object_har("https://www.example.com/users/1002"), encoding="utf-8")
        spec = spec_from_settings("example.com", load_settings(None, 20))
        spec["har_path"] = str(account_a)
        spec["har_b_path"] = str(account_b)
        result = run_job(spec, verify=False, runner=fixture_runner, ai_client=FixtureAI())
        self.assertEqual(result["status"], "ok")
        connection = db.connect(self.root / "recon.db")
        view = run_view(connection, result["run_id"])
        output = self.root / view["run"]["output_dir"]
        templates = [
            row["template_id"]
            for row in connection.execute(
                "SELECT template_id FROM finding WHERE run_id = ?",
                (result["run_id"],),
            )
        ]
        self.assertIn("corr/idor-cross-account", templates)
        self.assertTrue((output / "har" / "capture-b.har").is_file())
        stored = (output / "har" / "a" / "requests.jsonl").read_text(encoding="utf-8")
        stored += (output / "har" / "b" / "requests.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("users/1001", stored)
        self.assertNotIn("users/1002", stored)
        checklist = (output / "corr" / "checklist.txt").read_text(encoding="utf-8")
        self.assertIn("Pares IDOR entre contas: 1", checklist)
        self.assertNotIn("Confirmar IDOR com duas contas", checklist)

    def test_same_object_id_does_not_emit_cross_account_idor(self):
        account_a = self.root / "a.har"
        account_b = self.root / "b.har"
        account_a.write_text(_object_har("https://www.example.com/users/1001"), encoding="utf-8")
        account_b.write_text(_object_har("https://www.example.com/users/1001"), encoding="utf-8")
        spec = spec_from_settings("example.com", load_settings(None, 20))
        spec["har_path"] = str(account_a)
        spec["har_b_path"] = str(account_b)
        result = run_job(spec, verify=False, runner=fixture_runner, ai_client=FixtureAI())
        self.assertEqual(result["status"], "ok")
        connection = db.connect(self.root / "recon.db")
        templates = [
            row["template_id"]
            for row in connection.execute(
                "SELECT template_id FROM finding WHERE run_id = ?",
                (result["run_id"],),
            )
        ]
        self.assertNotIn("corr/idor-cross-account", templates)
        view = run_view(connection, result["run_id"])
        checklist = (self.root / view["run"]["output_dir"] / "corr" / "checklist.txt").read_text(encoding="utf-8")
        self.assertIn("Pares IDOR entre contas: 0", checklist)

    def test_invalid_har_fails_before_ai(self):
        broken = self.root / "bad.har"
        broken.write_text("{", encoding="utf-8")
        spec = spec_from_settings("example.com", load_settings(None, 20))
        spec["har_path"] = str(broken)
        result = run_job(spec, verify=False, runner=fixture_runner, ai_client=FixtureAI())
        self.assertEqual(result["status"], "failed")
        connection = db.connect(self.root / "recon.db")
        view = run_view(connection, result["run_id"])
        har = next(item for item in view["flow"] if item["name"] == "har")
        self.assertEqual(har["status"], "fail")
        count = connection.execute(
            "select count(*) from ai_result where run_id = ?",
            (result["run_id"],),
        ).fetchone()[0]
        self.assertEqual(count, 0)


class HarUiParseTests(unittest.TestCase):
    def test_multipart_spec_and_har(self):
        boundary = "----reconboundary"
        spec = json.dumps({"target": "example.com", "threads": 20})
        har = SAMPLE.read_bytes()
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="spec"\r\n\r\n'
            f"{spec}\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="har"; filename="c.har"\r\n'
            f"Content-Type: application/json\r\n\r\n"
        ).encode("utf-8") + har + f"\r\n--{boundary}--\r\n".encode("utf-8")

        class Handler:
            def __init__(self):
                self.headers = {
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "Content-Length": str(len(body)),
                }
                self.rfile = io.BytesIO(body)

        parsed, uploaded, uploaded_b = _read_run_post(Handler())
        self.assertEqual(parsed["target"], "example.com")
        self.assertEqual(uploaded, har)
        self.assertIsNone(uploaded_b)


if __name__ == "__main__":
    unittest.main()
