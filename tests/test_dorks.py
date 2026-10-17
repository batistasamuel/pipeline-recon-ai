import json
import os
import tempfile
import unittest
from pathlib import Path

from recon_ai import db
from recon_ai.config import load_settings
from recon_ai.control import run_job
from recon_ai.dorks import generate_queries, parse_hits
from recon_ai.ingest import read_findings
from recon_ai.job import spec_from_settings
from recon_ai.view import run_view

from tests.test_phase7 import FixtureAI, fixture_runner


class DorkGenerateTests(unittest.TestCase):
    def test_queries_use_site_and_respect_cap(self):
        queries = generate_queries("example.com", [], 3)
        self.assertEqual(len(queries), 3)
        self.assertTrue(all("site:example.com" in item for item in queries))

    def test_tech_fingerprint_adds_extra_query(self):
        fingerprints = [{"url": "https://ci.example.com", "title": "Dashboard [Jenkins]", "tech": ["Jenkins"]}]
        queries = generate_queries("example.com", fingerprints, 24)
        self.assertTrue(any("site:ci.example.com" in item and "jenkins" in item.casefold() for item in queries))

    def test_parse_hits_drops_non_urls(self):
        text = "https://example.com/.env\nnot a url\nhttps://evil.test/x\n"
        hits = parse_hits(text)
        self.assertEqual(hits[0], "https://example.com/.env")


def dork_runner(args, stdout_path, stderr_path):
    joined = " ".join(args)
    if args[0] == "go-dork":
        stderr_path.write_text("", encoding="utf-8")
        stdout_path.write_text("https://example.com/.env\nhttps://cdn.third-party.test/x\n", encoding="utf-8")
        return 0
    if args[0] == "httpx" and "dorks" in joined and "-json" in args:
        stderr_path.write_text("", encoding="utf-8")
        stdout_path.write_text(
            json.dumps({"url": "https://example.com/.env", "status_code": 200, "title": "env"}) + "\n",
            encoding="utf-8",
        )
        return 0
    return fixture_runner(args, stdout_path, stderr_path)


class DorkJobTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "scopes.txt").write_text("example.com\n", encoding="utf-8")
        os.environ["RECON_SCOPE"] = str(self.root / "scopes.txt")
        os.environ["RECON_RESULTS"] = str(self.root)
        os.environ["RECON_DB"] = str(self.root / "recon.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_hits_are_scoped_probed_and_correlated(self):
        spec = spec_from_settings("example.com", load_settings(None, 20))
        result = run_job(spec, verify=False, runner=dork_runner, ai_client=FixtureAI())
        self.assertEqual(result["status"], "ok")
        connection = db.connect(self.root / "recon.db")
        view = run_view(connection, result["run_id"])
        dorks = next(item for item in view["flow"] if item["name"] == "dorks")
        self.assertEqual(dorks["status"], "ok")
        output = self.root / view["run"]["output_dir"]
        hits = (output / "dorks" / "hits.txt").read_text(encoding="utf-8")
        self.assertIn("https://example.com/.env", hits)
        self.assertNotIn("cdn.third-party.test", hits)
        all_urls = (output / "urls" / "all_urls.txt").read_text(encoding="utf-8")
        self.assertIn("https://example.com/.env", all_urls)
        templates = {item["template_id"] for item in read_findings(output)}
        self.assertIn("corr/dork-live-exposure", templates)
        self.assertIn("corr/dork-unknown-to-crawl", templates)
        connection.close()

    def test_disable_dorks_skips_and_keeps_urls(self):
        spec = spec_from_settings("example.com", load_settings(None, 20), disabled=["dorks"])
        result = run_job(spec, verify=False, runner=dork_runner, ai_client=FixtureAI())
        self.assertEqual(result["status"], "ok")
        connection = db.connect(self.root / "recon.db")
        view = run_view(connection, result["run_id"])
        dorks = next(item for item in view["flow"] if item["name"] == "dorks")
        self.assertEqual(dorks["status"], "skip")
        output = self.root / view["run"]["output_dir"]
        all_urls = (output / "urls" / "all_urls.txt").read_text(encoding="utf-8")
        self.assertNotIn("https://example.com/.env", all_urls)
        connection.close()

    def test_shodan_without_key_fails(self):
        spec = spec_from_settings("example.com", load_settings(None, 20))
        spec["tools"]["dorks"]["engine"] = "shodan"
        spec["tools"]["dorks"]["shodan_key"] = "-"
        os.environ.pop("SHODAN_API_KEY", None)
        result = run_job(spec, verify=False, runner=dork_runner, ai_client=FixtureAI())
        self.assertEqual(result["status"], "failed")
        connection = db.connect(self.root / "recon.db")
        view = run_view(connection, result["run_id"])
        dorks = next(item for item in view["flow"] if item["name"] == "dorks")
        self.assertEqual(dorks["status"], "fail")
        count = connection.execute(
            "select count(*) from ai_result where run_id = ?",
            (result["run_id"],),
        ).fetchone()[0]
        self.assertEqual(count, 0)
        connection.close()
