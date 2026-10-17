import json
import os
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from pathlib import Path

from recon_ai import db
from recon_ai.ui import make_server
from recon_ai.view import report, run_view


class ReadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.environ["RECON_RESULTS"] = str(self.root)
        self.connection = db.connect(self.root / "recon.db")
        self.first = db.new_run(self.connection, "example.com", "one", 20)
        self.second = db.new_run(self.connection, "example.com", "two", 20)
        db.finish_run(self.connection, self.first, "ok")
        db.finish_run(self.connection, self.second, "failed")
        db.replace_run_details(
            self.connection,
            self.first,
            [
                {
                    "run_id": self.first,
                    "name": "report",
                    "status": "ok",
                    "exit_code": 0,
                    "duration_s": 1,
                    "stderr_path": "",
                    "detail": "resumo",
                }
            ],
            [("host", "a.example.com"), ("forbidden", "https://a.example.com")],
            ["https://a.example.com/"],
            [(self.first, "high", "Example", "https://a.example.com", "example-info")],
        )
        db.save_delta(
            self.connection,
            self.first,
            None,
            [{"entity": "asset", "change": "entered", "key": "a.example.com", "after": "host"}],
        )
        finding_id = self.connection.execute(
            "SELECT id FROM finding WHERE run_id = ?",
            (self.first,),
        ).fetchone()[0]
        db.save_ai_results(
            self.connection,
            self.first,
            [
                (
                    "classification",
                    "ollama",
                    "qwen2.5:7b",
                    json.dumps(
                        {
                            "items": [
                                {
                                    "finding_id": finding_id,
                                    "decision": "keep",
                                    "reason": "SQLi no login.",
                                }
                            ]
                        }
                    ),
                ),
                ("routes", "ollama", "qwen2.5:7b", json.dumps({"routes": [{"path": "/login"}]})),
            ],
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_run_view_reads_status_delta_and_routes(self):
        view = run_view(self.connection, self.first)
        self.assertEqual(view["run"]["status"], "ok")
        self.assertEqual(view["phases"][0]["name"], "report")
        self.assertEqual(view["urls"], 1)
        self.assertEqual(view["delta"][0]["key"], "a.example.com")
        self.assertEqual(view["routes"][0]["path"], "/login")
        self.assertEqual(view["classification"]["items"][0]["decision"], "keep")
        self.assertEqual(view["classification"]["items"][0]["name"], "Example")
        self.assertEqual(view["ai"][0]["provider"], "ollama")
        kinds = {item["name"]: item["count"] for item in view["assets"]}
        self.assertEqual(kinds["forbidden"], 1)

    def test_report_filters_kind_and_severity(self):
        by_kind = report(self.connection, kind="forbidden")
        self.assertEqual(by_kind["assets"]["total"], 1)
        self.assertEqual(by_kind["assets"]["rows"][0]["value"], "https://a.example.com")
        by_severity = report(self.connection, severity="info")
        self.assertEqual(by_severity["findings"]["total"], 0)
        by_high = report(self.connection, severity="high")
        self.assertEqual(by_high["findings"]["rows"][0]["template_id"], "example-info")

    def test_http_serves_runs_and_a_filtered_report(self):
        server = make_server(self.root / "recon.db", "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as response:
                page = response.read().decode("utf-8")
            self.assertIn("Recon — Controle", page)
            self.assertIn('id="lang"', page)
            self.assertIn("Análise da IA", page)
            self.assertIn('id="start"', page)
            self.assertIn('querySelector("#start").disabled = scanRunning', page)
            self.assertIn("icon-danger", page)
            self.assertIn("ui.delete_confirm", page)
            self.assertIn('const row = document.createElement("tr")', page)
            self.assertIn('tr("ui.delete")', page)
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/runs") as response:
                runs = json.loads(response.read().decode("utf-8"))
            self.assertEqual({run["status"] for run in runs}, {"ok", "failed"})
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/runs/{self.first}") as response:
                detail = json.loads(response.read().decode("utf-8"))
            self.assertEqual(detail["classification"]["items"][0]["decision"], "keep")
            self.assertEqual(detail["classification"]["items"][0]["reason"], "SQLi no login.")
            self.assertEqual(detail["routes"][0]["path"], "/login")
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/api/report?kind=host"
            ) as response:
                body = json.loads(response.read().decode("utf-8"))
            self.assertEqual(body["assets"]["total"], 1)
            self.assertEqual(body["assets"]["rows"][0]["kind"], "host")
            self.assertEqual(detail.get("drafts"), [])
        finally:
            server.shutdown()

    def test_view_and_api_expose_drafts(self):
        from recon_ai.catalog import cluster_key
        from recon_ai.drafts import write_draft

        os.environ["RECON_RESULTS"] = str(self.root)
        output = self.root / "one"
        output.mkdir(parents=True, exist_ok=True)
        key = cluster_key("corr/dangling-cname", "https://gone.example.com", "reportable")
        write_draft(
            output,
            {"cluster_key": key, "class": "reportable", "count": 1},
            [
                {
                    "severity": "high",
                    "name": "CNAME órfão",
                    "matched_at": "https://gone.example.com",
                    "template_id": "corr/dangling-cname",
                    "class": "reportable",
                    "cluster_key": key,
                    "evidence": {"cwe": "CWE-284"},
                }
            ],
            {
                "title": "Takeover",
                "summary": "resumo",
                "impact": "impacto",
                "steps": ["resolva o CNAME"],
                "evidence_notes": "dns",
            },
            "pt-BR",
        )
        view = run_view(self.connection, self.first)
        self.assertEqual(view["drafts"][0]["title"], "Takeover")
        self.assertEqual(view["drafts"][0]["status"], "draft")
        server = make_server(self.root / "recon.db", "127.0.0.1", 0, self.root)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/runs/{self.first}") as response:
                detail = json.loads(response.read().decode("utf-8"))
            self.assertEqual(detail["drafts"][0]["cluster_key"], key)
            encoded = urllib.parse.quote(key, safe="")
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/api/runs/{self.first}/drafts/{encoded}"
            ) as response:
                body = json.loads(response.read().decode("utf-8"))
            self.assertIn("CWE-284", body["markdown"])
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/runs/{self.first}/drafts/{encoded}",
                data=json.dumps({"status": "ready"}).encode("utf-8"),
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req) as response:
                marked = json.loads(response.read().decode("utf-8"))
            self.assertEqual(marked["status"], "ready")
        finally:
            server.shutdown()


if __name__ == "__main__":
    unittest.main()
