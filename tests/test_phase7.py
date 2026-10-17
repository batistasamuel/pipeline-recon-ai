import json
import os
import re
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from recon_ai import db
from recon_ai.config import load_settings
from recon_ai.control import ControlError, build_spec, run_job, stop_run
from recon_ai.export import render_export
from recon_ai.job import JobError, normalize_spec, spec_from_settings, tool_catalog
from recon_ai.parse import names_from_text, urls_for_domain
from recon_ai.phases import first_incomplete
from recon_ai.pipeline import Pipeline
from recon_ai.ai import INPUT_TOKEN_BUDGET
from recon_ai import pace as pace_mod
from recon_ai.ui import SCAN_LOCK, make_server
from recon_ai.view import run_view


def setUpModule():
    pace_mod.SKIP_WAIT = True


def tearDownModule():
    pace_mod.SKIP_WAIT = False


class FixtureAI:
    def complete_with_usage(self, prompt):
        if "Classifique cada finding" in prompt:
            ids = [int(item) for item in re.findall(r"id=(\d+)", prompt)]
            return {
                "result": {
                    "items": [
                        {"finding_id": item, "decision": "keep", "reason": "finding do fixture."}
                        for item in ids
                    ]
                },
                "prompt_eval_count": 10,
                "eval_count": 8,
                "done_reason": "stop",
            }
        if "evidence_notes" in prompt:
            return {
                "result": {
                    "title": "rascunho",
                    "summary": "resumo do fixture.",
                    "impact": "impacto do fixture.",
                    "steps": ["abra a URL"],
                    "evidence_notes": "evidencia do fixture.",
                },
                "prompt_eval_count": 10,
                "eval_count": 8,
                "done_reason": "stop",
            }
        return {
            "result": {"routes": [{"path": "/api/v1/users"}]},
            "prompt_eval_count": 10,
            "eval_count": 5,
            "done_reason": "stop",
        }

FIX = Path(__file__).parent / "fixtures"


def fixture_runner(args, stdout_path, stderr_path):
    stderr_path.write_text("", encoding="utf-8")
    joined = " ".join(args)
    name = "assetfinder" if args[0] == "timeout" else args[0]
    if name == "subfinder":
        text = (FIX / "subfinder.txt").read_text(encoding="utf-8")
    elif name == "amass":
        text = (FIX / "amass.txt").read_text(encoding="utf-8")
    elif name == "curl" and "crt.sh" in joined:
        text = (FIX / "crtsh.json").read_text(encoding="utf-8")
    elif name == "curl":
        text = (FIX / "app.js").read_text(encoding="utf-8")
    elif name == "dnsx" and "-cname" in args:
        text = ""
    elif name == "dnsx" and "wildcard_name.txt" in joined:
        text = ""
    elif name == "dnsx":
        text = (FIX / "dns.txt").read_text(encoding="utf-8")
    elif name == "httpx" and "-json" in args:
        text = (FIX / "http.jsonl").read_text(encoding="utf-8")
    elif name == "httpx":
        text = "https://www.example.com/app.js\n"
    elif name == "katana":
        text = (FIX / "urls.txt").read_text(encoding="utf-8")
    elif name == "nuclei" and ("har_nuclei" in joined or "takeover_hosts.txt" in joined):
        text = ""
    elif name == "nuclei":
        text = (FIX / "nuclei.jsonl").read_text(encoding="utf-8")
    else:
        text = ""
    stdout_path.write_text(text, encoding="utf-8")
    return 0


class SpecTests(unittest.TestCase):
    def test_default_spec_is_valid(self):
        spec = normalize_spec({"target": "example.com"})
        self.assertEqual(spec["in_scope"], ["example.com"])
        self.assertFalse(spec["cloud"])
        self.assertFalse(spec["verify"])
        self.assertEqual(spec["ai_delay_ms"], 2000)
        self.assertEqual(spec["cloud_mode"], "sequential")
        self.assertTrue(spec["tools"]["nuclei"]["enabled"])
        self.assertEqual(spec["tools"]["katana"]["depth"], 3)
        catalog = tool_catalog()
        self.assertGreaterEqual(len(catalog), 8)
        for item in catalog:
            for key in ("what", "input", "output", "place", "correlation"):
                self.assertTrue(item["help"][key].strip(), item["name"])

    def test_invalid_target_and_unknown_tool(self):
        with self.assertRaises(JobError):
            normalize_spec({"target": "../etc"})
        with self.assertRaises(JobError):
            normalize_spec({"target": "example.com", "tools": {"nmap": {"enabled": True}}})

    def test_nuclei_requires_httpx(self):
        with self.assertRaises(JobError):
            normalize_spec({"target": "example.com", "tools": {"httpx": {"enabled": False}}})

    def test_dorks_requires_httpx(self):
        with self.assertRaises(JobError) as ctx:
            normalize_spec({
                "target": "example.com",
                "tools": {"httpx": {"enabled": False}, "nuclei": {"enabled": False}},
            })
        self.assertIn("dorks", str(ctx.exception))

    def test_skip_is_complete_for_resume(self):
        rows = [{"name": name, "status": "skip" if name != "report" else "ok"} for name in (
            "subdomains", "dns", "http", "urls", "dorks", "js", "nuclei", "report", "har", "correlate", "ai"
        )]
        self.assertIsNone(first_incomplete(rows))


class ScopeListTests(unittest.TestCase):
    def test_out_scope_drops_host_and_url(self):
        names = names_from_text(
            "www.example.com\nadmin.example.com\n",
            "example.com",
            ["example.com"],
            ["admin.example.com"],
        )
        self.assertIn("www.example.com", names)
        self.assertNotIn("admin.example.com", names)
        urls = urls_for_domain(
            ["https://www.example.com/a", "https://admin.example.com/x"],
            "example.com",
            ["example.com"],
            ["admin.example.com"],
        )
        self.assertEqual(urls, ["https://www.example.com/a"])


class PipelineJobTests(unittest.TestCase):
    def test_disabled_source_is_not_called(self):
        called = []

        def runner(args, stdout_path, stderr_path):
            called.append(args[0] if args[0] != "timeout" else args[2])
            return fixture_runner(args, stdout_path, stderr_path)

        settings = spec_from_settings("example.com", load_settings(None, 20), disabled=["amass", "waybackurls"])
        from recon_ai.job import settings_from_spec

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "out"
            pipeline = Pipeline("example.com", settings_from_spec(settings), output, {}, runner)
            self.assertEqual(pipeline.run(), 0)
            self.assertNotIn("amass", called)
            self.assertNotIn("waybackurls", called)
            self.assertIn("subfinder", called)

    def test_running_phase_is_written_before_tools(self):
        seen = {}

        def runner(args, stdout_path, stderr_path):
            if not seen:
                text = (self.output / "phases.tsv").read_text(encoding="utf-8")
                seen["tsv"] = text
            return fixture_runner(args, stdout_path, stderr_path)

        with tempfile.TemporaryDirectory() as tmp:
            self.output = Path(tmp) / "out"
            pipeline = Pipeline("example.com", load_settings(None, 20), self.output, {}, runner)
            self.assertEqual(pipeline.run(), 0)
            self.assertIn("subdomains\trunning", seen["tsv"])

    def test_stop_marks_cancelled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            connection = db.connect(root / "recon.db")
            spec = spec_from_settings("example.com", load_settings(None, 20))
            from recon_ai.job import settings_from_spec

            run_id = db.new_run(connection, "example.com", "out", 20, spec)
            started = threading.Event()

            def runner(args, stdout_path, stderr_path):
                stdout_path.write_text("", encoding="utf-8")
                stderr_path.write_text("", encoding="utf-8")
                started.set()
                deadline = time.time() + 5
                while time.time() < deadline:
                    if db.cancel_requested(connection, run_id):
                        break
                    time.sleep(0.05)
                return 0

            pipeline = Pipeline(
                "example.com",
                settings_from_spec(spec),
                root / "out",
                {},
                runner,
                connection,
                run_id,
            )
            thread = threading.Thread(target=pipeline.run)
            thread.start()
            self.assertTrue(started.wait(2))
            db.request_cancel(connection, run_id)
            thread.join(5)
            self.assertTrue(pipeline.cancelled)
            text = (root / "out" / "phases.tsv").read_text(encoding="utf-8")
            self.assertIn("cancelled", text)


class ControlTests(unittest.TestCase):
    def test_run_job_refuses_target_outside_declared_scope(self):
        spec = normalize_spec({"target": "example.com", "in_scope": ["other.com"]})
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["RECON_SCOPE"] = str(Path(tmp) / "scopes.txt")
            Path(os.environ["RECON_SCOPE"]).write_text("example.com\n", encoding="utf-8")
            with self.assertRaises(ControlError) as ctx:
                run_job(spec, dry_run=True, verify=False)
            self.assertEqual(ctx.exception.code, 3)

    def test_run_job_dry_run_and_execute(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scope = root / "scopes.txt"
            scope.write_text("example.com\n", encoding="utf-8")
            os.environ["RECON_SCOPE"] = str(scope)
            os.environ["RECON_RESULTS"] = str(root)
            os.environ["RECON_DB"] = str(root / "recon.db")
            spec = spec_from_settings("example.com", load_settings(None, 20))
            plan = run_job(spec, dry_run=True, verify=False)
            self.assertEqual(plan["status"], "dry_run")
            self.assertIn(" ai", " " + plan["plan"])
            result = run_job(spec, verify=False, runner=fixture_runner, ai_client=FixtureAI())
            self.assertEqual(result["status"], "ok")
            self.assertTrue(result["run_id"])
            connection = db.connect(root / "recon.db")
            view = run_view(connection, result["run_id"])
            self.assertEqual(view["spec"]["target"], "example.com")
            self.assertTrue(any(item["status"] == "ok" for item in view["flow"]))
            self.assertTrue(any(item["name"] == "ai" and item["status"] == "ok" for item in view["flow"]))
            self.assertEqual(view["classification"]["items"], [])
            self.assertEqual(view["routes"][0]["path"], "/api/v1/users")
            self.assertEqual(view["drafts"], [])
            providers = {item["task"]: item["provider"] for item in view["ai"]}
            self.assertEqual(providers["classification"], "none")
            self.assertEqual(providers["routes"], "ollama")

    def test_export_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.environ["RECON_SCOPE"] = str(root / "scopes.txt")
            Path(os.environ["RECON_SCOPE"]).write_text("example.com\n", encoding="utf-8")
            os.environ["RECON_RESULTS"] = str(root)
            os.environ["RECON_DB"] = str(root / "recon.db")
            spec = spec_from_settings("example.com", load_settings(None, 20))
            result = run_job(spec, verify=False, runner=fixture_runner, ai_client=FixtureAI())
            connection = db.connect(root / "recon.db")
            view = run_view(connection, result["run_id"])
            findings = connection.execute(
                "SELECT severity, name, matched_at, template_id FROM finding WHERE run_id = ?",
                (result["run_id"],),
            ).fetchall()
            view["finding_rows"] = [dict(row) for row in findings]
            output = root / view["run"]["output_dir"]
            pdf_type, pdf = render_export(view, output, "pdf")
            doc_type, docx = render_export(view, output, "docx")
            self.assertEqual(pdf_type, "application/pdf")
            self.assertGreater(len(pdf), 20)
            self.assertTrue(docx.startswith(b"PK"))
            self.assertIn("word", doc_type)

    def test_export_draft_flag(self):
        from recon_ai.catalog import cluster_key
        from recon_ai.drafts import write_draft
        from recon_ai.export import write_export

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.environ["RECON_SCOPE"] = str(root / "scopes.txt")
            Path(os.environ["RECON_SCOPE"]).write_text("example.com\n", encoding="utf-8")
            os.environ["RECON_RESULTS"] = str(root)
            os.environ["RECON_DB"] = str(root / "recon.db")
            spec = spec_from_settings("example.com", load_settings(None, 20))
            result = run_job(spec, verify=False, runner=fixture_runner, ai_client=FixtureAI())
            connection = db.connect(root / "recon.db")
            view = run_view(connection, result["run_id"])
            output = root / view["run"]["output_dir"]
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
            path = write_export(
                root / "recon.db",
                root,
                result["run_id"],
                "pdf",
                draft=key,
            )
            self.assertTrue(path.name.startswith("rascunho"))
            self.assertGreater(path.stat().st_size, 20)
            notebook = write_export(root / "recon.db", root, result["run_id"], "pdf")
            self.assertTrue(notebook.name.startswith("relatorio"))


class ChatFixture:
    def __init__(self):
        self.calls = []

    def complete_with_usage(self, prompt, json_format=True):
        self.calls.append({"prompt": prompt, "json_format": json_format})
        return {
            "result": "resposta de teste",
            "prompt_eval_count": 12,
            "eval_count": 4,
            "done_reason": "stop",
        }


class UiApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "recon.db"
        connection = db.connect(self.db)
        run_id = db.new_run(connection, "example.com", "one", 20)
        db.finish_run(connection, run_id, "ok")
        self.chat = ChatFixture()
        self.server = make_server(self.db, "127.0.0.1", 0, self.root, ai_client=self.chat)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]
        self.scope = self.root / "scopes.txt"
        self.scope.write_text("example.com\n", encoding="utf-8")
        os.environ["RECON_SCOPE"] = str(self.scope)

    def tearDown(self):
        self.server.shutdown()
        if SCAN_LOCK.locked():
            SCAN_LOCK.release()
        self.tmp.cleanup()

    def test_tools_and_phase6_reads(self):
        with urlopen(f"http://127.0.0.1:{self.port}/api/tools") as response:
            tools = json.loads(response.read().decode())
        self.assertTrue(any(item["name"] == "nuclei" for item in tools))
        with urlopen(f"http://127.0.0.1:{self.port}/api/runs") as response:
            runs = json.loads(response.read().decode())
        self.assertEqual(runs[0]["target"], "example.com")

    def test_post_invalid_spec(self):
        req = Request(
            f"http://127.0.0.1:{self.port}/api/runs",
            data=json.dumps({"target": "../etc"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req)
        self.assertEqual(ctx.exception.code, 400)

    def test_ai_budget_and_complete(self):
        with urlopen(f"http://127.0.0.1:{self.port}/api/ai") as response:
            meta = json.loads(response.read().decode())
        self.assertEqual(meta["input_token_budget"], INPUT_TOKEN_BUDGET)
        self.assertEqual(meta["model"], "qwen2.5:7b")
        req = Request(
            f"http://127.0.0.1:{self.port}/api/ai/complete",
            data=json.dumps({"prompt": "olá"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req) as response:
            payload = json.loads(response.read().decode())
        self.assertEqual(payload["content"], "resposta de teste")
        self.assertEqual(self.chat.calls[0]["json_format"], False)
        self.assertEqual(self.chat.calls[0]["prompt"], "olá")

    def test_ai_complete_rejects_over_budget(self):
        req = Request(
            f"http://127.0.0.1:{self.port}/api/ai/complete",
            data=json.dumps({"prompt": "x" * 40000}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req)
        self.assertEqual(ctx.exception.code, 400)
        self.assertEqual(self.chat.calls, [])

    def test_ai_complete_rejects_when_scan_running(self):
        connection = db.connect(self.db)
        db.new_run(connection, "example.com", "two", 20)
        connection.close()
        req = Request(
            f"http://127.0.0.1:{self.port}/api/ai/complete",
            data=json.dumps({"prompt": "olá"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req)
        self.assertEqual(ctx.exception.code, 409)
        self.assertEqual(self.chat.calls, [])

    def test_ai_complete_rejects_when_scan_lock_held(self):
        SCAN_LOCK.acquire()
        try:
            req = Request(
                f"http://127.0.0.1:{self.port}/api/ai/complete",
                data=json.dumps({"prompt": "olá"}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(HTTPError) as ctx:
                urlopen(req)
            self.assertEqual(ctx.exception.code, 409)
        finally:
            SCAN_LOCK.release()
        self.assertEqual(self.chat.calls, [])

    def test_delete_run_purges_db_and_output(self):
        connection = db.connect(self.db)
        run_id = db.new_run(connection, "example.com", "gone", 20)
        db.finish_run(connection, run_id, "ok")
        connection.close()
        folder = self.root / "gone"
        folder.mkdir()
        (folder / "resumo.txt").write_text("ok\n", encoding="utf-8")
        req = Request(f"http://127.0.0.1:{self.port}/api/runs/{run_id}", method="DELETE")
        with urlopen(req) as response:
            payload = json.loads(response.read().decode())
        self.assertTrue(payload["deleted"])
        self.assertFalse(folder.exists())
        connection = db.connect(self.db)
        self.assertIsNone(db.get_run(connection, run_id))
        connection.close()
        missing = Request(f"http://127.0.0.1:{self.port}/api/runs/{run_id}", method="DELETE")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(missing)
        self.assertEqual(ctx.exception.code, 404)

    def test_delete_refuses_running_run(self):
        connection = db.connect(self.db)
        run_id = db.new_run(connection, "example.com", "live", 20)
        connection.close()
        req = Request(f"http://127.0.0.1:{self.port}/api/runs/{run_id}", method="DELETE")
        with self.assertRaises(HTTPError) as ctx:
            urlopen(req)
        self.assertEqual(ctx.exception.code, 409)
        self.assertIn("execução", ctx.exception.read().decode())


if __name__ == "__main__":
    unittest.main()
