import json
import tempfile
import unittest
from pathlib import Path

from recon_ai import db
from recon_ai.config import ConfigError, load_settings
from recon_ai.ingest import read_findings, read_phases, run_status
from recon_ai.phases import first_incomplete
from recon_ai.plan import command, describe
from recon_ai.runtime import prepare_state
from recon_ai.scope import domain_in_scope, output_safe_name, valid_domain, valid_target


class PhaseTests(unittest.TestCase):
    def test_first_incomplete_stops_on_warn(self):
        rows = [
            {"name": "subdomains", "status": "warn"},
            {"name": "dns", "status": "ok"},
        ]
        self.assertEqual(first_incomplete(rows), "subdomains")

    def test_complete_run(self):
        rows = [{"name": name, "status": "ok"} for name in (
            "subdomains", "dns", "http", "urls", "dorks", "js", "nuclei", "report", "har", "correlate", "ai"
        )]
        self.assertIsNone(first_incomplete(rows))

    def test_missing_har_is_incomplete(self):
        rows = [{"name": name, "status": "ok"} for name in (
            "subdomains", "dns", "http", "urls", "dorks", "js", "nuclei", "report"
        )]
        self.assertEqual(first_incomplete(rows), "har")

    def test_missing_ai_is_incomplete(self):
        rows = [{"name": name, "status": "ok"} for name in (
            "subdomains", "dns", "http", "urls", "dorks", "js", "nuclei", "report"
        )]
        rows.append({"name": "har", "status": "skip"})
        rows.append({"name": "correlate", "status": "skip"})
        self.assertEqual(first_incomplete(rows), "ai")

    def test_missing_correlate_is_incomplete(self):
        rows = [{"name": name, "status": "ok"} for name in (
            "subdomains", "dns", "http", "urls", "dorks", "js", "nuclei", "report"
        )]
        rows.append({"name": "har", "status": "skip"})
        self.assertEqual(first_incomplete(rows), "correlate")

    def test_command_includes_from(self):
        cmd = command("recon.sh", "example.com", 40, "out", "dns")
        self.assertEqual(cmd, ["recon.sh", "--output", "out", "--from", "dns", "example.com", "40"])


class ScopeTests(unittest.TestCase):
    def test_domain_and_scope(self):
        self.assertTrue(valid_domain("example.com"))
        self.assertFalse(valid_domain("../etc"))
        with tempfile.TemporaryDirectory() as tmp:
            scope = Path(tmp) / "scopes.txt"
            scope.write_text("# x\nExample.COM\n", encoding="utf-8")
            self.assertEqual(domain_in_scope("example.com", scope), 0)
            self.assertEqual(domain_in_scope("evil.com", scope), 1)
            self.assertEqual(domain_in_scope("example.com", Path(tmp) / "missing"), 2)

    def test_ipv4_port_is_a_valid_target(self):
        self.assertTrue(valid_target("127.0.0.1:8080"))
        self.assertTrue(valid_target("127.0.0.1"))
        self.assertFalse(valid_domain("127.0.0.1:8080"))
        self.assertFalse(valid_target("127.0.0.1:99999"))
        self.assertFalse(valid_target("127.0.0.1:8080/login"))
        self.assertFalse(valid_target("256.1.1.1"))
        self.assertFalse(valid_target("256.1.1.1:8080"))
        self.assertEqual(output_safe_name("127.0.0.1:8080"), "127.0.0.1_8080")
        with tempfile.TemporaryDirectory() as tmp:
            scope = Path(tmp) / "scopes.txt"
            scope.write_text("127.0.0.1:8080\n", encoding="utf-8")
            self.assertEqual(domain_in_scope("127.0.0.1:8080", scope), 0)


class ConfigTests(unittest.TestCase):
    def test_yaml_overrides_one_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "recon.yaml"
            path.write_text("threads: 40\ntools:\n  dnsx:\n    threads: 10\n  nuclei:\n    rate_limit: 80\n", encoding="utf-8")
            settings = load_settings(path, None)
        self.assertEqual(settings["threads"], 40)
        self.assertEqual(settings["tools"]["dnsx"]["threads"], 10)
        self.assertEqual(settings["tools"]["httpx"]["threads"], 40)
        self.assertEqual(settings["tools"]["nuclei"]["rate_limit"], 80)
        self.assertEqual(settings["amass_timeout"], 5)

    def test_invalid_yaml_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "recon.yaml"
            path.write_text("- apenas-lista\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_settings(path, None)


class StateTests(unittest.TestCase):
    def test_copy_is_not_a_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "config" / "subfinder"
            config.mkdir(parents=True)
            (config / "provider-config.yaml").write_text("keys: true\n", encoding="utf-8")
            home = root / "state" / "home"
            prepare_state(home, root / "config")
            copied = home / ".config" / "subfinder" / "provider-config.yaml"
            self.assertTrue(copied.is_file())
            self.assertFalse(copied.is_symlink())
            self.assertFalse((home / ".config" / "subfinder").is_symlink())


class StoreTests(unittest.TestCase):
    def test_two_runs_share_history_and_resume_point(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "recon_example.com_1"
            (output / "logs").mkdir(parents=True)
            (output / "subdomains").mkdir()
            (output / "subdomains" / "all_subs.txt").write_text("example.com\nwww.example.com\n", encoding="utf-8")
            (output / "nuclei").mkdir()
            (output / "nuclei" / "results.jsonl").write_text(
                json.dumps({"template-id": "t", "matched-at": "https://example.com", "info": {"severity": "info", "name": "n"}}) + "\n",
                encoding="utf-8",
            )
            (output / "phases.tsv").write_text(
                "subdomains\tok\t1\t2 nomes\ndns\tfail\t3\terro\n",
                encoding="utf-8",
            )
            connection = db.connect(root / "recon.db")
            first = db.new_run(connection, "Example.COM", "recon_example.com_1", 50)
            phases = read_phases(output)
            for row in phases:
                row["run_id"] = first
            db.replace_run_details(
                connection,
                first,
                phases,
                [("subdomain", "example.com")],
                ["https://example.com"],
                read_findings(output),
            )
            db.finish_run(connection, first, run_status(phases))
            second = db.new_run(connection, "example.com", "recon_example.com_2", 50)
            db.finish_run(connection, second, "ok")
            self.assertEqual(len(db.runs_for_target(connection, "example.com")), 2)
            self.assertEqual(db.get_run(connection, first)["status"], "failed")
            from recon_ai.runner import resume_from
            found, phase = resume_from(connection, first)
            self.assertEqual(found["target"], "example.com")
            self.assertEqual(phase, "dns")
            self.assertIn("rede: nao", describe("example.com", 50, load_settings(None, 50)["tools"], "out"))

    def test_reap_marks_running_as_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            connection = db.connect(Path(tmp) / "recon.db")
            run_id = db.new_run(connection, "example.com", "recon_example.com_1", 50)
            db.upsert_phase(connection, run_id, "har", "running", 0, "in progress")
            self.assertEqual(db.reap_stale_runs(connection), 1)
            self.assertEqual(db.get_run(connection, run_id)["status"], "failed")
            phase = db.list_phases(connection, run_id)[0]
            self.assertEqual(phase["status"], "fail")
            self.assertEqual(phase["detail_key"], "phase.interrupted")
            self.assertEqual(db.reap_stale_runs(connection), 0)

    def test_resume_invokes_fake_script_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "recon_example.com_1"
            (output / "logs").mkdir(parents=True)
            (output / "phases.tsv").write_text(
                "subdomains\tok\t1\t1 nome\ndns\tfail\t2\terro\n",
                encoding="utf-8",
            )
            script = root / "fake.sh"
            script.write_text(
                "#!/bin/bash\n"
                "set -euo pipefail\n"
                "out=\"\"\n"
                "frm=\"\"\n"
                "while [ $# -gt 0 ]; do\n"
                "  case \"$1\" in\n"
                "    --output) out=\"$2\"; shift 2 ;;\n"
                "    --from) frm=\"$2\"; shift 2 ;;\n"
                "    *) break ;;\n"
                "  esac\n"
                "done\n"
                "printf '%s\\n' \"$frm\" > \"$out/invoked-from.txt\"\n"
                "printf '%s\\n' $'subdomains\\tok\\t1\\tok' $'dns\\tok\\t1\\tok' > \"$out/phases.tsv\"\n",
                encoding="utf-8",
            )
            script.chmod(0o755)
            connection = db.connect(root / "recon.db")
            run_id = db.new_run(connection, "example.com", output.name, 50)
            phases = read_phases(output)
            for row in phases:
                row["run_id"] = run_id
            db.replace_run_details(connection, run_id, phases, [], [], [])
            db.finish_run(connection, run_id, "failed")
            from recon_ai.runner import execute, record, resume_from
            found, phase = resume_from(connection, run_id)
            self.assertEqual(phase, "dns")
            code = execute(
                str(script),
                "example.com",
                load_settings(None, 50),
                output.name,
                phase,
                root,
            )
            self.assertEqual(code, 0)
            self.assertEqual((output / "invoked-from.txt").read_text().strip(), "dns")
            self.assertEqual(record(connection, run_id, output), "ok")

    def test_delete_run_removes_rows_and_refuses_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            connection = db.connect(Path(tmp) / "recon.db")
            running = db.new_run(connection, "example.com", "out-running", 20)
            with self.assertRaises(db.RunError):
                db.delete_run(connection, running)
            self.assertIsNotNone(db.get_run(connection, running))
            done = db.new_run(connection, "example.com", "out-done", 20)
            db.replace_run_details(
                connection,
                done,
                [
                    {
                        "run_id": done,
                        "name": "dns",
                        "status": "ok",
                        "exit_code": 0,
                        "duration_s": 1,
                        "stderr_path": "",
                        "detail": "",
                    }
                ],
                [("host", "example.com")],
                ["https://example.com"],
                [("info", "Example", "https://example.com", "example-info")],
            )
            db.finish_run(connection, done, "ok")
            removed = db.delete_run(connection, done)
            self.assertEqual(removed["id"], done)
            self.assertIsNone(db.get_run(connection, done))
            self.assertEqual(
                connection.execute("SELECT count(*) FROM finding WHERE run_id = ?", (done,)).fetchone()[0],
                0,
            )
            self.assertIsNone(db.delete_run(connection, "missing"))


if __name__ == "__main__":
    unittest.main()
