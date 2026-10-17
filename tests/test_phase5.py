import tempfile
import unittest
from pathlib import Path

from recon_ai import db
from recon_ai.diff import write_delta
from recon_ai.runner import record


def seed(connection, root, name, assets, findings=None):
    output = root / name
    output.mkdir()
    (output / "resumo.txt").write_text("relatorio\n", encoding="utf-8")
    run_id = db.new_run(connection, "example.com", name, 20)
    phases = [
        {
            "run_id": run_id,
            "name": "report",
            "status": "ok",
            "exit_code": 0,
            "duration_s": 0,
            "stderr_path": "",
            "detail": "resumo",
        }
    ]
    finding_rows = [(run_id, *item) for item in (findings or [])]
    db.replace_run_details(connection, run_id, phases, assets, [], finding_rows)
    db.finish_run(connection, run_id, "ok")
    return run_id, output


class DeltaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.connection = db.connect(self.root / "recon.db")

    def tearDown(self):
        self.tmp.cleanup()

    def items(self, run_id, change):
        rows = self.connection.execute(
            "select entity, key, before, after from delta_item where run_id = ? and change = ? order by key",
            (run_id, change),
        ).fetchall()
        return [tuple(row) for row in rows]

    def test_first_run_lists_everything_as_entered(self):
        run_id, output = seed(
            self.connection,
            self.root,
            "one",
            [("host", "a.example.com")],
            [("info", "Example", "https://a.example.com", "example-info")],
        )
        delta = write_delta(self.connection, run_id, output)
        self.assertIsNone(delta["baseline_id"])
        self.assertEqual(
            self.items(run_id, "entered"),
            [
                ("asset", "a.example.com", None, "host"),
                ("finding", "example-info @ https://a.example.com", None, "info"),
            ],
        )
        self.assertEqual(self.items(run_id, "left"), [])
        self.assertEqual(self.items(run_id, "changed"), [])
        text = (output / "resumo.txt").read_text(encoding="utf-8")
        self.assertIn("Base                    : nenhuma", text)
        self.assertIn("- asset a.example.com", text)

    def test_identical_second_run_is_an_empty_delta(self):
        assets = [("host", "a.example.com")]
        findings = [("info", "Example", "https://a.example.com", "example-info")]
        first, _ = seed(self.connection, self.root, "one", assets, findings)
        second, output = seed(self.connection, self.root, "two", assets, findings)
        write_delta(self.connection, second, output)
        self.assertEqual(self.items(second, "entered"), [])
        self.assertEqual(self.items(second, "left"), [])
        self.assertEqual(self.items(second, "changed"), [])
        baseline = self.connection.execute(
            "select baseline_id from delta_run where run_id = ?",
            (second,),
        ).fetchone()["baseline_id"]
        self.assertEqual(baseline, first)
        self.assertIn("Delta                   : vazio", (output / "resumo.txt").read_text(encoding="utf-8"))

    def test_new_host_appears_only_as_entered(self):
        seed(self.connection, self.root, "one", [("host", "a.example.com")])
        second, output = seed(
            self.connection,
            self.root,
            "two",
            [("host", "a.example.com"), ("host", "b.example.com")],
        )
        write_delta(self.connection, second, output)
        self.assertEqual(self.items(second, "entered"), [("asset", "b.example.com", None, "host")])
        self.assertEqual(self.items(second, "left"), [])
        self.assertEqual(self.items(second, "changed"), [])
        text = (output / "resumo.txt").read_text(encoding="utf-8")
        self.assertIn("- asset b.example.com", text)
        self.assertNotIn("- asset a.example.com", text)

    def test_kind_change_is_not_an_entry(self):
        seed(self.connection, self.root, "one", [("host", "a.example.com")])
        second, output = seed(self.connection, self.root, "two", [("live", "a.example.com")])
        write_delta(self.connection, second, output)
        self.assertEqual(self.items(second, "entered"), [])
        self.assertEqual(self.items(second, "left"), [])
        self.assertEqual(
            self.items(second, "changed"),
            [("asset", "a.example.com", "host", "live")],
        )
        self.assertIn(
            "- asset a.example.com host -> live",
            (output / "resumo.txt").read_text(encoding="utf-8"),
        )

    def test_finding_severity_change_is_not_an_entry(self):
        finding = ("info", "Example", "https://a.example.com", "example-info")
        seed(self.connection, self.root, "one", [], [finding])
        second, _ = seed(
            self.connection,
            self.root,
            "two",
            [],
            [("high", "Example", "https://a.example.com", "example-info")],
        )
        write_delta(self.connection, second, self.root / "two")
        self.assertEqual(self.items(second, "entered"), [])
        self.assertEqual(
            self.items(second, "changed"),
            [("finding", "example-info @ https://a.example.com", "info", "high")],
        )

    def test_record_writes_the_delta_and_a_failed_run_does_not(self):
        seed(self.connection, self.root, "one", [("host", "a.example.com")])
        output = self.root / "two"
        output.mkdir()
        (output / "resumo.txt").write_text("relatorio\n", encoding="utf-8")
        (output / "subdomains").mkdir()
        (output / "subdomains" / "all_subs.txt").write_text("a.example.com\nb.example.com\n", encoding="utf-8")
        (output / "phases.tsv").write_text("report\tok\t0\tresumo\n", encoding="utf-8")
        run_id = db.new_run(self.connection, "example.com", output.name, 20)
        self.assertEqual(record(self.connection, run_id, output), "ok")
        self.assertEqual(self.items(run_id, "entered"), [("asset", "b.example.com", None, "subdomain")])
        text = (output / "resumo.txt").read_text(encoding="utf-8")
        self.assertIn("- asset b.example.com", text)
        self.assertIn("host -> subdomain", text)

        failed = self.root / "three"
        failed.mkdir()
        (failed / "phases.tsv").write_text("subdomains\tfail\t1\terro\n", encoding="utf-8")
        failed_id = db.new_run(self.connection, "example.com", failed.name, 20)
        self.assertEqual(record(self.connection, failed_id, failed), "failed")
        count = self.connection.execute(
            "select count(*) from delta_run where run_id = ?",
            (failed_id,),
        ).fetchone()[0]
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
