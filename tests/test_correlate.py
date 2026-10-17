import json
import tempfile
import unittest
from pathlib import Path

from recon_ai.correlate import correlate_run
from recon_ai.derive import append_provenance, write_buckets, write_fingerprints
from recon_ai.ingest import read_findings


class CorrelateTests(unittest.TestCase):
    def _output(self, tmp):
        output = Path(tmp) / "out"
        (output / "live").mkdir(parents=True)
        (output / "js").mkdir(parents=True)
        (output / "urls" / "buckets").mkdir(parents=True)
        (output / "nuclei").mkdir(parents=True)
        (output / "har").mkdir(parents=True)
        (output / "subdomains").mkdir(parents=True)
        (output / "dorks").mkdir(parents=True)
        return output

    def test_cross_account_query_id_and_same_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = self._output(tmp)
            (output / "live" / "live_hosts.txt").write_text("", encoding="utf-8")
            (output / "live" / "unauthorized.txt").write_text("", encoding="utf-8")
            (output / "live" / "forbidden.txt").write_text("", encoding="utf-8")
            (output / "js" / "endpoints.txt").write_text("", encoding="utf-8")
            (output / "nuclei" / "results.jsonl").write_text("", encoding="utf-8")
            (output / "subdomains" / "all_subs.txt").write_text("example.com\n", encoding="utf-8")
            write_fingerprints(output, "")
            self._requests(output, "a", ["same", "only-a"])
            self._requests(output, "b", ["same"])
            stats = correlate_run(output, "example.com")
            self.assertEqual(stats["findings"], 1)
            finding = read_findings(output)[0]
            self.assertEqual(finding["template_id"], "corr/idor-cross-account")
            self.assertNotIn("only-a", finding["matched_at"])
            checklist = (output / "corr" / "checklist.txt").read_text(encoding="utf-8")
            self.assertIn("Pares IDOR entre contas: 1", checklist)

    def _requests(self, output, account, fingerprints):
        folder = output / "har" / account
        folder.mkdir(parents=True, exist_ok=True)
        rows = [
            {
                "method": "GET",
                "template": "www.example.com/orders",
                "param": "order_id",
                "id_fp": item,
            }
            for item in fingerprints
        ]
        (folder / "requests.jsonl").write_text(
            "\n".join(json.dumps(row) for row in rows) + "\n",
            encoding="utf-8",
        )

    def test_zero_matches_is_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = self._output(tmp)
            (output / "live" / "live_hosts.txt").write_text("", encoding="utf-8")
            (output / "live" / "unauthorized.txt").write_text("", encoding="utf-8")
            (output / "live" / "forbidden.txt").write_text("", encoding="utf-8")
            (output / "js" / "endpoints.txt").write_text("", encoding="utf-8")
            (output / "nuclei" / "results.jsonl").write_text("", encoding="utf-8")
            (output / "subdomains" / "all_subs.txt").write_text("example.com\n", encoding="utf-8")
            write_fingerprints(output, "")
            stats = correlate_run(output, "example.com")
            self.assertEqual(stats["findings"], 0)
            self.assertEqual(read_findings(output), [])
            self.assertTrue((output / "corr" / "checklist.txt").is_file())

    def test_js_on_gated_and_har_not_crawled(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = self._output(tmp)
            (output / "live" / "unauthorized.txt").write_text("https://api.example.com\n", encoding="utf-8")
            (output / "live" / "forbidden.txt").write_text("", encoding="utf-8")
            (output / "live" / "live_hosts.txt").write_text("https://example.com\n", encoding="utf-8")
            (output / "js" / "endpoints.txt").write_text("/api/v1/users\n", encoding="utf-8")
            (output / "har" / "urls.txt").write_text("https://example.com/private\n", encoding="utf-8")
            (output / "nuclei" / "results.jsonl").write_text("", encoding="utf-8")
            (output / "subdomains" / "all_subs.txt").write_text("example.com\n", encoding="utf-8")
            append_provenance(output, ["https://example.com/a"], "katana")
            stats = correlate_run(output, "example.com")
            templates = {item["template_id"] for item in read_findings(output)}
            self.assertIn("corr/js-on-gated-host", templates)
            self.assertIn("corr/har-not-crawled", templates)
            self.assertGreater(stats["findings"], 0)

    def test_cors_join_raises_severity(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = self._output(tmp)
            (output / "live" / "live_hosts.txt").write_text("https://example.com\n", encoding="utf-8")
            (output / "live" / "unauthorized.txt").write_text("", encoding="utf-8")
            (output / "live" / "forbidden.txt").write_text("", encoding="utf-8")
            (output / "js" / "endpoints.txt").write_text("", encoding="utf-8")
            (output / "subdomains" / "all_subs.txt").write_text("example.com\n", encoding="utf-8")
            (output / "nuclei" / "results.jsonl").write_text(
                json.dumps(
                    {
                        "template-id": "cors-misconfig",
                        "matched-at": "https://example.com",
                        "info": {"name": "CORS", "severity": "info"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (output / "har" / "findings.jsonl").write_text(
                json.dumps(
                    {
                        "severity": "high",
                        "name": "CORS * com credenciais",
                        "matched_at": "https://example.com/app",
                        "template_id": "har/cors",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            correlate_run(output, "example.com")
            found = [item for item in read_findings(output) if item["template_id"] == "corr/cors-credentialed"]
            self.assertEqual(found[0]["severity"], "high")

    def test_from_phase_ai_does_not_recompute(self):
        from recon_ai import db
        from recon_ai.runner import apply_correlate_phase

        with tempfile.TemporaryDirectory() as tmp:
            output = self._output(tmp)
            connection = db.connect(Path(tmp) / "recon.db")
            run_id = db.new_run(connection, "example.com", str(output), 20)
            db.upsert_phase(connection, run_id, "correlate", "ok", 1, "já calculado", str(output / "logs"))
            status = apply_correlate_phase(
                connection, run_id, output, {"target": "example.com"}, from_phase="ai"
            )
            self.assertEqual(status, "ok")
            self.assertFalse((output / "corr" / "findings.jsonl").is_file())

    def _blank(self, output):
        (output / "live" / "live_hosts.txt").write_text("", encoding="utf-8")
        (output / "live" / "unauthorized.txt").write_text("", encoding="utf-8")
        (output / "live" / "forbidden.txt").write_text("", encoding="utf-8")
        (output / "js" / "endpoints.txt").write_text("", encoding="utf-8")
        (output / "nuclei" / "results.jsonl").write_text("", encoding="utf-8")
        (output / "subdomains" / "all_subs.txt").write_text("example.com\n", encoding="utf-8")
        write_fingerprints(output, "")

    def test_archive_live_file_drives_still_live(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = self._output(tmp)
            self._blank(output)
            url = "https://old.example.com/secret"
            append_provenance(output, [url], "gau")
            write_fingerprints(output, json.dumps({"url": url, "status_code": 200, "title": "", "tech": []}) + "\n")
            correlate_run(output, "example.com")
            templates = {item["template_id"] for item in read_findings(output)}
            self.assertNotIn("corr/archive-still-live", templates)
            (output / "urls" / "archive_live.txt").write_text(url + "\n", encoding="utf-8")
            correlate_run(output, "example.com")
            found = [item for item in read_findings(output) if item["template_id"] == "corr/archive-still-live"]
            self.assertEqual(found[0]["matched_at"], url)

    def test_js_path_missing_from_crawl(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = self._output(tmp)
            self._blank(output)
            (output / "js" / "endpoints.txt").write_text("/api/v1/users\n/v2/health\n", encoding="utf-8")
            (output / "urls" / "all_urls.txt").write_text("https://example.com/v2/health\n", encoding="utf-8")
            correlate_run(output, "example.com")
            found = [item for item in read_findings(output) if item["template_id"] == "corr/js-not-crawled"]
            self.assertEqual([item["matched_at"] for item in found], ["/api/v1/users"])

    def test_crtsh_only_resolved_is_finding_and_unresolved_is_checklist(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = self._output(tmp)
            self._blank(output)
            (output / "dns").mkdir()
            (output / "dns" / "resolved_hosts.txt").write_text("admin.example.com\n", encoding="utf-8")
            (output / "subdomains" / "provenance.tsv").write_text(
                "admin.example.com\tcrtsh\nwww.example.com\tsubfinder\nwww.example.com\tcrtsh\nsolo.example.com\tcrtsh\n",
                encoding="utf-8",
            )
            correlate_run(output, "example.com")
            found = [item for item in read_findings(output) if item["template_id"] == "corr/crtsh-only"]
            self.assertEqual([item["matched_at"] for item in found], ["admin.example.com"])
            checklist = (output / "corr" / "checklist.txt").read_text(encoding="utf-8")
            self.assertIn("Nomes só no crt.sh sem DNS: 1", checklist)

    def test_dangling_cname_skips_scanned_live_and_in_domain(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = self._output(tmp)
            self._blank(output)
            (output / "dns").mkdir()
            (output / "live" / "live_hosts.txt").write_text("https://live.example.com\n", encoding="utf-8")
            (output / "dns" / "cnames.tsv").write_text(
                "gone.example.com\tgone.s3.amazonaws.com\n"
                "cdn.example.com\tcdn.example.com\n"
                "live.example.com\tother.s3.amazonaws.com\n",
                encoding="utf-8",
            )
            correlate_run(output, "example.com")
            found = [item for item in read_findings(output) if item["template_id"] == "corr/dangling-cname"]
            self.assertEqual(found[0]["matched_at"], "gone.example.com -> gone.s3.amazonaws.com")
            (output / "dns" / "takeover_scanned.txt").write_text("gone.example.com\n", encoding="utf-8")
            correlate_run(output, "example.com")
            found = [item for item in read_findings(output) if item["template_id"] == "corr/dangling-cname"]
            self.assertEqual(found, [])

    def test_bucket_candidate_requires_live_archive_or_har(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = self._output(tmp)
            self._blank(output)
            write_buckets(
                output,
                ["https://example.com/graphql", "https://example.com/debug", "https://example.com/upload"],
            )
            write_fingerprints(
                output,
                json.dumps({"url": "https://example.com/graphql", "status_code": 200, "title": "", "tech": []}) + "\n",
            )
            (output / "har" / "urls.txt").write_text("https://example.com/upload\n", encoding="utf-8")
            correlate_run(output, "example.com")
            templates = {item["template_id"] for item in read_findings(output)}
            self.assertIn("corr/graphql-candidate", templates)
            self.assertIn("corr/upload-candidate", templates)
            self.assertNotIn("corr/debug-candidate", templates)

    def test_dork_gated_joins_js_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = self._output(tmp)
            self._blank(output)
            (output / "dorks" / "gated.txt").write_text("https://gated.example.com/admin\n", encoding="utf-8")
            (output / "js" / "endpoints.txt").write_text("/api/v1/users\n", encoding="utf-8")
            (output / "urls" / "all_urls.txt").write_text("https://example.com/api/v1/users\n", encoding="utf-8")
            correlate_run(output, "example.com")
            found = [item for item in read_findings(output) if item["template_id"] == "corr/js-on-gated-host"]
            self.assertEqual(found[0]["matched_at"], "https://gated.example.com/api/v1/users")
