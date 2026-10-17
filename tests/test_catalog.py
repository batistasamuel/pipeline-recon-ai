import json
import tempfile
import unittest
from pathlib import Path

from recon_ai.catalog import build_finding, cluster_key, nuclei_evidence
from recon_ai.cluster import group_findings, write_clusters
from recon_ai.ingest import read_findings


class CatalogTests(unittest.TestCase):
    def test_nuclei_persists_cwe_and_curl(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            folder = output / "nuclei"
            folder.mkdir()
            (folder / "results.jsonl").write_text(
                json.dumps(
                    {
                        "template-id": "cve-custom",
                        "matched-at": "https://a.example.com/login",
                        "curl-command": "curl -X GET https://a.example.com/login",
                        "info": {
                            "name": "Reflected XSS",
                            "severity": "high",
                            "description": "eco do parâmetro",
                            "classification": {"cwe-id": ["cwe-79"], "cve-id": ["CVE-2024-0001"]},
                            "reference": ["https://cwe.mitre.org/data/definitions/79.html"],
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            finding = read_findings(output)[0]
            self.assertEqual(finding["class"], "reportable")
            self.assertIn("cwe-79", finding["evidence"]["cwe"])
            self.assertEqual(finding["evidence"]["curl"], "curl -X GET https://a.example.com/login")
            self.assertNotIn("token", json.dumps(finding["evidence"]))

    def test_har_secret_keeps_fingerprint_not_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            folder = output / "har"
            folder.mkdir()
            (folder / "findings.jsonl").write_text(
                json.dumps(
                    {
                        "severity": "high",
                        "name": "Segredo em JS",
                        "matched_at": "https://example.com/app.js",
                        "template_id": "har/secret",
                        "detail": "api_key: sk***redacted",
                        "fingerprint": "deadbeef",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            finding = read_findings(output)[0]
            self.assertEqual(finding["class"], "reportable")
            self.assertEqual(finding["evidence"]["secret_fp"], "deadbeef")
            self.assertEqual(finding["evidence"]["detail"], "api_key: sk***redacted")
            dumped = json.dumps(finding)
            self.assertNotIn("sk_live", dumped)
            self.assertNotIn("ghp_", dumped)

    def test_har_not_crawled_shares_cluster_per_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            folder = output / "corr"
            folder.mkdir()
            rows = []
            for path in ("/a", "/b", "/c?x=1"):
                rows.append(
                    json.dumps(
                        {
                            "severity": "info",
                            "name": "URL HAR ausente do crawl",
                            "matched_at": f"https://app.example.com{path}",
                            "template_id": "corr/har-not-crawled",
                        }
                    )
                )
            (folder / "findings.jsonl").write_text("\n".join(rows) + "\n", encoding="utf-8")
            findings = read_findings(output)
            self.assertEqual({item["class"] for item in findings}, {"coverage"})
            keys = {item["cluster_key"] for item in findings}
            self.assertEqual(len(keys), 1)
            self.assertEqual(next(iter(keys)), cluster_key("corr/har-not-crawled", "https://app.example.com/a", "coverage"))

    def test_unknown_nuclei_without_cwe_is_note(self):
        item = {
            "template-id": "example-info",
            "matched-at": "https://example.com",
            "info": {"name": "Example", "severity": "info"},
        }
        finding = build_finding(item, "nuclei")
        self.assertEqual(finding["class"], "note")
        self.assertEqual(nuclei_evidence(item)["cwe"], "")

    def test_three_note_coverage_clusters_skip_ids_in_group(self):
        findings = [
            {
                "id": 1,
                "template_id": "corr/har-not-crawled",
                "class": "coverage",
                "cluster_key": cluster_key("corr/har-not-crawled", "https://a.example.com/1", "coverage"),
                "matched_at": "https://a.example.com/1",
            },
            {
                "id": 2,
                "template_id": "corr/har-not-crawled",
                "class": "coverage",
                "cluster_key": cluster_key("corr/har-not-crawled", "https://a.example.com/2", "coverage"),
                "matched_at": "https://a.example.com/2",
            },
            {
                "id": 3,
                "template_id": "corr/js-not-crawled",
                "class": "coverage",
                "cluster_key": cluster_key("corr/js-not-crawled", "https://a.example.com/x", "coverage"),
                "matched_at": "https://a.example.com/x",
            },
            {
                "id": 4,
                "template_id": "corr/shadow-host",
                "class": "note",
                "cluster_key": cluster_key("corr/shadow-host", "ghost.example.com", "note"),
                "matched_at": "ghost.example.com",
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            rows = write_clusters(tmp, findings)
            self.assertEqual(len(rows), 3)
            self.assertEqual({row["class"] for row in rows}, {"coverage", "note"})
            grouped = {row["template_id"]: row["count"] for row in group_findings(findings)}
            self.assertEqual(grouped["corr/har-not-crawled"], 2)


if __name__ == "__main__":
    unittest.main()
