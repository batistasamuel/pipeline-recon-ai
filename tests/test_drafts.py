import json
import tempfile
import unittest
from pathlib import Path

from recon_ai.catalog import cluster_key
from recon_ai.drafts import DraftError, render_markdown, set_status, validate_draft, write_draft
from recon_ai.export import _text_blocks, render_export
from recon_ai.verify import persist_verified, verify_findings


def _dangling():
    key = cluster_key("corr/dangling-cname", "https://gone.example.com", "reportable")
    finding = {
        "id": 1,
        "severity": "high",
        "name": "CNAME órfão",
        "matched_at": "https://gone.example.com",
        "template_id": "corr/dangling-cname",
        "kind": "corr",
        "class": "reportable",
        "cluster_key": key,
        "evidence": {"cwe": "CWE-284", "secret_fp": "", "detail": "", "curl": "", "references": []},
    }
    cluster = {"cluster_key": key, "class": "reportable", "template_id": "corr/dangling-cname", "count": 1}
    draft = {
        "title": "[Subdomain Takeover] via CNAME órfão em https://gone.example.com",
        "summary": "CNAME aponta para terceiro sem recurso reclamado.",
        "impact": "Um atacante pode reclamar o alvo e servir conteúdo no host.",
        "steps": ["Resolva o CNAME de gone.example.com e confirme se o alvo de terceiro está reclamado."],
        "evidence_notes": "CNAME no dns/cnames.tsv do run.",
    }
    return cluster, finding, draft


class DraftTests(unittest.TestCase):
    def test_dangling_markdown_has_eight_sections_without_token(self):
        cluster, finding, draft = _dangling()
        text = render_markdown(cluster, [finding], draft, "pt-BR")
        self.assertIn("## Resumo", text)
        self.assertIn("## Tipo e classificação", text)
        self.assertIn("CWE-284", text)
        self.assertIn("## Impacto", text)
        self.assertIn("## Passos para reproduzir", text)
        self.assertIn("Resolva o CNAME", text)
        self.assertIn("## Evidência", text)
        self.assertIn("## Remediação sugerida", text)
        self.assertIn("## Referências", text)
        self.assertNotIn("sk_live", text)
        self.assertNotIn("Authorization", text)

    def test_write_and_status_do_not_rewrite_evidence(self):
        cluster, finding, draft = _dangling()
        with tempfile.TemporaryDirectory() as tmp:
            write_draft(tmp, cluster, [finding], draft, "pt-BR")
            index = json.loads((Path(tmp) / "drafts" / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(index[0]["status"], "draft")
            set_status(tmp, cluster["cluster_key"], "ready")
            again = json.loads((Path(tmp) / "drafts" / "index.json").read_text(encoding="utf-8"))
            self.assertEqual(again[0]["status"], "ready")
            with self.assertRaises(DraftError):
                set_status(tmp, cluster["cluster_key"], "shipped")

    def test_validate_draft_rejects_extra_keys(self):
        with self.assertRaises(DraftError):
            validate_draft({"title": "a", "summary": "b", "impact": "c", "steps": ["d"], "evidence_notes": "e", "extra": "x"})

    def test_export_draft_pdf_and_run_notebook_stay_distinct(self):
        cluster, finding, draft = _dangling()
        with tempfile.TemporaryDirectory() as tmp:
            write_draft(tmp, cluster, [finding], draft, "pt-BR")
            view = {
                "run": {
                    "id": "run1",
                    "target": "example.com",
                    "status": "ok",
                    "started_at": "t",
                    "finished_at": "t",
                    "threads": 20,
                },
                "spec": {"in_scope": ["example.com"], "out_scope": []},
                "flow": [],
                "finding_rows": [],
                "candidates": [],
                "clusters": [
                    {
                        "class": "coverage",
                        "template_id": "corr/har-not-crawled",
                        "count": 3,
                        "sample": "https://example.com/x",
                    }
                ],
            }
            notebook_type, notebook = render_export(view, tmp, "pdf")
            draft_type, body = render_export(view, tmp, "pdf", draft=cluster["cluster_key"])
            self.assertEqual(notebook_type, "application/pdf")
            self.assertEqual(draft_type, "application/pdf")
            self.assertGreater(len(notebook), 20)
            self.assertGreater(len(body), 20)
            notebook_text = "\n".join(_text_blocks(view, tmp, "pt-BR"))
            self.assertIn("Clusters de cobertura", notebook_text)
            self.assertIn("corr/har-not-crawled", notebook_text)


class VerifyTests(unittest.TestCase):
    def test_default_is_skip(self):
        _, finding, _ = _dangling()
        rows = verify_findings([dict(finding)], "/tmp", enabled=False)
        self.assertEqual(rows[0]["evidence"]["verified"], "skip")

    def test_cname_uses_resolver_stub(self):
        _, finding, _ = _dangling()
        yes = verify_findings([dict(finding)], "/tmp", enabled=True, resolver=lambda host: ["unclaimed.vendors.test"])
        self.assertEqual(yes[0]["evidence"]["verified"], "yes")
        no = verify_findings([dict(finding)], "/tmp", enabled=True, resolver=lambda host: [])
        self.assertEqual(no[0]["evidence"]["verified"], "no")
        dumped = json.dumps(yes[0]["evidence"])
        self.assertNotIn("Authorization", dumped)
        self.assertNotIn("Cookie", dumped)

    def test_secret_fingerprint_reads_disk_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            (output / "js").mkdir()
            (output / "js" / "secrets.jsonl").write_text(
                json.dumps({"fingerprint": "abc", "detail": "key: ***"}) + "\n",
                encoding="utf-8",
            )
            finding = {
                "id": 2,
                "template_id": "har/secret",
                "matched_at": "https://example.com/app.js",
                "evidence": {"secret_fp": "abc"},
            }
            rows = verify_findings([finding], output, enabled=True)
            self.assertEqual(rows[0]["evidence"]["verified"], "yes")
            missing = verify_findings(
                [{"id": 3, "template_id": "har/secret", "matched_at": "https://example.com/app.js", "evidence": {"secret_fp": "nope"}}],
                output,
                enabled=True,
            )
            self.assertEqual(missing[0]["evidence"]["verified"], "no")

    def test_persist_verified_updates_sqlite(self):
        from recon_ai import db

        with tempfile.TemporaryDirectory() as tmp:
            connection = db.connect(Path(tmp) / "recon.db")
            run_id = db.new_run(connection, "example.com", "out", 20)
            db.replace_run_details(connection, run_id, [], [], [], [_dangling()[1]])
            stored = db.list_findings(connection, run_id)
            stored[0]["evidence"]["verified"] = "yes"
            persist_verified(connection, run_id, stored)
            again = db.list_findings(connection, run_id)
            self.assertEqual(again[0]["evidence"]["verified"], "yes")


if __name__ == "__main__":
    unittest.main()
