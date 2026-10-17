import json
import tempfile
import unittest
from pathlib import Path

from recon_ai.derive import (
    append_provenance,
    fingerprints_from_httpx,
    read_bucket,
    read_provenance,
    scan_js_secrets,
    write_buckets,
    write_fingerprints,
)


class DeriveTests(unittest.TestCase):
    def test_fingerprints_keep_title_and_tech(self):
        text = json.dumps(
            {"url": "https://example.com", "status_code": 200, "title": "Jenkins", "tech": ["Jenkins"]}
        )
        rows = fingerprints_from_httpx(text)
        self.assertEqual(rows[0]["title"], "Jenkins")
        self.assertEqual(rows[0]["tech"], ["Jenkins"])

    def test_provenance_and_buckets(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            append_provenance(output, ["https://example.com/a?id=1"], "gau")
            append_provenance(output, ["https://example.com/a?id=1"], "katana")
            mapping = read_provenance(output)
            self.assertEqual(mapping["https://example.com/a?id=1"], {"gau", "katana"})
            write_buckets(output, ["https://example.com/user/12", "https://example.com/swagger"])
            self.assertTrue(any("user/12" in line for line in read_bucket(output, "idor")))
            self.assertTrue(any("swagger" in line for line in read_bucket(output, "swagger")))

    def test_js_secrets_are_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            folder = output / "js" / "content"
            folder.mkdir(parents=True)
            (folder / "a.js").write_text('const k = "AKIAIOSFODNN7EXAMPLE";\n', encoding="utf-8")
            rows = scan_js_secrets(output)
            self.assertEqual(rows[0]["label"], "AWS Access Key")
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", rows[0]["detail"])
            self.assertTrue(rows[0]["fingerprint"])
            written = write_fingerprints(output, "")
            self.assertEqual(written, [])
