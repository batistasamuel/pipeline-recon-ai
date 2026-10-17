import json
import os
import tempfile
import unittest
from pathlib import Path

from recon_ai import db
from recon_ai.config import load_settings
from recon_ai.ingest import read_assets
from recon_ai.parse import (
    classify_http,
    hosts_without_wildcard,
    names_from_text,
    parse_cname,
    referenced_scripts,
    source_map_url,
    urls_for_domain,
)
from recon_ai.pipeline import scan_har_nuclei
from recon_ai.pipeline import Pipeline
from recon_ai.runner import record

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


class ParserTests(unittest.TestCase):
    def test_names_keep_apex_and_drop_lookalikes(self):
        names = names_from_text((FIX / "amass.txt").read_text(encoding="utf-8"), "example.com")
        self.assertIn("example.com", names)
        self.assertIn("www.example.com", names)
        self.assertNotIn("notexample.com", names)
        self.assertNotIn("evil.example.com.other.net", names)

    def test_urls_anchor_on_host(self):
        urls = urls_for_domain((FIX / "urls.txt").read_text(encoding="utf-8").splitlines(), "example.com")
        self.assertIn("https://example.com/a", urls)
        self.assertIn("https://www.example.com/app.js", urls)
        self.assertFalse(any("notexample.com" in item for item in urls))
        self.assertFalse(any("other.net" in item for item in urls))

    def test_urls_keep_ip_port_and_loopback_alias(self):
        lines = [
            "http://127.0.0.1:8080/login.php",
            "http://127.0.0.1/login.php",
            "http://127.0.0.1:80/other",
            "http://host.docker.internal:8080/vulnerabilities/sqli/",
            "http://10.0.0.2:8080/out",
        ]
        kept = urls_for_domain(lines, "127.0.0.1:8080")
        self.assertEqual(kept, ["http://127.0.0.1:8080/login.php"])
        previous = os.environ.get("RECON_LOOPBACK_HOST")
        os.environ["RECON_LOOPBACK_HOST"] = "host.docker.internal"
        try:
            kept = urls_for_domain(lines, "127.0.0.1:8080")
        finally:
            if previous is None:
                os.environ.pop("RECON_LOOPBACK_HOST", None)
            else:
                os.environ["RECON_LOOPBACK_HOST"] = previous
        self.assertIn("http://127.0.0.1:8080/login.php", kept)
        self.assertIn("http://host.docker.internal:8080/vulnerabilities/sqli/", kept)
        self.assertNotIn("http://127.0.0.1/login.php", kept)
        self.assertNotIn("http://10.0.0.2:8080/out", kept)

    def test_wildcard_filter_drops_only_wildcard_hosts(self):
        from recon_ai.parse import parse_dns
        rows = parse_dns((FIX / "dns.txt").read_text(encoding="utf-8"))
        kept = hosts_without_wildcard(rows, {"198.51.100.8"})
        self.assertIn("api.example.com", kept)
        self.assertNotIn("wild.example.com", kept)
        self.assertIn("example.com", kept)

    def test_cname_source_map_and_script_ref(self):
        rows = parse_cname("gone.example.com [CNAME] [Gone.S3.amazonaws.com]\nexample.com [A] [203.0.113.10]\n")
        self.assertEqual(rows, [("gone.example.com", "gone.s3.amazonaws.com")])
        body = 'fetch("./extra.js");\n//# sourceMappingURL=app.js.map\n//# sourceMappingURL=https://cdn.example.net/app.js.map\n'
        script = "https://www.example.com/static/app.js"
        self.assertEqual(source_map_url(body, script, "example.com"), "https://www.example.com/static/app.js.map")
        self.assertIsNone(
            source_map_url("//# sourceMappingURL=https://cdn.example.net/app.js.map\n", script, "example.com")
        )
        refs = referenced_scripts(body, script, "example.com")
        self.assertIn("https://www.example.com/static/extra.js", refs)
        self.assertNotIn("https://cdn.example.net/app.js", refs)

    def test_http_states_do_not_mix(self):
        live, unauthorized, forbidden = classify_http((FIX / "http.jsonl").read_text(encoding="utf-8"))
        self.assertEqual(live, ["https://example.com"])
        self.assertEqual(unauthorized, ["https://api.example.com"])
        self.assertEqual(forbidden, ["https://admin.example.com"])


class PipelineTests(unittest.TestCase):
    def test_summary_matches_sqlite_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "recon_example.com_1"
            pipeline = Pipeline("example.com", load_settings(None, 20), output, {}, fixture_runner)
            self.assertEqual(pipeline.run(), 0)
            summary = (output / "resumo.txt").read_text(encoding="utf-8")
            self.assertIn("Hosts vivos             : 1", summary)
            self.assertIn("Hosts 401               : 1", summary)
            self.assertIn("Hosts 403               : 1", summary)
            self.assertIn("Findings Nuclei         : 1", summary)
            live = (output / "live" / "live_hosts.txt").read_text(encoding="utf-8")
            self.assertNotIn("401", live)
            self.assertNotIn("admin.example.com", live)
            connection = db.connect(root / "recon.db")
            run_id = db.new_run(connection, "example.com", output.name, 20)
            self.assertEqual(record(connection, run_id, output), "ok")
            counts = dict(read_assets(output))
            stored = connection.execute(
                "select kind, count(*) from asset where run_id = ? group by kind",
                (run_id,),
            ).fetchall()
            stored = {kind: count for kind, count in stored}
            self.assertEqual(stored["live"], 1)
            self.assertEqual(stored["unauthorized"], 1)
            self.assertEqual(stored["forbidden"], 1)
            self.assertEqual(
                connection.execute("select count(*) from finding where run_id = ?", (run_id,)).fetchone()[0],
                1,
            )
            self.assertGreater(len(counts), 0)
            json.loads((FIX / "crtsh.json").read_text(encoding="utf-8"))

    def test_literal_host_does_not_call_osint(self):
        forbidden = {"subfinder", "amass", "dnsx", "assetfinder"}

        def runner(args, stdout_path, stderr_path):
            name = "assetfinder" if args[0] == "timeout" else args[0]
            if name in forbidden:
                raise AssertionError(f"OSINT não cabe em alvo literal: {args}")
            stderr_path.write_text("", encoding="utf-8")
            if name == "httpx" and "-json" in args:
                text = json.dumps({"url": "http://127.0.0.1:8080", "status_code": 302}) + "\n"
            elif name == "httpx":
                text = ""
            elif name == "katana":
                text = "http://127.0.0.1:8080/login.php\n"
            elif name == "nuclei":
                text = json.dumps(
                    {
                        "template-id": "dvwa-detect",
                        "matched-at": "http://127.0.0.1:8080",
                        "info": {"name": "DVWA", "severity": "medium"},
                    }
                ) + "\n"
            else:
                text = ""
            stdout_path.write_text(text, encoding="utf-8")
            return 0

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "recon_127.0.0.1_8080_1"
            pipeline = Pipeline("127.0.0.1:8080", load_settings(None, 20), output, {}, runner)
            self.assertEqual(pipeline.run(), 0)
            self.assertEqual((output / "subdomains" / "all_subs.txt").read_text(encoding="utf-8"), "127.0.0.1:8080\n")
            self.assertEqual((output / "dns" / "resolved_hosts.txt").read_text(encoding="utf-8"), "127.0.0.1:8080\n")
            self.assertIn("http://127.0.0.1:8080/login.php", (output / "urls" / "all_urls.txt").read_text(encoding="utf-8"))
            self.assertIn("Findings Nuclei         : 1", (output / "resumo.txt").read_text(encoding="utf-8"))

    def test_cname_takeover_archive_probe_and_har_nuclei(self):
        def runner(args, stdout_path, stderr_path):
            joined = " ".join(args)
            if args[0] == "dnsx" and "-cname" in args:
                stderr_path.write_text("", encoding="utf-8")
                stdout_path.write_text(
                    "gone.example.com [CNAME] [gone.s3.amazonaws.com]\napi.example.com [CNAME] [api.example.com]\n",
                    encoding="utf-8",
                )
                return 0
            if args[0] == "gau":
                stderr_path.write_text("", encoding="utf-8")
                stdout_path.write_text("https://old.example.com/secret\n", encoding="utf-8")
                return 0
            if args[0] == "httpx" and "archive_probe.txt" in joined:
                stderr_path.write_text("", encoding="utf-8")
                stdout_path.write_text(
                    json.dumps({"url": "https://old.example.com/secret", "status_code": 200}) + "\n",
                    encoding="utf-8",
                )
                return 0
            if args[0] == "nuclei" and "takeover_hosts.txt" in joined:
                stderr_path.write_text("", encoding="utf-8")
                stdout_path.write_text("", encoding="utf-8")
                self.assertIn("-tags", args)
                self.assertEqual(args[args.index("-tags") + 1], "takeover")
                self.assertNotIn("-H", args)
                return 0
            return fixture_runner(args, stdout_path, stderr_path)

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "recon_example.com_1"
            pipeline = Pipeline("example.com", load_settings(None, 20), output, {}, runner)
            self.assertEqual(pipeline.run(), 0)
            cnames = (output / "dns" / "cnames.tsv").read_text(encoding="utf-8")
            self.assertIn("gone.example.com\tgone.s3.amazonaws.com", cnames)
            scanned = (output / "dns" / "takeover_scanned.txt").read_text(encoding="utf-8")
            self.assertIn("gone.example.com", scanned)
            self.assertNotIn("api.example.com", scanned)
            self.assertIn("https://old.example.com/secret", (output / "urls" / "archive_live.txt").read_text(encoding="utf-8"))
            provenance = (output / "subdomains" / "provenance.tsv").read_text(encoding="utf-8")
            self.assertIn("admin.example.com\tcrtsh", provenance)
            hosts = [line.strip() for line in (output / "dns" / "resolved_hosts.txt").read_text(encoding="utf-8").splitlines()]
            gau_calls = []

            def counting(args, stdout_path, stderr_path):
                if args and args[0] == "gau":
                    gau_calls.append(args[1])
                return runner(args, stdout_path, stderr_path)

            output2 = Path(tmp) / "recon_example.com_2"
            pipeline = Pipeline("example.com", load_settings(None, 20), output2, {}, counting)
            self.assertEqual(pipeline.run(), 0)
            self.assertIn("example.com", gau_calls)
            self.assertGreater(len(set(gau_calls)), 1)
            self.assertLessEqual(len(set(gau_calls)), 30)

            seen = []

            def har_runner(args, stdout_path, stderr_path):
                seen.append(args)
                stderr_path.write_text("", encoding="utf-8")
                if args[0] == "nuclei":
                    stdout_path.write_text("", encoding="utf-8")
                    return 0
                return 7

            har_root = Path(tmp) / "harscan"
            (har_root / "live").mkdir(parents=True)
            (har_root / "har").mkdir()
            (har_root / "live" / "live_hosts.txt").write_text("https://example.com\n", encoding="utf-8")
            (har_root / "har" / "urls.txt").write_text("https://example.com\nhttps://example.com/private\n", encoding="utf-8")
            self.assertEqual(scan_har_nuclei(har_root, {"target": "example.com", "threads": 20}, har_runner), 1)
            blob = " ".join(seen[0])
            self.assertNotIn("Authorization", blob)
            self.assertNotIn("-H", seen[0])
            self.assertIn("har_nuclei_0.txt", blob)
            self.assertIn("-max-host-error", seen[0])
            self.assertEqual(scan_har_nuclei(har_root, {"target": "example.com", "tools": {"nuclei": {"enabled": False}}}, har_runner), 0)

            batch_root = Path(tmp) / "harbatch"
            (batch_root / "har").mkdir(parents=True)
            urls = [f"https://example.com/p{i}" for i in range(12)]
            (batch_root / "har" / "urls.txt").write_text("\n".join(urls) + "\n", encoding="utf-8")
            seen.clear()
            self.assertEqual(
                scan_har_nuclei(batch_root, {"target": "example.com", "threads": 20}, har_runner, batch_size=5),
                12,
            )
            self.assertEqual(len(seen), 3)
            self.assertTrue((batch_root / "nuclei" / "har_nuclei.txt").is_file())

    def test_source_map_and_js_hop_feed_endpoints(self):
        def runner(args, stdout_path, stderr_path):
            joined = " ".join(args)
            stderr_path.write_text("", encoding="utf-8")
            if args[0] == "curl" and "crt.sh" not in joined:
                url = args[-1]
                if url.endswith(".map"):
                    text = 'const path = "/api/from-map";\n'
                elif url.endswith("extra.js"):
                    text = 'fetch("/api/from-hop");\n'
                else:
                    text = 'fetch("./extra.js");\n//# sourceMappingURL=app.js.map\n'
                stdout_path.write_text(text, encoding="utf-8")
                return 0
            if args[0] == "httpx" and "js_hop.txt" in joined:
                stdout_path.write_text("https://www.example.com/extra.js\n", encoding="utf-8")
                return 0
            return fixture_runner(args, stdout_path, stderr_path)

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "recon_example.com_hop"
            pipeline = Pipeline("example.com", load_settings(None, 20), output, {}, runner)
            self.assertEqual(pipeline.run(), 0)
            endpoints = (output / "js" / "endpoints.txt").read_text(encoding="utf-8")
            self.assertIn("/api/from-map", endpoints)
            self.assertIn("/api/from-hop", endpoints)
            self.assertTrue(list((output / "js" / "content").glob("*.map")))
