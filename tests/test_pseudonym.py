import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from recon_ai import db
from recon_ai import pace as pace_mod
from recon_ai.ai import AiError, CloudNotAvailable, analyze
from recon_ai.gemini import GeminiClient, mask_secrets, read_api_key
from recon_ai.job import normalize_spec
from recon_ai.pseudonym import (
    IdentityLeak,
    apply,
    assert_clean,
    collect_identities,
    rehydrate,
    write_map,
)
from recon_ai.runner import analyze_run


class MappingTests(unittest.TestCase):
    def test_libs_prompt_drops_the_domain(self):
        spec = normalize_spec({"target": "xpto.com"})
        mapping = collect_identities(spec)
        libs = "jQuery 3.6.0, lodash 4.17.21, React 18.2.0, nginx 1.24, OpenSSL 3.0.8, Express 4.18, moment 2.29, axios 1.6, webpack 5.88, bootstrap 5.3"
        text = f"o domínio xpto.com listou 10 bibliotecas: {libs}"
        masked = apply(text, mapping)
        self.assertNotIn("xpto.com", masked.casefold())
        self.assertIn("HOST_1", masked)
        self.assertIn("jQuery 3.6.0", masked)
        assert_clean(masked, mapping)

    def test_longest_host_wins(self):
        spec = {
            "target": "app.internal.example.com",
            "in_scope": ["app.internal.example.com", "internal.example.com"],
            "out_scope": [],
        }
        mapping = collect_identities(spec)
        masked = apply("https://app.internal.example.com/login e internal.example.com", mapping)
        self.assertNotIn("app.internal.example.com", masked.casefold())
        self.assertNotIn("internal.example.com", masked.casefold())
        self.assertIn("HOST_", masked)
        restored = rehydrate("visto em HOST_1", mapping)
        self.assertIn("app.internal.example.com", restored)

    def test_gate_rejects_leftover_target(self):
        spec = normalize_spec({"target": "xpto.com"})
        mapping = collect_identities(spec)
        with self.assertRaises(IdentityLeak):
            assert_clean("ainda fala de xpto.com", mapping)

    def test_secrets_are_redacted(self):
        spec = normalize_spec({"target": "xpto.com"})
        mapping = collect_identities(spec)
        fake_key = "AIza" + ("X" * 35)
        masked = apply(f'const k = "{fake_key}"; // xpto.com', mapping)
        self.assertNotIn(fake_key, masked)
        self.assertNotIn("xpto.com", masked.casefold())


def setUpModule():
    pace_mod.SKIP_WAIT = True


def tearDownModule():
    pace_mod.SKIP_WAIT = False


class CloudAnalyzeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.output = self.root / "recon_xpto.com_1"
        (self.output / "js" / "content").mkdir(parents=True)
        (self.output / "live").mkdir(parents=True)
        self.connection = db.connect(self.root / "recon.db")
        spec = normalize_spec({"target": "xpto.com", "cloud": True})
        self.run_id = db.new_run(self.connection, "xpto.com", self.output.name, 20, spec)
        db.finish_run(self.connection, self.run_id, "ok")

    def tearDown(self):
        self.tmp.cleanup()

    def test_cloud_masks_host_and_rehydrates_reason(self):
        self.connection.execute(
            "insert into finding (run_id, severity, name, matched_at, template_id) values (?, ?, ?, ?, ?)",
            (self.run_id, "info", "Example", "https://xpto.com/login", "corr/dangling-cname"),
        )
        self.connection.commit()
        finding_id = self.connection.execute(
            "select id from finding where run_id = ?", (self.run_id,)
        ).fetchone()["id"]
        seen = {}

        class Capture:
            provider = "google-ai-studio"
            model = "gemini-flash-latest"

            def complete_with_usage(self, prompt, json_format=True):
                seen["prompt"] = prompt
                self.assertNotIn("xpto.com", prompt.casefold())
                return {
                    "result": {
                        "items": [
                            {
                                "finding_id": finding_id,
                                "decision": "review",
                                "reason": "HOST_1 expõe login",
                            }
                        ]
                    },
                    "prompt_eval_count": 10,
                    "eval_count": 4,
                    "done_reason": "stop",
                }

            def assertNotIn(self, needle, haystack):
                if needle in haystack:
                    raise AssertionError(needle)

        rows = analyze(self.connection, self.run_id, self.root, Capture(), cloud=True)
        classification = next(item for item in rows if item[0] == "classification")
        self.assertEqual(classification[1], "google-ai-studio")
        self.assertIn("xpto.com", classification[3]["items"][0]["reason"])
        self.assertNotIn("xpto.com", seen["prompt"].casefold())
        mapped = json.loads((self.output / "ai" / "pseudonym_map.json").read_text(encoding="utf-8"))
        self.assertIn("HOST_1", mapped)

    def test_tech_task_omits_hosts(self):
        (self.output / "live" / "fingerprints.jsonl").write_text(
            json.dumps({"url": "https://xpto.com", "status_code": 200, "title": "App", "tech": ["jQuery:3.6.0", "nginx"]})
            + "\n",
            encoding="utf-8",
        )
        seen = {}

        class Capture:
            provider = "google-ai-studio"
            model = "gemini-flash-latest"

            def complete_with_usage(self, prompt, json_format=True):
                seen["prompt"] = prompt
                return {
                    "result": {"items": [{"name": "jQuery", "version": "3.6.0", "note": "atualize"}]},
                    "prompt_eval_count": 8,
                    "eval_count": 3,
                    "done_reason": "stop",
                }

        rows = analyze(self.connection, self.run_id, self.root, Capture(), cloud=True)
        self.assertNotIn("xpto.com", seen["prompt"].casefold())
        tech = next(item for item in rows if item[0] == "tech")
        self.assertEqual(tech[3]["items"][0]["name"], "jQuery")

    def test_missing_key_does_not_call_the_network(self):
        env = {
            key: value
            for key, value in os.environ.items()
            if key not in {"GEMINI_API_KEY", "GOOGLE_API_KEY", "GROQ_API_KEY", "DEEPSEEK_API_KEY", "NVIDIA_API_KEY"}
        }
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(CloudNotAvailable):
                GeminiClient()
            status = analyze_run(self.connection, self.run_id, self.root, cloud=True)
        self.assertEqual(status, "failed")


class GeminiClientTests(unittest.TestCase):
    def test_reads_env_and_masks_error_bodies(self):
        self.assertEqual(read_api_key({"GEMINI_API_KEY": "  abc  "}), "abc")
        self.assertIn("[redacted]", mask_secrets("erro AQ.ExampleTestTokenNotReal000000000000000"))
        captured = {}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return json.dumps(
                    {
                        "candidates": [{"content": {"parts": [{"text": '{"routes":[]}'}]}, "finishReason": "STOP"}],
                        "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 2},
                    }
                ).encode("utf-8")

        def fake_urlopen(request, timeout=0):
            captured["url"] = request.full_url
            captured["header"] = request.get_header("X-goog-api-key")
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return FakeResponse()

        with patch("recon_ai.gemini.urllib.request.urlopen", fake_urlopen):
            usage = GeminiClient(api_key="not-a-real-key").complete_with_usage("ping")
        self.assertIn("gemini-flash-latest:generateContent", captured["url"])
        self.assertEqual(captured["header"], "not-a-real-key")
        self.assertNotIn("key=", captured["url"])
        self.assertEqual(captured["body"]["contents"][0]["parts"][0]["text"], "ping")
        self.assertEqual(usage["result"], {"routes": []})

    def test_retries_transient_503_then_succeeds(self):
        calls = {"n": 0}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return json.dumps(
                    {
                        "candidates": [
                            {"content": {"parts": [{"text": '{"items":[]}'}]}, "finishReason": "STOP"}
                        ],
                        "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1},
                    }
                ).encode("utf-8")

        def fake_urlopen(request, timeout=0):
            calls["n"] += 1
            if calls["n"] < 3:
                raise HTTPError(
                    request.full_url,
                    503,
                    "Unavailable",
                    hdrs={},
                    fp=io.BytesIO(b'{"error":{"code":503,"message":"high demand"}}'),
                )
            return FakeResponse()

        with patch("recon_ai.gemini.urllib.request.urlopen", fake_urlopen):
            with patch("recon_ai.gemini.time.sleep") as slept:
                usage = GeminiClient(api_key="not-a-real-key").complete_with_usage("ping")
        self.assertEqual(calls["n"], 3)
        self.assertEqual(slept.call_count, 2)
        self.assertEqual(usage["result"], {"items": []})

    def test_http_400_is_not_retried(self):
        calls = {"n": 0}

        def fake_urlopen(request, timeout=0):
            calls["n"] += 1
            raise HTTPError(
                request.full_url,
                400,
                "Bad Request",
                hdrs={},
                fp=io.BytesIO(b'{"error":{"code":400,"message":"bad"}}'),
            )

        with patch("recon_ai.gemini.urllib.request.urlopen", fake_urlopen):
            with patch("recon_ai.gemini.time.sleep") as slept:
                with self.assertRaises(AiError) as caught:
                    GeminiClient(api_key="not-a-real-key").complete_with_usage("ping")
        self.assertEqual(calls["n"], 1)
        slept.assert_not_called()
        self.assertIn("HTTP 400", str(caught.exception))

    def test_quota_429_is_not_retried(self):
        calls = {"n": 0}
        body = b'{"error":{"code":429,"message":"You exceeded your current quota, please check your plan and billing details."}}'

        def fake_urlopen(request, timeout=0):
            calls["n"] += 1
            raise HTTPError(request.full_url, 429, "Too Many Requests", hdrs={}, fp=io.BytesIO(body))

        with patch("recon_ai.gemini.urllib.request.urlopen", fake_urlopen):
            with patch("recon_ai.gemini.time.sleep") as slept:
                with self.assertRaises(AiError) as caught:
                    GeminiClient(api_key="not-a-real-key").complete_with_usage("ping")
        self.assertEqual(calls["n"], 1)
        slept.assert_not_called()
        self.assertIn("HTTP 429", str(caught.exception))
        self.assertIn("quota", str(caught.exception).casefold())

    def test_http_200_non_json_is_aierror(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b"<html>upstream error</html>"

        def fake_urlopen(request, timeout=0):
            return FakeResponse()

        with patch("recon_ai.gemini.urllib.request.urlopen", fake_urlopen):
            with self.assertRaises(AiError) as caught:
                GeminiClient(api_key="not-a-real-key").complete_with_usage("ping")
        self.assertIn("não é JSON", str(caught.exception))

    def test_consult_handler_stays_on_ollama(self):
        source = Path(__file__).resolve().parents[1] / "recon_ai" / "ui.py"
        text = source.read_text(encoding="utf-8")
        self.assertIn("OllamaClient", text)
        self.assertNotIn("GeminiClient", text)
        self.assertIn("traceback.print_exc()", text)

    def test_repo_tree_has_no_studio_keys(self):
        root = Path(__file__).resolve().parents[1]
        skip = {".git", "results", "node_modules", "__pycache__", ".venv", "venv"}
        leaked = []
        live = __import__("re").compile(r"\bAQ\.[A-Za-z0-9_\-]{20,}\b")
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in skip for part in path.parts) or path.name == ".env" or path.name.startswith(".env."):
                continue
            if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".woff", ".woff2", ".pptx", ".docx", ".pdf"}:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for match in live.findall(text):
                if "ExampleTestTokenNotReal" in match:
                    continue
                leaked.append(f"{path}:{match[:8]}")
        self.assertEqual(leaked, [])


if __name__ == "__main__":
    unittest.main()
