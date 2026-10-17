import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from recon_ai import db
from recon_ai import pace as pace_mod
from recon_ai.ai import (
    CLASSIFY_OUTPUT_BUDGET,
    MAX_OUTPUT_TOKENS,
    MAX_PREDICT_TOKENS,
    MODEL,
    TRUNCATED_PREFIX,
    AiError,
    CloudNotAvailable,
    OllamaClient,
    _routes_prompt,
    analyze,
    classification_batches,
    estimate_prompt_tokens,
    estimated_classification_output_tokens,
    route_excerpts,
    routes_keeping_slash_paths,
    validate_classification,
    validate_routes,
    _is_unusable_json,
)


class Boom:
    def complete(self, prompt):
        raise AssertionError("o modelo não deveria ser chamado")


class Scripted:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def complete(self, prompt):
        self.calls += 1
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


class SchemaTests(unittest.TestCase):
    def test_classification_rejects_unknown_decision(self):
        with self.assertRaises(AiError):
            validate_classification(
                {"items": [{"finding_id": 1, "decision": "exploit", "reason": "x"}]},
                {1},
            )

    def test_routes_prompt_allows_only_the_routes_key(self):
        prompt = _routes_prompt("fetch('/api/a');")
        self.assertIn("somente a chave routes", prompt)
        self.assertIn('{"routes":[]}', prompt)
        self.assertNotIn("/api/v1/users", prompt)

    def test_timeout_is_a_transport_error(self):
        self.assertEqual(MAX_PREDICT_TOKENS, MAX_OUTPUT_TOKENS)
        self.assertGreater(MAX_PREDICT_TOKENS, 469)

        def raise_timeout(*args, **kwargs):
            raise TimeoutError("timed out")

        with patch("recon_ai.ai.urllib.request.urlopen", raise_timeout):
            with self.assertRaises(AiError) as caught:
                OllamaClient("http://ollama:11434").complete_with_usage("prompt")
        self.assertEqual(str(caught.exception), "Ollama excedeu o tempo da chamada.")

    def test_estimate_prompt_tokens_uses_utf8_bytes_div_3(self):
        self.assertEqual(estimate_prompt_tokens(""), 0)
        self.assertEqual(estimate_prompt_tokens("abc"), 1)
        self.assertEqual(estimate_prompt_tokens("á"), 1)
        self.assertEqual(estimate_prompt_tokens("a" * 4), 2)

    def test_complete_without_json_format_omits_format_key(self):
        captured = {}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return json.dumps(
                    {
                        "model": "qwen2.5:7b",
                        "message": {"content": "texto livre"},
                        "prompt_eval_count": 9,
                        "eval_count": 3,
                    }
                ).encode("utf-8")

        def fake_urlopen(request, timeout=None):
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["timeout"] = timeout
            return FakeResponse()

        with patch("recon_ai.ai.urllib.request.urlopen", fake_urlopen):
            usage = OllamaClient("http://ollama:11434").complete_with_usage("oi", json_format=False)
        self.assertNotIn("format", captured["body"])
        self.assertEqual(usage["result"], "texto livre")
        self.assertEqual(usage["prompt_eval_count"], 9)

    def test_truncated_json_is_a_distinct_error(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return json.dumps(
                    {
                        "model": "qwen2.5:7b",
                        "message": {"content": '{"routes":[{"path":"/a"'},
                        "eval_count": MAX_PREDICT_TOKENS,
                        "done_reason": "length",
                    }
                ).encode("utf-8")

        def fake_urlopen(request, timeout=None):
            return FakeResponse()

        with patch("recon_ai.ai.urllib.request.urlopen", fake_urlopen):
            with self.assertRaises(AiError) as caught:
                OllamaClient("http://ollama:11434").complete_with_usage("prompt")
        self.assertTrue(str(caught.exception).startswith(TRUNCATED_PREFIX))

    def test_route_excerpts_keep_the_quoted_path_and_drop_noise(self):
        body = ("x" * 12000) + 'fetch("/iframe.html");' + ("y" * 12000)
        pieces = route_excerpts(body)
        self.assertEqual(len(pieces), 1)
        self.assertIn("/iframe.html", pieces[0])
        self.assertLess(len(pieces[0]), 5000)
        self.assertLess(len(pieces[0]), len(body) // 4)

    def test_routes_require_a_path(self):
        with self.assertRaises(AiError):
            validate_routes({"routes": [{"method": "GET"}]})
        validate_routes({"routes": [{"path": "/api/v1/users", "method": "GET"}]})

    def test_routes_filter_drops_protocol_relative_and_tokens(self):
        kept = routes_keeping_slash_paths(
            {
                "routes": [
                    {"path": "/ok"},
                    {"path": "//vimeo.comHOST_48{id}.json"},
                    {"path": "/login?next=HOST_1"},
                    {"path": "https://example.com/x"},
                ]
            }
        )
        self.assertEqual(kept, {"routes": [{"path": "/ok"}]})
        validate_routes(kept)

    def test_unusable_json_from_groq_is_detected(self):
        self.assertTrue(_is_unusable_json(AiError("Groq respondeu HTTP 400. json_validate_failed")))
        self.assertTrue(_is_unusable_json(AiError("Resposta do Groq não é JSON.")))
        self.assertFalse(_is_unusable_json(AiError("Groq respondeu HTTP 500.")))

    def test_classification_batches_keep_output_under_predict(self):
        findings = [
            {
                "id": index,
                "severity": "low",
                "template_id": "corr/har-not-crawled",
                "name": "URL HAR ausente do crawl",
                "matched_at": f"https://example.com/p{index}?CTRL={index}",
            }
            for index in range(1, 145)
        ]
        batches = classification_batches(findings)
        self.assertGreater(len(batches), 1)
        self.assertEqual(sum(len(batch) for batch in batches), 144)
        for batch in batches:
            self.assertLessEqual(
                estimated_classification_output_tokens(batch),
                CLASSIFY_OUTPUT_BUDGET,
            )
        self.assertGreater(
            estimated_classification_output_tokens(findings),
            MAX_PREDICT_TOKENS,
        )
        self.assertEqual(classification_batches([]), [])
        self.assertEqual(len(classification_batches(findings[:1])), 1)


def setUpModule():
    pace_mod.SKIP_WAIT = True


def tearDownModule():
    pace_mod.SKIP_WAIT = False


class AnalyzeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.output = self.root / "recon_example.com_1"
        (self.output / "js" / "content").mkdir(parents=True)
        self.connection = db.connect(self.root / "recon.db")
        self.run_id = db.new_run(self.connection, "example.com", self.output.name, 20)
        db.finish_run(self.connection, self.run_id, "ok")

    def tearDown(self):
        self.tmp.cleanup()

    def test_empty_findings_do_not_call_the_model(self):
        rows = analyze(self.connection, self.run_id, self.root, Boom())
        self.assertEqual(rows[0][0], "classification")
        self.assertEqual(rows[0][1], "none")
        self.assertEqual(rows[0][3], {"items": []})
        stored = self.connection.execute(
            "select provider, model from ai_result where run_id = ?",
            (self.run_id,),
        ).fetchall()
        self.assertEqual(stored[0]["provider"], "none")
        self.assertEqual(stored[0]["model"], "")

    def test_invalid_model_json_is_not_stored(self):
        self.connection.execute(
            "insert into finding (run_id, severity, name, matched_at, template_id) values (?, ?, ?, ?, ?)",
            (self.run_id, "high", "CNAME órfão", "https://takeover.example.com", "corr/dangling-cname"),
        )
        self.connection.commit()
        client = Scripted([{"items": []}])
        with self.assertRaises(AiError):
            analyze(self.connection, self.run_id, self.root, client)
        self.assertEqual(client.calls, 1)
        count = self.connection.execute(
            "select count(*) from ai_result where run_id = ?",
            (self.run_id,),
        ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_valid_response_is_stored_with_the_pinned_model(self):
        self.connection.execute(
            "insert into finding (run_id, severity, name, matched_at, template_id) values (?, ?, ?, ?, ?)",
            (self.run_id, "high", "CNAME órfão", "https://takeover.example.com", "corr/dangling-cname"),
        )
        self.connection.commit()
        finding_id = self.connection.execute("select id from finding").fetchone()["id"]
        (self.output / "js" / "content" / "app.js").write_text(
            'fetch("/api/v1/users");', encoding="utf-8"
        )
        client = Scripted(
            [
                {"routes": [{"path": "/api/v1/users", "method": "GET"}]},
                {
                    "items": [
                        {
                            "finding_id": finding_id,
                            "decision": "review",
                            "reason": "O template só observa o cabeçalho.",
                        }
                    ]
                },
                {
                    "title": "t",
                    "summary": "resumo",
                    "impact": "impacto",
                    "steps": ["passo"],
                    "evidence_notes": "evidencia",
                },
            ]
        )
        analyze(self.connection, self.run_id, self.root, client)
        self.assertEqual(client.calls, 3)
        models = [
            row["model"]
            for row in self.connection.execute(
                "select model from ai_result where provider = 'ollama'"
            )
        ]
        self.assertEqual(models, [MODEL, MODEL, MODEL])

    def test_routes_read_each_unique_file_and_skip_the_regex_list(self):
        (self.output / "js" / "endpoints.txt").write_text("/api/from-regex\n", encoding="utf-8")
        (self.output / "js" / "content" / "a.js").write_text(
            'fetch("/api/a");', encoding="utf-8"
        )
        (self.output / "js" / "content" / "a-copy.js").write_text(
            'fetch("/api/a");', encoding="utf-8"
        )
        (self.output / "js" / "content" / "b.js").write_text(
            'fetch("/api/b");', encoding="utf-8"
        )
        prompts = []

        class Capture:
            def complete(self, prompt):
                prompts.append(prompt)
                if "/api/a" in prompt:
                    return {"routes": [{"path": "/api/a", "method": "GET"}]}
                return {"routes": [{"path": "/api/b"}]}

        analyze(self.connection, self.run_id, self.root, Capture())
        self.assertEqual(len(prompts), 2)
        self.assertFalse(any("/api/from-regex" in prompt for prompt in prompts))
        stored = self.connection.execute(
            "select payload from ai_result where task = 'routes'"
        ).fetchone()["payload"]
        self.assertEqual(
            stored,
            '{"routes": [{"path": "/api/a", "method": "GET"}, {"path": "/api/b"}]}',
        )

    def test_long_file_is_split_and_routes_are_merged(self):
        body = ("x" * 20) + 'fetch("/api/tail");'
        (self.output / "js" / "content" / "big.js").write_text(body, encoding="utf-8")
        prompts = []

        class Capture:
            def complete(self, prompt):
                prompts.append(prompt)
                if "/api/tail" in prompt:
                    return {"routes": [{"path": "/api/tail", "method": "POST"}]}
                return {"routes": []}

        analyze(self.connection, self.run_id, self.root, Capture(), chunk_chars=20)
        self.assertEqual(len(prompts), 1)
        self.assertIn("/api/tail", prompts[0])
        payload = self.connection.execute(
            "select payload from ai_result where task = 'routes'"
        ).fetchone()["payload"]
        self.assertIn("/api/tail", payload)

    def test_invalid_chunk_keeps_the_previous_result(self):
        (self.output / "js" / "content" / "big.js").write_text(
            'fetch("/api/one");' + ("x" * 20) + 'fetch("/api/two");',
            encoding="utf-8",
        )
        analyze(
            self.connection,
            self.run_id,
            self.root,
            Scripted([{"routes": []}, {"routes": []}]),
            chunk_chars=30,
        )
        client = Scripted(
            [
                {"routes": [{"path": "/api/one"}]},
                {"routes": [], "method": ""},
            ]
        )
        with self.assertRaises(AiError):
            analyze(self.connection, self.run_id, self.root, client, chunk_chars=30)
        payload = self.connection.execute(
            "select payload from ai_result where task = 'routes'"
        ).fetchone()["payload"]
        self.assertEqual(payload, '{"routes": []}')
        count = self.connection.execute(
            "select count(*) from ai_result where run_id = ?",
            (self.run_id,),
        ).fetchone()[0]
        self.assertEqual(count, 2)

    def test_schema_error_continues_and_skips_publication(self):
        (self.output / "js" / "content" / "a.js").write_text('fetch("/api/a");', encoding="utf-8")
        (self.output / "js" / "content" / "b.js").write_text('fetch("/api/b");', encoding="utf-8")
        client = Scripted(
            [
                {"routes": [], "method": ""},
                {"routes": [{"path": "/api/b", "method": "GET"}]},
            ]
        )
        with self.assertRaises(AiError) as caught:
            analyze(self.connection, self.run_id, self.root, client)
        self.assertIn("1 parte(s) com erro de schema", str(caught.exception))
        self.assertIn("ai_manifest.jsonl", str(caught.exception))
        self.assertEqual(client.calls, 2)
        count = self.connection.execute(
            "select count(*) from ai_result where run_id = ?",
            (self.run_id,),
        ).fetchone()[0]
        self.assertEqual(count, 0)
        lines = [
            json.loads(line)
            for line in (self.output / "ai_manifest.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0]["valid"], False)
        self.assertEqual(lines[0]["response"], {"routes": [], "method": ""})
        self.assertEqual(lines[0]["validation_error"], "Rotas fora do schema.")
        self.assertEqual(lines[0]["error"], None)
        self.assertEqual(lines[0]["over_budget"], False)
        self.assertEqual(len(lines[0]["prompt_sha256"]), 64)
        self.assertEqual(lines[1]["valid"], True)

    def test_transport_error_stops_the_remaining_parts(self):
        (self.output / "js" / "content" / "a.js").write_text('fetch("/api/a");', encoding="utf-8")
        (self.output / "js" / "content" / "b.js").write_text('fetch("/api/b");', encoding="utf-8")
        client = Scripted(
            [
                {"routes": []},
                AiError("Ollama excedeu o tempo da chamada."),
                {"routes": [{"path": "/api/ignored"}]},
            ]
        )
        with self.assertRaises(AiError) as caught:
            analyze(self.connection, self.run_id, self.root, client)
        self.assertIn("1 com erro de transporte", str(caught.exception))
        self.assertEqual(client.calls, 2)
        lines = [
            json.loads(line)
            for line in (self.output / "ai_manifest.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(lines[1]["response"], None)
        self.assertEqual(lines[1]["validation_error"], None)
        self.assertEqual(lines[1]["error"], "Ollama excedeu o tempo da chamada.")
        self.assertEqual(lines[1]["prompt_eval_count"], None)
        self.assertEqual(lines[1]["over_budget"], False)

    def test_over_budget_part_is_still_published(self):
        (self.output / "js" / "content" / "a.js").write_text('fetch("/api/a");', encoding="utf-8")

        class Measured:
            def complete_with_usage(self, prompt):
                return {
                    "result": {"routes": [{"path": "/api/a"}]},
                    "prompt_eval_count": 13120,
                    "eval_count": 8,
                    "done_reason": "stop",
                }

        analyze(self.connection, self.run_id, self.root, Measured())
        line = json.loads((self.output / "ai_manifest.jsonl").read_text(encoding="utf-8"))
        self.assertEqual(line["valid"], True)
        self.assertEqual(line["over_budget"], True)
        self.assertEqual(line["prompt_eval_count"], 13120)
        stored = self.connection.execute(
            "select payload from ai_result where task = 'routes'"
        ).fetchone()["payload"]
        self.assertIn("/api/a", stored)

    def test_classification_failure_does_not_publish_valid_routes(self):
        self.connection.execute(
            "insert into finding (run_id, severity, name, matched_at, template_id) values (?, ?, ?, ?, ?)",
            (self.run_id, "high", "CNAME órfão", "https://takeover.example.com", "corr/dangling-cname"),
        )
        self.connection.commit()
        (self.output / "js" / "content" / "a.js").write_text('fetch("/api/a");', encoding="utf-8")
        client = Scripted(
            [
                {"routes": [{"path": "/api/a"}]},
                {"items": []},
            ]
        )
        with self.assertRaises(AiError) as caught:
            analyze(self.connection, self.run_id, self.root, client)
        self.assertIn("classificação rejeitada", str(caught.exception))
        count = self.connection.execute(
            "select count(*) from ai_result where run_id = ?",
            (self.run_id,),
        ).fetchone()[0]
        self.assertEqual(count, 0)
        lines = [
            json.loads(line)
            for line in (self.output / "ai_manifest.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(lines[0]["task"], "routes")
        self.assertEqual(lines[0]["valid"], True)
        self.assertEqual(lines[1]["task"], "classification")
        self.assertEqual(lines[1]["valid"], False)

    def test_new_command_replaces_the_manifest_and_keeps_a_published_result(self):
        (self.output / "js" / "content" / "a.js").write_text('fetch("/api/a");', encoding="utf-8")
        analyze(self.connection, self.run_id, self.root, Scripted([{"routes": [{"path": "/api/a"}]}]))
        with self.assertRaises(AiError):
            analyze(self.connection, self.run_id, self.root, Scripted([AiError("Ollama não está acessível.")]))
        lines = (self.output / "ai_manifest.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["error"], "Ollama não está acessível.")
        stored = self.connection.execute(
            "select payload from ai_result where task = 'routes'"
        ).fetchone()["payload"]
        self.assertIn("/api/a", stored)

    def test_part_without_a_literal_path_does_not_call_the_model(self):
        (self.output / "js" / "content" / "vendor.js").write_text(
            "U.dT_.fEP(bc,Ra);U.dT_.sMPS(1);xhrUrl:ra",
            encoding="utf-8",
        )
        analyze(self.connection, self.run_id, self.root, Boom())
        line = json.loads((self.output / "ai_manifest.jsonl").read_text(encoding="utf-8"))
        self.assertEqual(line["model_called"], False)
        self.assertEqual(line["response"], {"routes": []})
        stored = self.connection.execute(
            "select provider, payload from ai_result where task = 'routes'"
        ).fetchone()
        self.assertEqual(stored["provider"], "none")
        self.assertEqual(stored["payload"], '{"routes": []}')

    def test_invented_path_is_dropped(self):
        (self.output / "js" / "content" / "app.js").write_text(
            'fetch("/avisolegal.html");',
            encoding="utf-8",
        )
        analyze(
            self.connection,
            self.run_id,
            self.root,
            Scripted([{"routes": [{"path": "/avisolegal.html"}, {"path": "/ex"}]}]),
        )
        stored = self.connection.execute(
            "select payload from ai_result where task = 'routes'"
        ).fetchone()["payload"]
        self.assertEqual(stored, '{"routes": [{"path": "/avisolegal.html"}]}')

    def test_slash_only_literal_does_not_call_the_model(self):
        (self.output / "js" / "content" / "vendor.js").write_text(
            'var origin = "//"; $.getJSON(url);',
            encoding="utf-8",
        )
        analyze(self.connection, self.run_id, self.root, Boom())
        line = json.loads((self.output / "ai_manifest.jsonl").read_text(encoding="utf-8"))
        self.assertEqual(line["model_called"], False)
        self.assertEqual(line["response"], {"routes": []})

    def test_method_names_are_dropped_and_the_part_stays_valid(self):
        (self.output / "js" / "content" / "app.js").write_text(
            'fetch("/avisolegal.html"); $.get(url);',
            encoding="utf-8",
        )
        analyze(
            self.connection,
            self.run_id,
            self.root,
            Scripted(
                [
                    {
                        "routes": [
                            {"path": "load"},
                            {"path": "getJSON"},
                            {"path": "get"},
                            {"path": "post"},
                            {"path": "/avisolegal.html"},
                        ]
                    }
                ]
            ),
        )
        stored = self.connection.execute(
            "select payload from ai_result where task = 'routes'"
        ).fetchone()["payload"]
        self.assertEqual(stored, '{"routes": [{"path": "/avisolegal.html"}]}')
        count = self.connection.execute(
            "select count(*) from ai_result where run_id = ?",
            (self.run_id,),
        ).fetchone()[0]
        self.assertEqual(count, 2)

    def test_dense_file_sends_a_focused_excerpt(self):
        body = ("n" * 15000) + 'fetch("/api/users");' + ("z" * 15000)
        (self.output / "js" / "content" / "bundle.js").write_text(body, encoding="utf-8")
        prompts = []

        class Capture:
            def complete(self, prompt):
                prompts.append(prompt)
                return {"routes": [{"path": "/api/users", "method": "GET"}]}

        analyze(self.connection, self.run_id, self.root, Capture())
        self.assertEqual(len(prompts), 1)
        self.assertIn("/api/users", prompts[0])
        self.assertLess(len(prompts[0]), 8000)

    def test_truncated_output_splits_and_keeps_both_routes(self):
        (self.output / "js" / "content" / "app.js").write_text(
            'fetch("/api/one");' + ("x" * 500) + 'fetch("/api/two");',
            encoding="utf-8",
        )

        class ThenSplit:
            def __init__(self):
                self.calls = 0

            def complete_with_usage(self, prompt, json_format=True):
                self.calls += 1
                if self.calls == 1:
                    raise AiError(f"{TRUNCATED_PREFIX} (done_reason=length, eval_count=2500).")
                if "/api/one" in prompt and "/api/two" not in prompt:
                    return {"result": {"routes": [{"path": "/api/one"}]}, "prompt_eval_count": 20, "eval_count": 8, "done_reason": "stop"}
                if "/api/two" in prompt and "/api/one" not in prompt:
                    return {"result": {"routes": [{"path": "/api/two"}]}, "prompt_eval_count": 20, "eval_count": 8, "done_reason": "stop"}
                return {"result": {"routes": []}, "prompt_eval_count": 20, "eval_count": 5, "done_reason": "stop"}

        client = ThenSplit()
        analyze(self.connection, self.run_id, self.root, client)
        self.assertGreaterEqual(client.calls, 3)
        stored = self.connection.execute(
            "select payload from ai_result where task = 'routes'"
        ).fetchone()["payload"]
        self.assertIn("/api/one", stored)
        self.assertIn("/api/two", stored)

    def _insert_findings(
        self,
        count,
        template="corr/har-not-crawled",
        name="URL HAR ausente do crawl",
        url_fmt="https://example.com/p{index}",
    ):
        ids = []
        for index in range(count):
            self.connection.execute(
                "insert into finding (run_id, severity, name, matched_at, template_id) values (?, ?, ?, ?, ?)",
                (
                    self.run_id,
                    "low",
                    name,
                    url_fmt.format(index=index),
                    template,
                ),
            )
        self.connection.commit()
        for row in self.connection.execute(
            "select id from finding where run_id = ? order by id",
            (self.run_id,),
        ):
            ids.append(row["id"])
        return ids

    def test_coverage_findings_are_not_classified(self):
        self._insert_findings(144)
        rows = analyze(self.connection, self.run_id, self.root, Boom())
        self.assertEqual(rows[0][0], "classification")
        self.assertEqual(rows[0][1], "none")
        self.assertEqual(rows[0][3], {"items": []})
        clusters = json.loads((self.output / "clusters.json").read_text(encoding="utf-8"))
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["class"], "coverage")
        self.assertEqual(clusters[0]["count"], 144)
        stored = json.loads(
            self.connection.execute(
                "select payload from ai_result where task = 'classification'"
            ).fetchone()["payload"]
        )
        self.assertEqual(stored, {"items": []})
        self.assertFalse((self.output / "drafts" / "index.json").is_file())

    def test_one_reportable_among_coverage_makes_a_single_classify_call(self):
        self._insert_findings(20)
        self.connection.execute(
            "insert into finding (run_id, severity, name, matched_at, template_id) values (?, ?, ?, ?, ?)",
            (self.run_id, "high", "CNAME órfão", "https://gone.example.com", "corr/dangling-cname"),
        )
        self.connection.commit()
        finding_id = self.connection.execute(
            "select id from finding where template_id = 'corr/dangling-cname'"
        ).fetchone()["id"]
        prompts = []

        class Capture:
            def complete(self, prompt):
                prompts.append(prompt)
                if "evidence_notes" in prompt:
                    return {
                        "title": "t",
                        "summary": "resumo",
                        "impact": "impacto",
                        "steps": ["passo"],
                        "evidence_notes": "evidencia",
                    }
                found = [int(item) for item in re.findall(r"(?m)^id=(\d+) ", prompt)]
                return {
                    "items": [
                        {"finding_id": item, "decision": "keep", "reason": "takeover"}
                        for item in found
                    ]
                }

        rows = analyze(self.connection, self.run_id, self.root, Capture())
        classify_prompts = [item for item in prompts if "Classifique cada finding" in item]
        self.assertEqual(len(classify_prompts), 1)
        self.assertEqual(len(rows[0][3]["items"]), 1)
        self.assertEqual(rows[0][3]["items"][0]["finding_id"], finding_id)
        clusters = json.loads((self.output / "clusters.json").read_text(encoding="utf-8"))
        classes = {row["class"] for row in clusters}
        self.assertEqual(classes, {"coverage", "reportable"})

    def test_many_reportable_findings_are_classified_in_batches_and_merged(self):
        ids = self._insert_findings(
            144,
            "corr/dangling-cname",
            "CNAME órfão",
            "https://takeover{index}.example.com/",
        )
        classify_prompts = []

        class Capture:
            def complete(self, prompt):
                if "evidence_notes" in prompt:
                    return {
                        "title": "t",
                        "summary": "resumo",
                        "impact": "impacto",
                        "steps": ["passo"],
                        "evidence_notes": "evidencia",
                    }
                classify_prompts.append(prompt)
                found = [int(item) for item in re.findall(r"(?m)^id=(\d+) ", prompt)]
                return {
                    "items": [
                        {"finding_id": finding_id, "decision": "keep", "reason": "ok"}
                        for finding_id in found
                    ]
                }

        rows = analyze(self.connection, self.run_id, self.root, Capture())
        self.assertGreater(len(classify_prompts), 1)
        self.assertEqual(len(rows[0][3]["items"]), 144)
        stored = json.loads(
            self.connection.execute(
                "select payload from ai_result where task = 'classification'"
            ).fetchone()["payload"]
        )
        self.assertEqual([item["finding_id"] for item in stored["items"]], ids)
        lines = [
            json.loads(line)
            for line in (self.output / "ai_manifest.jsonl").read_text(encoding="utf-8").splitlines()
            if json.loads(line)["task"] == "classification"
        ]
        self.assertEqual(len(lines), len(classify_prompts))
        self.assertTrue(all(line["valid"] for line in lines))
        self.assertEqual(sum(part["count"] for line in lines for part in line["parts"]), 144)

    def test_truncated_classification_batch_is_split(self):
        ids = self._insert_findings(
            4,
            "corr/dangling-cname",
            "CNAME órfão",
            "https://takeover{index}.example.com/",
        )

        class ThenSplit:
            def __init__(self):
                self.calls = 0

            def complete_with_usage(self, prompt, json_format=True):
                if "evidence_notes" in prompt:
                    return {
                        "result": {
                            "title": "t",
                            "summary": "resumo",
                            "impact": "impacto",
                            "steps": ["passo"],
                            "evidence_notes": "evidencia",
                        },
                        "prompt_eval_count": 20,
                        "eval_count": 8,
                        "done_reason": "stop",
                    }
                self.calls += 1
                found = [int(item) for item in re.findall(r"(?m)^id=(\d+) ", prompt)]
                if self.calls == 1:
                    raise AiError(f"{TRUNCATED_PREFIX} (done_reason=length, eval_count=2500).")
                return {
                    "result": {
                        "items": [
                            {"finding_id": finding_id, "decision": "review", "reason": "ok"}
                            for finding_id in found
                        ]
                    },
                    "prompt_eval_count": 20,
                    "eval_count": 8,
                    "done_reason": "stop",
                }

        client = ThenSplit()
        analyze(self.connection, self.run_id, self.root, client)
        self.assertEqual(client.calls, 3)
        stored = json.loads(
            self.connection.execute(
                "select payload from ai_result where task = 'classification'"
            ).fetchone()["payload"]
        )
        self.assertEqual([item["finding_id"] for item in stored["items"]], ids)

    def test_classification_timeout_on_later_batch_is_not_published(self):
        self._insert_findings(
            144,
            "corr/dangling-cname",
            "CNAME órfão",
            "https://takeover{index}.example.com/",
        )
        calls = {"n": 0}

        class TimeoutLater:
            def complete(self, prompt):
                if "evidence_notes" in prompt:
                    raise AssertionError("draft não deveria rodar após falha de classificação")
                calls["n"] += 1
                found = [int(item) for item in re.findall(r"(?m)^id=(\d+) ", prompt)]
                if calls["n"] == 1:
                    return {
                        "items": [
                            {"finding_id": finding_id, "decision": "keep", "reason": "ok"}
                            for finding_id in found
                        ]
                    }
                raise AiError("Ollama excedeu o tempo da chamada.")

        with self.assertRaises(AiError) as caught:
            analyze(self.connection, self.run_id, self.root, TimeoutLater())
        self.assertIn("1 com erro de transporte", str(caught.exception))
        self.assertIn("classificação rejeitada", str(caught.exception))
        self.assertEqual(calls["n"], 2)
        count = self.connection.execute(
            "select count(*) from ai_result where run_id = ?",
            (self.run_id,),
        ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_cloud_without_injected_client_does_not_call_the_network(self):
        from recon_ai.gemini import GeminiClient
        from recon_ai.runner import analyze_run

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


if __name__ == "__main__":
    unittest.main()
