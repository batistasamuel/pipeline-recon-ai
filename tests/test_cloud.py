import io
import json
import os
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from recon_ai.ai import AiError, CloudNotAvailable
from recon_ai.cloud import FallbackCloudClient, make_cloud_client
from recon_ai.gemini import GeminiClient
from recon_ai.groq import GroqClient, mask_secrets, read_api_key


def _gemini_ok():
    return json.dumps(
        {
            "candidates": [
                {"content": {"parts": [{"text": '{"routes":[]}'}]}, "finishReason": "STOP"}
            ],
            "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1},
        }
    ).encode("utf-8")


def _groq_ok():
    return json.dumps(
        {
            "choices": [
                {"message": {"content": '{"routes":[{"path":"/api"}]}'}, "finish_reason": "stop"}
            ],
            "usage": {"prompt_tokens": 2, "completion_tokens": 3},
        }
    ).encode("utf-8")


def _dispatch(fake_gemini, fake_groq):
    def fake_urlopen(request, timeout=0):
        url = request.full_url
        if "generativelanguage.googleapis.com" in url:
            return fake_gemini(request, timeout=timeout)
        if "api.groq.com" in url:
            return fake_groq(request, timeout=timeout)
        raise AssertionError(f"urlopen inesperado: {url}")

    return fake_urlopen


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self._payload


class GroqClientTests(unittest.TestCase):
    def test_reads_env_and_masks_keys(self):
        self.assertEqual(read_api_key({"GROQ_API_KEY": "  gsk_abc  "}), "gsk_abc")
        self.assertIn("[redacted]", mask_secrets("erro gsk_abcdefghijklmnopqrstuv GROQ_API_KEY=x"))

    def test_posts_chat_completions(self):
        captured = {}

        def fake_urlopen(request, timeout=0):
            captured["url"] = request.full_url
            captured["auth"] = request.get_header("Authorization")
            captured["ua"] = request.get_header("User-agent")
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return FakeResponse(_groq_ok())

        with patch("urllib.request.urlopen", fake_urlopen):
            usage = GroqClient(api_key="not-a-real-key").complete_with_usage("ping")
        self.assertIn("/openai/v1/chat/completions", captured["url"])
        self.assertEqual(captured["auth"], "Bearer not-a-real-key")
        self.assertEqual(captured["ua"], "recon-ai")
        self.assertEqual(captured["body"]["response_format"], {"type": "json_object"})
        self.assertEqual(usage["result"], {"routes": [{"path": "/api"}]})
        self.assertEqual(usage["prompt_eval_count"], 2)

    def test_retries_tpm_429_not_billing_cta(self):
        calls = {"n": 0}

        def fake_urlopen(request, timeout=0):
            calls["n"] += 1
            if calls["n"] == 1:
                raise HTTPError(
                    request.full_url,
                    429,
                    "Too Many Requests",
                    hdrs={},
                    fp=io.BytesIO(
                        b'{"error":{"message":"Rate limit reached for model x on tokens per minute (TPM): Limit 8000. Please try again in 1.2s. Upgrade at https://console.groq.com/settings/billing","code":"rate_limit_exceeded"}}'
                    ),
                )
            return FakeResponse(_groq_ok())

        with patch("urllib.request.urlopen", fake_urlopen):
            with patch("recon_ai.openai_compat.time.sleep") as slept:
                usage = GroqClient(api_key="k").complete_with_usage("ping")
        self.assertEqual(calls["n"], 2)
        slept.assert_called_once()
        self.assertGreaterEqual(slept.call_args[0][0], 2)
        self.assertEqual(usage["result"]["routes"][0]["path"], "/api")


class CloudFallbackTests(unittest.TestCase):
    def test_requires_at_least_one_key(self):
        env = {
            key: value
            for key, value in os.environ.items()
                if key not in {"GEMINI_API_KEY", "GOOGLE_API_KEY", "GROQ_API_KEY", "DEEPSEEK_API_KEY", "NVIDIA_API_KEY"}
        }
        with self.assertRaises(CloudNotAvailable):
            make_cloud_client(env)

    def test_uses_groq_when_gemini_has_no_key(self):
        env = {"GROQ_API_KEY": "gsk_test"}
        client = make_cloud_client(env)
        self.assertIsInstance(client, GroqClient)

    def test_gemini_429_switches_to_groq_and_stays(self):
        gemini_calls = {"n": 0}
        groq_calls = {"n": 0}

        def fake_gemini(request, timeout=0):
            gemini_calls["n"] += 1
            raise HTTPError(
                request.full_url,
                429,
                "Too Many Requests",
                hdrs={},
                fp=io.BytesIO(
                    b'{"error":{"code":429,"message":"You exceeded your current quota, please check your plan and billing details."}}'
                ),
            )

        def fake_groq(request, timeout=0):
            groq_calls["n"] += 1
            return FakeResponse(_groq_ok())

        gemini = GeminiClient(api_key="gemini-key")
        groq = GroqClient(api_key="groq-key")
        client = FallbackCloudClient(gemini, groq)
        with patch("urllib.request.urlopen", _dispatch(fake_gemini, fake_groq)):
            first = client.complete_with_usage("a")
            second = client.complete_with_usage("b")
        self.assertEqual(gemini_calls["n"], 1)
        self.assertEqual(groq_calls["n"], 2)
        self.assertEqual(client.provider, "groq")
        self.assertEqual(first["result"]["routes"][0]["path"], "/api")
        self.assertEqual(second["result"]["routes"][0]["path"], "/api")

    def test_gemini_success_does_not_call_groq(self):
        groq_calls = {"n": 0}

        def fake_gemini(request, timeout=0):
            return FakeResponse(_gemini_ok())

        def fake_groq(request, timeout=0):
            groq_calls["n"] += 1
            return FakeResponse(_groq_ok())

        client = FallbackCloudClient(GeminiClient(api_key="g"), GroqClient(api_key="q"))
        with patch("urllib.request.urlopen", _dispatch(fake_gemini, fake_groq)):
            usage = client.complete_with_usage("ping")
        self.assertEqual(groq_calls["n"], 0)
        self.assertEqual(client.provider, "google-ai-studio")
        self.assertEqual(usage["result"], {"routes": []})

    def test_without_groq_gemini_error_propagates(self):
        def fake_gemini(request, timeout=0):
            raise HTTPError(
                request.full_url,
                500,
                "Boom",
                hdrs={},
                fp=io.BytesIO(b'{"error":{"message":"no"}}'),
            )

        with patch("recon_ai.gemini.urllib.request.urlopen", fake_gemini):
            with self.assertRaises(AiError) as caught:
                GeminiClient(api_key="g").complete_with_usage("ping")
        self.assertIn("HTTP 500", str(caught.exception))

    def test_builds_sequential_chain_and_parallel_pool(self):
        env = {
            "GEMINI_API_KEY": "g",
            "GROQ_API_KEY": "q",
            "DEEPSEEK_API_KEY": "d",
            "NVIDIA_API_KEY": "n",
        }
        sequential = make_cloud_client(env, mode="sequential")
        parallel = make_cloud_client(env, mode="parallel")
        from recon_ai.cloud import ParallelCloudClient, SequentialCloudClient

        self.assertIsInstance(sequential, SequentialCloudClient)
        self.assertEqual([item.provider for item in sequential.clients], ["groq", "nvidia"])
        self.assertIsInstance(parallel, ParallelCloudClient)
        self.assertEqual(parallel.worker_count, 2)

    def test_skips_disabled_gemini_and_deepseek_even_with_keys(self):
        env = {"GEMINI_API_KEY": "g", "DEEPSEEK_API_KEY": "d"}
        with self.assertRaises(CloudNotAvailable):
            make_cloud_client(env)

    def test_parallel_round_robin_uses_two_providers(self):
        from recon_ai.cloud import ParallelCloudClient
        from recon_ai.deepseek import DeepSeekClient

        hits = []

        class Probe:
            def __init__(self, name):
                self.provider = name
                self.model = name

            def complete_with_usage(self, prompt, json_format=True):
                hits.append(self.provider)
                return {"result": {"routes": [{"path": f"/{self.provider}"}]}}

        client = ParallelCloudClient([Probe("groq"), Probe("deepseek")])
        client.complete_with_usage("a")
        client.complete_with_usage("b")
        self.assertEqual(hits, ["groq", "deepseek"])
        self.assertEqual(DeepSeekClient(api_key="k").provider, "deepseek")


if __name__ == "__main__":
    unittest.main()
