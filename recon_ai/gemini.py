import json
import os
import re
import time
import urllib.error
import urllib.request

from recon_ai.ai import AiError, CloudNotAvailable

DEFAULT_MODEL = "gemini-flash-latest"
ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
TRANSIENT_HTTP = {429, 503}
RETRY_ATTEMPTS = 8
RETRY_BASE_S = 4
RETRY_CAP_S = 60
ERROR_DETAIL_CHARS = 800


def _retry_http(code, detail):
    if code not in TRANSIENT_HTTP:
        return False
    if code == 429:
        text = str(detail or "").casefold()
        if "exceeded your current quota" in text or "billing details" in text:
            return False
    return True


KEY_LEAK = re.compile(
    r"(?:AQ\.[A-Za-z0-9_\-]{10,}|AIza[0-9A-Za-z_\-]{20,}|GEMINI_API_KEY=\S+|GOOGLE_API_KEY=\S+)"
)


def read_api_key(env=None):
    source = env if env is not None else os.environ
    return (source.get("GEMINI_API_KEY") or source.get("GOOGLE_API_KEY") or "").strip()


def mask_secrets(text):
    return KEY_LEAK.sub("[redacted]", str(text or ""))


def cloud_model(env=None):
    source = env if env is not None else os.environ
    return (source.get("RECON_GEMINI_MODEL") or DEFAULT_MODEL).strip() or DEFAULT_MODEL


class GeminiClient:
    provider = "google-ai-studio"

    def __init__(self, api_key=None, model=None, timeout=600, env=None):
        self.api_key = api_key if api_key is not None else read_api_key(env)
        if not self.api_key:
            raise CloudNotAvailable("Provedor em nuvem sem chave configurada.")
        self.model = model or cloud_model(env)
        self.timeout = timeout

    def complete(self, prompt):
        return self.complete_with_usage(prompt)["result"]

    def complete_with_usage(self, prompt, json_format=True):
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        if json_format:
            payload["generationConfig"] = {"responseMimeType": "application/json"}
        body = json.dumps(payload).encode("utf-8")
        last_error = None
        for attempt in range(RETRY_ATTEMPTS):
            request = urllib.request.Request(
                ENDPOINT.format(model=self.model),
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "X-goog-api-key": self.api_key,
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    data = json.loads(response.read().decode("utf-8"))
                break
            except json.JSONDecodeError as exc:
                raise AiError("Resposta do Gemini não é JSON.") from exc
            except TimeoutError as exc:
                raise AiError("Gemini excedeu o tempo da chamada.") from exc
            except urllib.error.HTTPError as exc:
                detail = mask_secrets(exc.read().decode("utf-8", "replace")[:ERROR_DETAIL_CHARS])
                last_error = AiError(f"Gemini respondeu HTTP {exc.code}. {detail}")
                if not _retry_http(exc.code, detail) or attempt >= RETRY_ATTEMPTS - 1:
                    raise last_error from exc
                time.sleep(min(RETRY_CAP_S, RETRY_BASE_S * (2 ** attempt)))
            except urllib.error.URLError as exc:
                if isinstance(exc.reason, TimeoutError):
                    raise AiError("Gemini excedeu o tempo da chamada.") from exc
                raise AiError("Gemini não está acessível.") from exc
        else:
            raise last_error
        text = _candidate_text(data)
        if not isinstance(text, str) or not text.strip():
            raise AiError("Resposta do Gemini sem conteúdo JSON." if json_format else "Resposta do Gemini sem conteúdo.")
        usage = data.get("usageMetadata") or {}
        finish = ((data.get("candidates") or [{}])[0] or {}).get("finishReason")
        if json_format:
            try:
                result = json.loads(text)
            except json.JSONDecodeError as exc:
                if finish == "MAX_TOKENS":
                    raise AiError("Resposta do Gemini truncada.") from exc
                raise AiError("Resposta do Gemini não é JSON.") from exc
        else:
            result = text
        return {
            "result": result,
            "prompt_eval_count": usage.get("promptTokenCount"),
            "eval_count": usage.get("candidatesTokenCount"),
            "done_reason": "length" if finish == "MAX_TOKENS" else finish,
        }


def _candidate_text(data):
    candidates = data.get("candidates") or []
    if not candidates:
        return None
    parts = ((candidates[0] or {}).get("content") or {}).get("parts") or []
    chunks = [part.get("text") for part in parts if isinstance(part, dict) and part.get("text")]
    if not chunks:
        return None
    return "".join(chunks)
