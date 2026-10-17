import json
import os
import re
import time
import urllib.error
import urllib.request

from recon_ai.ai import AiError, CloudNotAvailable

TRANSIENT_HTTP = {429, 503}
RETRY_ATTEMPTS = 8
RETRY_BASE_S = 2
RETRY_CAP_S = 60
ERROR_DETAIL_CHARS = 800
RETRY_IN = re.compile(r"try again in ([0-9]+(?:\.[0-9]+)?)s", re.I)


def _is_quota_429(detail):
    text = str(detail or "").casefold()
    if "rate_limit_exceeded" in text or "rate limit reached" in text:
        return False
    return "exceeded your current quota" in text or "insufficient_quota" in text


def _retry_http(code, detail):
    if code == 400 and "json_validate_failed" in str(detail or "").casefold():
        return True
    if code not in TRANSIENT_HTTP:
        return False
    if code == 429 and _is_quota_429(detail):
        return False
    return True


def _retry_wait_s(detail, attempt):
    match = RETRY_IN.search(str(detail or ""))
    if match:
        return min(RETRY_CAP_S, max(1, int(float(match.group(1)) + 1.5)))
    return min(RETRY_CAP_S, RETRY_BASE_S * (2 ** attempt))


def _message_text(data):
    choices = data.get("choices") or []
    if not choices:
        return None
    message = (choices[0] or {}).get("message") or {}
    return message.get("content")


class OpenAICompatClient:
    provider = "openai"
    default_model = ""
    endpoint = ""
    key_names = ()
    model_env = ""
    key_leak = re.compile(r"")
    missing = "Provedor em nuvem sem chave configurada."
    label = "Nuvem"

    def __init__(self, api_key=None, model=None, timeout=600, env=None):
        self.api_key = api_key if api_key is not None else self.read_api_key(env)
        if not self.api_key:
            raise CloudNotAvailable(self.missing)
        self.model = model or self.cloud_model(env)
        self.timeout = timeout

    @classmethod
    def read_api_key(cls, env=None):
        source = env if env is not None else os.environ
        for name in cls.key_names:
            value = (source.get(name) or "").strip()
            if value:
                return value
        return ""

    @classmethod
    def mask_secrets(cls, text):
        return cls.key_leak.sub("[redacted]", str(text or ""))

    @classmethod
    def cloud_model(cls, env=None):
        source = env if env is not None else os.environ
        return (source.get(cls.model_env) or cls.default_model).strip() or cls.default_model

    def complete(self, prompt):
        return self.complete_with_usage(prompt)["result"]

    def complete_with_usage(self, prompt, json_format=True):
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
            "stream": False,
        }
        if json_format:
            payload["response_format"] = {"type": "json_object"}
        body = json.dumps(payload).encode("utf-8")
        last_error = None
        data = None
        for attempt in range(RETRY_ATTEMPTS):
            request = urllib.request.Request(
                self.endpoint,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}",
                    "User-Agent": "recon-ai",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    data = json.loads(response.read().decode("utf-8"))
                break
            except json.JSONDecodeError as exc:
                raise AiError(f"Resposta do {self.label} não é JSON.") from exc
            except TimeoutError as exc:
                raise AiError(f"{self.label} excedeu o tempo da chamada.") from exc
            except urllib.error.HTTPError as exc:
                detail = self.mask_secrets(exc.read().decode("utf-8", "replace")[:ERROR_DETAIL_CHARS])
                last_error = AiError(f"{self.label} respondeu HTTP {exc.code}. {detail}")
                if not _retry_http(exc.code, detail) or attempt >= RETRY_ATTEMPTS - 1:
                    raise last_error from exc
                if exc.code == 400 and attempt >= 2:
                    raise last_error from exc
                time.sleep(_retry_wait_s(detail, attempt))
            except urllib.error.URLError as exc:
                if isinstance(exc.reason, TimeoutError):
                    raise AiError(f"{self.label} excedeu o tempo da chamada.") from exc
                raise AiError(f"{self.label} não está acessível.") from exc
        else:
            raise last_error
        text = _message_text(data)
        if not isinstance(text, str) or not text.strip():
            raise AiError(
                f"Resposta do {self.label} sem conteúdo JSON."
                if json_format
                else f"Resposta do {self.label} sem conteúdo."
            )
        usage = data.get("usage") or {}
        finish = ((data.get("choices") or [{}])[0] or {}).get("finish_reason")
        if json_format:
            try:
                result = json.loads(text)
            except json.JSONDecodeError as exc:
                if finish == "length":
                    raise AiError(f"Resposta do {self.label} truncada.") from exc
                raise AiError(f"Resposta do {self.label} não é JSON.") from exc
        else:
            result = text
        return {
            "result": result,
            "prompt_eval_count": usage.get("prompt_tokens"),
            "eval_count": usage.get("completion_tokens"),
            "done_reason": "length" if finish == "length" else finish,
        }
