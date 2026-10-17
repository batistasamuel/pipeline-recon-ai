import re

from recon_ai.openai_compat import OpenAICompatClient

DEFAULT_MODEL = "openai/gpt-oss-120b"
ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
KEY_LEAK = re.compile(r"(?:gsk_[A-Za-z0-9]{10,}|GROQ_API_KEY=\S+)")


class GroqClient(OpenAICompatClient):
    provider = "groq"
    default_model = DEFAULT_MODEL
    endpoint = ENDPOINT
    key_names = ("GROQ_API_KEY",)
    model_env = "RECON_GROQ_MODEL"
    key_leak = KEY_LEAK
    missing = "Groq sem chave configurada."
    label = "Groq"


def read_api_key(env=None):
    return GroqClient.read_api_key(env)


def mask_secrets(text):
    return GroqClient.mask_secrets(text)


def cloud_model(env=None):
    return GroqClient.cloud_model(env)
