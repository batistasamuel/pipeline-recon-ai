import re

from recon_ai.openai_compat import OpenAICompatClient

DEFAULT_MODEL = "deepseek-chat"
ENDPOINT = "https://api.deepseek.com/chat/completions"
KEY_LEAK = re.compile(r"(?:sk-[A-Za-z0-9]{8,}|DEEPSEEK_API_KEY=\S+)")


class DeepSeekClient(OpenAICompatClient):
    provider = "deepseek"
    default_model = DEFAULT_MODEL
    endpoint = ENDPOINT
    key_names = ("DEEPSEEK_API_KEY",)
    model_env = "RECON_DEEPSEEK_MODEL"
    key_leak = KEY_LEAK
    missing = "DeepSeek sem chave configurada."
    label = "DeepSeek"


def read_api_key(env=None):
    return DeepSeekClient.read_api_key(env)


def mask_secrets(text):
    return DeepSeekClient.mask_secrets(text)


def cloud_model(env=None):
    return DeepSeekClient.cloud_model(env)
