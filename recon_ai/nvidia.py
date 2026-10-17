import re

from recon_ai.openai_compat import OpenAICompatClient

DEFAULT_MODEL = "openai/gpt-oss-20b"
ENDPOINT = "https://integrate.api.nvidia.com/v1/chat/completions"
KEY_LEAK = re.compile(r"(?:nvapi-[A-Za-z0-9_\-]{8,}|NVIDIA_API_KEY=\S+)")


class NvidiaClient(OpenAICompatClient):
    provider = "nvidia"
    default_model = DEFAULT_MODEL
    endpoint = ENDPOINT
    key_names = ("NVIDIA_API_KEY",)
    model_env = "RECON_NVIDIA_MODEL"
    key_leak = KEY_LEAK
    missing = "NVIDIA sem chave configurada."
    label = "NVIDIA"


def read_api_key(env=None):
    return NvidiaClient.read_api_key(env)


def mask_secrets(text):
    return NvidiaClient.mask_secrets(text)


def cloud_model(env=None):
    return NvidiaClient.cloud_model(env)
