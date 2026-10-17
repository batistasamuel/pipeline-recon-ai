import sys
import threading

from recon_ai.ai import AiError, CloudNotAvailable
from recon_ai.pace import DEFAULT_CLOUD_MODE, coerce_cloud_mode

# Fora da rotação até a cota/saldo voltarem. As chaves podem ficar no ambiente.
DISABLED_CLOUD_PROVIDERS = frozenset({"google-ai-studio", "deepseek"})


def make_cloud_client(env=None, mode=None):
    from recon_ai.deepseek import DeepSeekClient
    from recon_ai.gemini import GeminiClient
    from recon_ai.groq import GroqClient
    from recon_ai.nvidia import NvidiaClient

    candidates = (
        GeminiClient,
        GroqClient,
        DeepSeekClient,
        NvidiaClient,
    )
    clients = []
    for cls in candidates:
        if getattr(cls, "provider", None) in DISABLED_CLOUD_PROVIDERS:
            continue
        client = _try_client(cls, env)
        if client is not None:
            clients.append(client)
    if not clients:
        raise CloudNotAvailable("Provedor em nuvem sem chave configurada.")
    if len(clients) == 1:
        return clients[0]
    chosen = coerce_cloud_mode(mode)
    if chosen == "parallel":
        return ParallelCloudClient(clients)
    return SequentialCloudClient(clients)


def _try_client(cls, env):
    try:
        return cls(env=env) if env is not None else cls()
    except CloudNotAvailable:
        return None


class SequentialCloudClient:
    """Ordem dos clientes ativos. Uma falha passa ao próximo e fica nele."""

    def __init__(self, *clients):
        if len(clients) == 1 and isinstance(clients[0], (list, tuple)):
            clients = clients[0]
        self.clients = [item for item in clients if item is not None]
        if not self.clients:
            raise CloudNotAvailable("Provedor em nuvem sem chave configurada.")
        self._index = 0

    @property
    def provider(self):
        return getattr(self.clients[self._index], "provider", None)

    @property
    def model(self):
        return getattr(self.clients[self._index], "model", None)

    @property
    def worker_count(self):
        return 1

    def complete(self, prompt):
        return self.complete_with_usage(prompt)["result"]

    def complete_with_usage(self, prompt, json_format=True):
        last_error = None
        while self._index < len(self.clients):
            client = self.clients[self._index]
            try:
                return client.complete_with_usage(prompt, json_format=json_format)
            except AiError as exc:
                last_error = exc
                if self._index + 1 >= len(self.clients):
                    raise
                nxt = self.clients[self._index + 1]
                reason = str(exc).split(".", 1)[0].strip() or f"{client.provider} falhou"
                print(f"nuvem: {reason}; usando {nxt.provider}", file=sys.stderr, flush=True)
                self._index += 1
        raise last_error


class ParallelCloudClient:
    """Distribui prompts em round-robin. Falha de um provedor tira ele da rotação."""

    def __init__(self, clients):
        self.clients = [item for item in clients if item is not None]
        if not self.clients:
            raise CloudNotAvailable("Provedor em nuvem sem chave configurada.")
        self._lock = threading.Lock()
        self._rr = 0
        self._dead = set()
        self._last = self.clients[0]

    @property
    def provider(self):
        return getattr(self._last, "provider", "parallel")

    @property
    def model(self):
        return getattr(self._last, "model", None)

    @property
    def worker_count(self):
        with self._lock:
            live = [item for item in self.clients if id(item) not in self._dead]
        return max(1, len(live))

    def complete(self, prompt):
        return self.complete_with_usage(prompt)["result"]

    def complete_with_usage(self, prompt, json_format=True):
        last_error = None
        tried = set()
        while True:
            client = self._pick(exclude=tried)
            if client is None:
                if last_error is not None:
                    raise last_error
                raise CloudNotAvailable("Provedor em nuvem sem chave configurada.")
            tried.add(id(client))
            try:
                usage = client.complete_with_usage(prompt, json_format=json_format)
            except AiError as exc:
                last_error = exc
                self._mark_dead(client)
                nxt = self._pick(exclude=tried)
                if nxt is not None:
                    reason = str(exc).split(".", 1)[0].strip() or f"{client.provider} falhou"
                    print(f"nuvem: {reason}; usando {nxt.provider}", file=sys.stderr, flush=True)
                continue
            self._last = client
            return usage

    def _pick(self, exclude=None):
        skip = exclude or set()
        with self._lock:
            live = [item for item in self.clients if id(item) not in self._dead and id(item) not in skip]
            if not live:
                return None
            client = live[self._rr % len(live)]
            self._rr += 1
            return client

    def _mark_dead(self, client):
        with self._lock:
            self._dead.add(id(client))


FallbackCloudClient = SequentialCloudClient
