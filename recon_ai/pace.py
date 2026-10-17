import threading
import time

DEFAULT_AI_DELAY_MS = 2000
MIN_AI_DELAY_MS = 10
MAX_AI_DELAY_MS = 600_000
DEFAULT_CLOUD_MODE = "sequential"
CLOUD_MODES = ("sequential", "parallel")
SKIP_WAIT = False


class PaceError(ValueError):
    pass


def coerce_ai_delay_ms(value):
    if value is None or value == "":
        return DEFAULT_AI_DELAY_MS
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise PaceError(
            f"Intervalo entre prompts inválido. Use um inteiro de {MIN_AI_DELAY_MS} a {MAX_AI_DELAY_MS} ms."
        ) from exc
    if number < MIN_AI_DELAY_MS or number > MAX_AI_DELAY_MS:
        raise PaceError(
            f"Intervalo entre prompts inválido. Use um inteiro de {MIN_AI_DELAY_MS} a {MAX_AI_DELAY_MS} ms."
        )
    return number


def coerce_cloud_mode(value):
    if value is None or value == "":
        return DEFAULT_CLOUD_MODE
    mode = str(value).strip().casefold()
    if mode not in CLOUD_MODES:
        raise PaceError("Modo de nuvem inválido. Use sequential ou parallel.")
    return mode


class Pace:
    """Espera o intervalo depois da resposta anterior, no mesmo fio."""

    def __init__(self, delay_ms):
        self.delay_s = coerce_ai_delay_ms(delay_ms) / 1000.0
        self._local = threading.local()

    def wait(self):
        if SKIP_WAIT:
            return
        last = getattr(self._local, "last", None)
        if last is None:
            return
        remain = self.delay_s - (time.monotonic() - last)
        if remain > 0:
            time.sleep(remain)

    def mark(self):
        self._local.last = time.monotonic()
