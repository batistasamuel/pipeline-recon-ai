from pathlib import Path

import yaml

TOOL_NAMES = ("subfinder", "dnsx", "httpx", "katana", "gau", "nuclei")


class ConfigError(ValueError):
    pass


def _threads(value, label):
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"Threads inválidas em {label}.") from exc
    if number < 1 or number > 200:
        raise ConfigError(f"Threads inválidas em {label}. Use de 1 a 200.")
    return number


def load_settings(path, cli_threads):
    data = {}
    if path:
        file_path = Path(path)
        if file_path.is_file():
            loaded = yaml.safe_load(file_path.read_text(encoding="utf-8"))
            if loaded is None:
                loaded = {}
            if not isinstance(loaded, dict):
                raise ConfigError("config/recon.yaml precisa ser um mapa.")
            data = loaded
    default = _threads(
        cli_threads if cli_threads is not None else data.get("threads", 50),
        "threads",
    )
    tools_in = data.get("tools") or {}
    if not isinstance(tools_in, dict):
        raise ConfigError("tools precisa ser um mapa.")
    tools = {}
    for name in TOOL_NAMES:
        item = tools_in.get(name) or {}
        if not isinstance(item, dict):
            raise ConfigError(f"tools.{name} precisa ser um mapa.")
        rate = item.get("rate_limit")
        if rate is not None:
            rate = _threads(rate, f"tools.{name}.rate_limit")
        tools[name] = {
            "threads": _threads(item.get("threads", default), f"tools.{name}.threads"),
            "rate_limit": rate,
        }
    amass = tools_in.get("amass") or {}
    if not isinstance(amass, dict):
        raise ConfigError("tools.amass precisa ser um mapa.")
    timeout = amass.get("timeout_minutes", 5)
    timeout = _threads(timeout, "tools.amass.timeout_minutes")
    return {"threads": default, "tools": tools, "amass_timeout": timeout}
