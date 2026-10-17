from recon_ai.i18n import DEFAULT_LOCALE, I18nError, require_locale, t
from recon_ai.scope import is_literal_host, valid_target

TOOL_CATALOG = (
    {"name": "subfinder", "phase": "subdomains", "params": ()},
    {
        "name": "amass",
        "phase": "subdomains",
        "params": (("timeout_minutes", "int", 5, 1, 200),),
    },
    {"name": "assetfinder", "phase": "subdomains", "params": ()},
    {"name": "crtsh", "phase": "subdomains", "params": ()},
    {
        "name": "dnsx",
        "phase": "dns",
        "params": (("threads", "int", 50, 1, 200),),
    },
    {
        "name": "httpx",
        "phase": "http",
        "params": (
            ("threads", "int", 50, 1, 200),
            ("timeout", "int", 10, 1, 120),
            ("retries", "int", 2, 0, 10),
        ),
    },
    {
        "name": "katana",
        "phase": "urls",
        "params": (
            ("threads", "int", 50, 1, 200),
            ("depth", "int", 3, 1, 10),
            ("timeout", "int", 10, 1, 120),
        ),
    },
    {
        "name": "gau",
        "phase": "urls",
        "params": (("threads", "int", 50, 1, 200),),
    },
    {"name": "waybackurls", "phase": "urls", "params": ()},
    {
        "name": "dorks",
        "phase": "dorks",
        "params": (
            ("engine", "string", "bing", None, None),
            ("delay_s", "int", 12, 0, 120),
            ("max_queries", "int", 24, 1, 80),
            ("max_results", "int", 20, 1, 100),
            ("proxy", "string", "-", None, None),
            ("shodan_key", "string", "-", None, None),
        ),
    },
    {
        "name": "js_httpx",
        "phase": "js",
        "params": (
            ("threads", "int", 50, 1, 200),
            ("timeout", "int", 8, 1, 120),
        ),
    },
    {
        "name": "js_curl",
        "phase": "js",
        "params": (("timeout", "int", 15, 1, 120),),
    },
    {
        "name": "nuclei",
        "phase": "nuclei",
        "params": (
            ("threads", "int", 50, 1, 200),
            ("rate_limit", "int", 150, 1, 200),
            ("severity", "string", "critical,high,medium", None, None),
            (
                "tags",
                "string",
                "cve,exposure,misconfiguration,takeover,tech,config,default-login",
                None,
                None,
            ),
            ("timeout", "int", 10, 1, 120),
            ("retries", "int", 1, 0, 10),
        ),
    },
)

TOOL_NAMES = tuple(item["name"] for item in TOOL_CATALOG)
SUBDOMAIN_SOURCES = ("subfinder", "amass", "assetfinder", "crtsh")
URL_SOURCES = ("katana", "gau", "waybackurls")

class JobError(ValueError):
    pass


def tool_catalog(locale=None):
    catalog = []
    fields = ("what", "input", "output", "place", "correlation")
    for item in TOOL_CATALOG:
        params = []
        for name, kind, default, minimum, maximum in item["params"]:
            entry = {"name": name, "type": kind, "default": default}
            if minimum is not None:
                entry["min"] = minimum
            if maximum is not None:
                entry["max"] = maximum
            params.append(entry)
        catalog.append(
            {
                "name": item["name"],
                "phase": item["phase"],
                "params": params,
                "help": {field: t(f"help.{item['name']}.{field}", locale) for field in fields},
            }
        )
    return catalog


def _defaults_for(name, threads):
    found = next(item for item in TOOL_CATALOG if item["name"] == name)
    values = {"enabled": True}
    for key, kind, default, _minimum, _maximum in found["params"]:
        values[key] = threads if key == "threads" else default
    return values


def default_spec(target, threads=50):
    tools = {name: _defaults_for(name, threads) for name in TOOL_NAMES}
    return {
        "target": target.casefold(),
        "in_scope": [target.casefold()],
        "out_scope": [],
        "threads": threads,
        "tools": tools,
    }


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    raise JobError("Lista de escopo inválida.")


def _int_param(value, spec, label):
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise JobError(f"Parâmetro inválido em {label}.") from exc
    if spec[3] is not None and number < spec[3]:
        raise JobError(f"Parâmetro inválido em {label}.")
    if spec[4] is not None and number > spec[4]:
        raise JobError(f"Parâmetro inválido em {label}.")
    return number


def _merge_tool(name, incoming, threads):
    catalog = next(item for item in TOOL_CATALOG if item["name"] == name)
    merged = _defaults_for(name, threads)
    if incoming is None:
        return merged
    if not isinstance(incoming, dict):
        raise JobError(f"tools.{name} precisa ser um mapa.")
    if "enabled" in incoming:
        merged["enabled"] = bool(incoming["enabled"])
    for spec in catalog["params"]:
        key = spec[0]
        if key not in incoming or incoming[key] is None:
            continue
        if spec[1] == "int":
            merged[key] = _int_param(incoming[key], spec, f"tools.{name}.{key}")
        else:
            text = str(incoming[key]).strip()
            if not text:
                raise JobError(f"Parâmetro inválido em tools.{name}.{key}.")
            merged[key] = text
    return merged


def tool_enabled(spec, name):
    item = (spec.get("tools") or {}).get(name) or {}
    return item.get("enabled", True)


def tool_param(spec, name, key, default=None):
    item = (spec.get("tools") or {}).get(name) or {}
    if key in item and item[key] is not None:
        return item[key]
    return default


def _check_dependencies(spec):
    target = spec["target"]
    if tool_enabled(spec, "nuclei") and not tool_enabled(spec, "httpx"):
        raise JobError("Nuclei exige httpx.")
    if tool_enabled(spec, "dorks") and not tool_enabled(spec, "httpx"):
        raise JobError("dorks exige httpx.")
    if is_literal_host(target):
        return
    if tool_enabled(spec, "httpx") and not tool_enabled(spec, "dnsx"):
        raise JobError("httpx exige dnsx.")
    if tool_enabled(spec, "dnsx") and not any(tool_enabled(spec, name) for name in SUBDOMAIN_SOURCES):
        raise JobError("dnsx exige ao menos uma fonte de subdomínios.")


def normalize_spec(raw, threads=None):
    if not isinstance(raw, dict):
        raise JobError("Job spec precisa ser um mapa.")
    target = str(raw.get("target") or "").strip()
    if not valid_target(target):
        raise JobError("Alvo inválido.")
    chosen_threads = raw.get("threads", threads if threads is not None else 50)
    try:
        chosen_threads = int(chosen_threads)
    except (TypeError, ValueError) as exc:
        raise JobError("Threads inválidas.") from exc
    if chosen_threads < 1 or chosen_threads > 200:
        raise JobError("Threads inválidas. Use um inteiro de 1 a 200.")
    incoming_tools = raw.get("tools") or {}
    if incoming_tools and not isinstance(incoming_tools, dict):
        raise JobError("tools precisa ser um mapa.")
    unknown = set(incoming_tools) - set(TOOL_NAMES)
    if unknown:
        raise JobError(f"Ferramenta desconhecida: {sorted(unknown)[0]}.")
    tools = {name: _merge_tool(name, incoming_tools.get(name), chosen_threads) for name in TOOL_NAMES}
    in_scope = [item.casefold() for item in _as_list(raw.get("in_scope"))]
    out_scope = [item.casefold() for item in _as_list(raw.get("out_scope"))]
    if not in_scope:
        in_scope = [target.casefold()]
    try:
        lang = require_locale(raw.get("lang") or DEFAULT_LOCALE)
    except I18nError as exc:
        raise JobError(str(exc)) from exc
    from recon_ai.pace import PaceError, coerce_ai_delay_ms, coerce_cloud_mode

    try:
        ai_delay_ms = coerce_ai_delay_ms(raw.get("ai_delay_ms"))
        cloud_mode = coerce_cloud_mode(raw.get("cloud_mode"))
    except PaceError as exc:
        raise JobError(str(exc)) from exc
    spec = {
        "target": target.casefold(),
        "in_scope": in_scope,
        "out_scope": out_scope,
        "threads": chosen_threads,
        "lang": lang,
        "cloud": bool(raw.get("cloud")),
        "verify": bool(raw.get("verify")),
        "ai_delay_ms": ai_delay_ms,
        "cloud_mode": cloud_mode,
        "tools": tools,
    }
    har_path = raw.get("har_path")
    if har_path:
        spec["har_path"] = str(har_path)
    har_b_path = raw.get("har_b_path")
    if har_b_path:
        spec["har_b_path"] = str(har_b_path)
    _check_dependencies(spec)
    return spec


def spec_from_settings(target, settings, in_scope=None, out_scope=None, disabled=None):
    raw = default_spec(target, settings["threads"])
    raw["in_scope"] = in_scope or [target]
    raw["out_scope"] = out_scope or []
    yaml_tools = settings.get("tools") or {}
    known = {
        item["name"]: {param[0] for param in item["params"]}
        for item in TOOL_CATALOG
    }
    for name, item in yaml_tools.items():
        if name not in raw["tools"]:
            continue
        if "threads" in known[name] and item.get("threads") is not None:
            raw["tools"][name]["threads"] = item["threads"]
        if name == "nuclei" and item.get("rate_limit") is not None:
            raw["tools"][name]["rate_limit"] = item["rate_limit"]
    amass_timeout = settings.get("amass_timeout")
    if amass_timeout is not None:
        raw["tools"]["amass"]["timeout_minutes"] = amass_timeout
    for name in disabled or []:
        if name not in raw["tools"]:
            raise JobError(f"Ferramenta desconhecida: {name}.")
        raw["tools"][name]["enabled"] = False
    return normalize_spec(raw, settings["threads"])


def apply_job_file(base, overlay):
    merged = dict(base)
    if overlay.get("target"):
        merged["target"] = overlay["target"]
    if overlay.get("threads") is not None:
        merged["threads"] = overlay["threads"]
    if overlay.get("in_scope"):
        merged["in_scope"] = overlay["in_scope"]
    if overlay.get("out_scope") is not None:
        merged["out_scope"] = overlay["out_scope"]
    if overlay.get("lang"):
        merged["lang"] = overlay["lang"]
    if "cloud" in overlay:
        merged["cloud"] = overlay["cloud"]
    if "verify" in overlay:
        merged["verify"] = overlay["verify"]
    if "ai_delay_ms" in overlay:
        merged["ai_delay_ms"] = overlay["ai_delay_ms"]
    if "cloud_mode" in overlay:
        merged["cloud_mode"] = overlay["cloud_mode"]
    tools = dict(merged.get("tools") or {})
    for name, item in (overlay.get("tools") or {}).items():
        current = dict(tools.get(name) or {})
        current.update(item)
        tools[name] = current
    merged["tools"] = tools
    return normalize_spec(merged, merged.get("threads"))


def settings_from_spec(spec):
    tools = {}
    for name, item in spec["tools"].items():
        tools[name] = dict(item)
    return {
        "threads": spec["threads"],
        "tools": tools,
        "amass_timeout": spec["tools"]["amass"]["timeout_minutes"],
        "job": spec,
    }
