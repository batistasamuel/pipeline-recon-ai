import json
from pathlib import Path

LOCALES = ("en-US", "pt-BR", "es-ES")
DEFAULT_LOCALE = "pt-BR"
_DIR = Path(__file__).resolve().parent / "locales"


class I18nError(ValueError):
    pass


def _flatten(node, prefix=""):
    flat = {}
    for key, value in node.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            flat.update(_flatten(value, path))
        else:
            flat[path] = str(value)
    return flat


def _load():
    catalogs = {}
    for locale in LOCALES:
        path = _DIR / f"{locale}.json"
        catalogs[locale] = _flatten(json.loads(path.read_text(encoding="utf-8")))
    return catalogs


CATALOGS = _load()


def require_locale(value):
    if value in LOCALES:
        return value
    raise I18nError("Idioma inválido. Use en-US, pt-BR ou es-ES.")


def locale_from_env(environ=None):
    import os

    source = os.environ if environ is None else environ
    raw = source.get("RECON_LANG")
    if raw is None or str(raw).strip() == "":
        return DEFAULT_LOCALE
    return require_locale(str(raw).strip())


def has_key(key, locale=None):
    chosen = require_locale(locale or DEFAULT_LOCALE)
    return key in CATALOGS[chosen]


def t(key, locale=None, **params):
    chosen = require_locale(locale or DEFAULT_LOCALE)
    text = CATALOGS[chosen].get(key)
    if text is None:
        return key
    for name, value in params.items():
        text = text.replace("{" + name + "}", str(value))
    return text


def display_name(template_id, stored, locale=None):
    key = f"finding.{template_id}" if template_id else ""
    if key and has_key(key, locale):
        return t(key, locale)
    return stored


def display_detail(detail, detail_key, detail_args, locale=None):
    if not detail_key:
        return detail or ""
    args = detail_args or {}
    if isinstance(args, str):
        if not args.strip():
            args = {}
        else:
            args = json.loads(args)
    return t(detail_key, locale, **args)


def render_checklist(output_dir, locale=None):
    folder = Path(output_dir) / "corr"
    structured = folder / "checklist.json"
    if structured.is_file():
        items = json.loads(structured.read_text(encoding="utf-8"))
        return [t(item["key"], locale, **(item.get("args") or {})) for item in items]
    plain = folder / "checklist.txt"
    if not plain.is_file():
        return []
    return [line for line in plain.read_text(encoding="utf-8").splitlines() if line.strip()]


def catalog_messages(locale=None):
    chosen = require_locale(locale or DEFAULT_LOCALE)
    return dict(CATALOGS[chosen])
