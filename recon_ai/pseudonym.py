import json
import re
from pathlib import Path
from urllib.parse import urlparse

from recon_ai.har import SECRET_PATTERNS, redact

IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", re.I)
MAP_NAME = "pseudonym_map.json"


class IdentityLeak(Exception):
    pass


class Mapping:
    def __init__(self):
        self.token_to_value = {}
        self._value_to_token = {}
        self._hosts = []
        self._ips = []

    def identities(self):
        return list(self.token_to_value.values())

    def covers_host(self, host):
        folded = _fold_host(host)
        if not folded:
            return False
        for known in self._hosts:
            if folded == known or folded.endswith(f".{known}"):
                return True
        return False

    def add_host(self, host):
        folded = _fold_host(host)
        if not folded or _is_ip(folded):
            return
        if folded not in self._hosts:
            self._hosts.append(folded)

    def add_ip(self, ip):
        text = str(ip or "").strip()
        if not _is_ip(text):
            return
        if text not in self._ips:
            self._ips.append(text)

    def add_email(self, email):
        text = str(email or "").strip()
        if not text or "@" not in text:
            return
        self._assign("EMAIL", text)

    def freeze(self):
        for host in sorted(self._hosts, key=len, reverse=True):
            self._assign("HOST", host)
        for ip in sorted(self._ips, key=len, reverse=True):
            self._assign("IP", ip)

    def replacements(self):
        return sorted(self._value_to_token.items(), key=lambda item: len(item[0]), reverse=True)

    def _assign(self, prefix, value):
        key = value.casefold()
        if key in self._value_to_token:
            return self._value_to_token[key]
        index = 1 + sum(1 for token in self.token_to_value if token.startswith(f"{prefix}_"))
        token = f"{prefix}_{index}"
        self.token_to_value[token] = value
        self._value_to_token[key] = token
        return token


def _fold_host(value):
    text = str(value or "").strip().casefold()
    if not text:
        return ""
    if "://" in text:
        parsed = urlparse(text)
        text = parsed.hostname or text
    if ":" in text and not _is_ip(text):
        host, _sep, port = text.rpartition(":")
        if port.isdigit():
            text = host
    return text.strip(".")


def _is_ip(value):
    return bool(IPV4.fullmatch(str(value or "").strip()))


def host_suffixes(host):
    folded = _fold_host(host)
    if not folded or _is_ip(folded):
        return []
    labels = [part for part in folded.split(".") if part]
    if len(labels) < 2:
        return []
    return [".".join(labels[index:]) for index in range(len(labels) - 1)]


def collect_identities(spec, connection=None, run_id=None):
    mapping = Mapping()
    spec = spec or {}
    seeds = [spec.get("target"), *(spec.get("in_scope") or []), *(spec.get("out_scope") or [])]
    if connection is not None and run_id:
        from recon_ai import db

        run = db.get_run(connection, run_id)
        if run:
            seeds.append(run.get("target"))
        for kind, value in db.list_assets(connection, run_id):
            if kind in {"host", "subdomain", "live"}:
                seeds.append(value)
            if _is_ip(value) or (isinstance(value, str) and IPV4.search(value)):
                for ip in IPV4.findall(str(value)):
                    mapping.add_ip(ip)
        for finding in db.list_findings(connection, run_id):
            seeds.append(finding.get("matched_at"))
    for raw in seeds:
        if not raw:
            continue
        text = str(raw).strip()
        if _is_ip(text):
            mapping.add_ip(text)
            continue
        parsed = urlparse(text if "://" in text else f"https://{text}")
        host = parsed.hostname or _fold_host(text)
        if host and _is_ip(host):
            mapping.add_ip(host)
        for item in host_suffixes(host or text):
            mapping.add_host(item)
        if host:
            mapping.add_host(host)
    mapping.freeze()
    return mapping


def redact_secrets(text):
    out = text
    for _label, pattern, _severity in SECRET_PATTERNS:
        out = pattern.sub(lambda match: redact(match.group(0)), out)
    out = re.sub(r"\bAQ\.[A-Za-z0-9_\-]{10,}\b", lambda match: redact(match.group(0)), out)
    return out


def apply(text, mapping):
    if text is None:
        return text
    out = str(text)
    for email in EMAIL.findall(out):
        domain = email.rsplit("@", 1)[-1]
        if mapping.covers_host(domain):
            mapping.add_email(email)
    for value, token in mapping.replacements():
        out = re.sub(re.escape(value), token, out, flags=re.IGNORECASE)
    return redact_secrets(out)


def assert_clean(text, mapping):
    haystack = str(text or "").casefold()
    for value in mapping.identities():
        if value and value.casefold() in haystack:
            raise IdentityLeak("Prompt ainda contém identidade do alvo.")
    if re.search(r"\bAQ\.[A-Za-z0-9_\-]{10,}\b", str(text or "")):
        raise IdentityLeak("Prompt ainda contém identidade do alvo.")
    if re.search(r"\bAIza[0-9A-Za-z_\-]{20,}\b", str(text or "")):
        raise IdentityLeak("Prompt ainda contém identidade do alvo.")


def rehydrate(text, mapping):
    if text is None:
        return text
    out = str(text)
    for token, value in sorted(mapping.token_to_value.items(), key=lambda item: len(item[0]), reverse=True):
        out = out.replace(token, value)
    return out


def rehydrate_payload(payload, mapping):
    if isinstance(payload, str):
        return rehydrate(payload, mapping)
    if isinstance(payload, list):
        return [rehydrate_payload(item, mapping) for item in payload]
    if isinstance(payload, dict):
        return {
            key: value if key == "path" else rehydrate_payload(value, mapping)
            for key, value in payload.items()
        }
    return payload


def write_map(output_dir, mapping):
    folder = Path(output_dir) / "ai"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / MAP_NAME
    path.write_text(json.dumps(mapping.token_to_value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


class PseudonymizingClient:
    def __init__(self, inner, mapping):
        self.inner = inner
        self.mapping = mapping

    @property
    def provider(self):
        return getattr(self.inner, "provider", None)

    @property
    def model(self):
        return getattr(self.inner, "model", None)

    @property
    def worker_count(self):
        return getattr(self.inner, "worker_count", 1)

    def complete(self, prompt):
        return self.complete_with_usage(prompt)["result"]

    def complete_with_usage(self, prompt, json_format=True):
        masked = apply(prompt, self.mapping)
        assert_clean(masked, self.mapping)
        method = getattr(self.inner, "complete_with_usage", None)
        if method is not None:
            usage = method(masked, json_format) if _accepts_json_format(method) else method(masked)
        else:
            usage = {
                "result": self.inner.complete(masked),
                "prompt_eval_count": None,
                "eval_count": None,
                "done_reason": None,
            }
        usage = dict(usage)
        usage["sent_prompt"] = masked
        usage["result"] = rehydrate_payload(usage.get("result"), self.mapping)
        return usage


def _accepts_json_format(method):
    code = getattr(method, "__code__", None)
    if code is None:
        return True
    return "json_format" in code.co_varnames
