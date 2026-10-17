import json
import re
from pathlib import Path
from urllib.parse import urlparse

from recon_ai.har import SECRET_PATTERNS, redact, secret_fingerprint

BUCKETS = (
    ("idor", re.compile(r"[?&](id|user|user_id|account|account_id|uuid|doc_id|order_id|report_id)=|/users?/\d+|/accounts?/\d+", re.I)),
    ("swagger", re.compile(r"swagger|api-docs|openapi\.json", re.I)),
    ("graphql", re.compile(r"graphql|graphiql", re.I)),
    ("debug", re.compile(r"phpinfo|/debug|stack.?trace|/actuator", re.I)),
    ("upload", re.compile(r"/uploads?(?:/|\?|$)|/files(?:/|\?|$)|/attachments?(?:/|\?|$)", re.I)),
)

HOST_IN_JS = re.compile(
    r"(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})",
    re.I,
)
INTERNAL_HOST = re.compile(
    r"(^|\.)(stg|staging|dev|internal|int|vpc|corp|lan)[-.]|\.local$|\.internal$",
    re.I,
)


def _lines(path):
    file_path = Path(path)
    if not file_path.is_file():
        return []
    return [line.strip() for line in file_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


def fingerprints_from_httpx(text):
    rows = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"httpx.json inválido na linha {number}") from exc
        if not isinstance(item, dict):
            raise ValueError(f"httpx.json inválido na linha {number}")
        url = item.get("url")
        if not url:
            continue
        tech = item.get("tech") or item.get("technologies") or []
        if isinstance(tech, str):
            tech = [tech]
        rows.append(
            {
                "url": url,
                "status_code": item.get("status_code") or item.get("status-code") or 0,
                "title": item.get("title") or "",
                "tech": list(tech),
            }
        )
    return rows


def write_fingerprints(output_dir, text):
    rows = fingerprints_from_httpx(text)
    path = Path(output_dir) / "live" / "fingerprints.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n") if rows else "", encoding="utf-8")
    return rows


def read_fingerprints(output_dir):
    path = Path(output_dir) / "live" / "fingerprints.jsonl"
    if not path.is_file():
        return []
    rows = []
    for number, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"fingerprints.jsonl inválido na linha {number}") from exc
        if not isinstance(item, dict):
            raise ValueError(f"fingerprints.jsonl inválido na linha {number}")
        rows.append(item)
    return rows


def read_provenance(output_dir):
    path = Path(output_dir) / "urls" / "provenance.tsv"
    mapping = {}
    if not path.is_file():
        return mapping
    for number, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        if not raw.strip():
            continue
        parts = raw.split("\t")
        if len(parts) != 2:
            raise ValueError(f"provenance.tsv inválido na linha {number}")
        url, source = parts[0].strip(), parts[1].strip()
        if not url or not source:
            raise ValueError(f"provenance.tsv inválido na linha {number}")
        mapping.setdefault(url, set()).add(source)
    return mapping


def append_provenance(output_dir, urls, source):
    mapping = read_provenance(output_dir)
    for url in urls:
        mapping.setdefault(url, set()).add(source)
    path = Path(output_dir) / "urls" / "provenance.tsv"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for url in sorted(mapping):
        for item in sorted(mapping[url]):
            lines.append(f"{url}\t{item}")
    path.write_text(("\n".join(lines) + "\n") if lines else "", encoding="utf-8")
    return mapping


def write_buckets(output_dir, urls):
    folder = Path(output_dir) / "urls" / "buckets"
    folder.mkdir(parents=True, exist_ok=True)
    grouped = {name: [] for name, _pattern in BUCKETS}
    for url in urls:
        for name, pattern in BUCKETS:
            if pattern.search(url):
                grouped[name].append(url)
    for name, rows in grouped.items():
        unique = sorted(set(rows))
        (folder / f"{name}.txt").write_text(("\n".join(unique) + "\n") if unique else "", encoding="utf-8")
    return grouped


def read_bucket(output_dir, name):
    return _lines(Path(output_dir) / "urls" / "buckets" / f"{name}.txt")


def scan_js_secrets(output_dir):
    folder = Path(output_dir) / "js" / "content"
    rows = []
    if not folder.is_dir():
        return rows
    for path in sorted(folder.glob("*.js")):
        body = path.read_text(encoding="utf-8", errors="replace")
        for label, pattern, severity in SECRET_PATTERNS:
            for match in pattern.finditer(body):
                value = match.group(0)
                rows.append(
                    {
                        "file": path.name,
                        "label": label,
                        "severity": severity,
                        "fingerprint": secret_fingerprint(value),
                        "detail": f"{label}: {redact(value)}",
                    }
                )
    seen = set()
    unique = []
    for item in rows:
        key = (item["fingerprint"], item["file"], item["label"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    dest = Path(output_dir) / "js" / "secrets.jsonl"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(("\n".join(json.dumps(item, ensure_ascii=False) for item in unique) + "\n") if unique else "", encoding="utf-8")
    return unique


def read_js_secrets(output_dir):
    path = Path(output_dir) / "js" / "secrets.jsonl"
    if not path.is_file():
        return []
    rows = []
    for number, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"js/secrets.jsonl inválido na linha {number}") from exc
        if not isinstance(item, dict):
            raise ValueError(f"js/secrets.jsonl inválido na linha {number}")
        rows.append(item)
    return rows


def hosts_in_js(output_dir, target):
    folder = Path(output_dir) / "js" / "content"
    found = set()
    if not folder.is_dir():
        return found
    target = (target or "").casefold().strip(".")
    for path in folder.glob("*.js"):
        body = path.read_text(encoding="utf-8", errors="replace")
        for match in HOST_IN_JS.finditer(body):
            host = match.group(1).casefold().strip(".")
            if not host or host == target:
                continue
            if host.endswith("." + target) or INTERNAL_HOST.search(host):
                found.add(host)
    return found


def origin_host(url):
    parsed = urlparse(url)
    return (parsed.hostname or "").casefold().strip(".")
