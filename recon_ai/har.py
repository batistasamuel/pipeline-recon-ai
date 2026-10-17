import base64
import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from recon_ai.parse import url_allowed

MAX_HAR_BYTES = 32 * 1024 * 1024
_VERSION_RX = r"[0-9][0-9.a-z_\-]+"
_ACCOUNTS = {"a": ("capture.har", "har"), "b": ("capture-b.har", "har-b")}
_OBJECT_QUERY = {
    "id",
    "user",
    "user_id",
    "account",
    "account_id",
    "uuid",
    "doc_id",
    "order_id",
    "report_id",
}
_PATH_OBJECT = re.compile(r"/(users|user|accounts|account)/(\d+)", re.I)


def retire_candidates():
    paths = []
    override = os.environ.get("RECON_RETIRE_DB")
    if override:
        paths.append(Path(override))
    paths.extend((Path("/opt/recon/jsrepository.json"), Path("/config/jsrepository.json")))
    return paths

SECRET_PATTERNS = (
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    ("Slack Token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"), "high"),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "high"),
    ("Stripe Live Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "high"),
    ("Chave privada", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "high"),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}\b"), "medium"),
)


class HarError(ValueError):
    pass


def _skip_ws(text, idx):
    length = len(text)
    while idx < length and text[idx] in " \t\r\n":
        idx += 1
    return idx


def _object_value_start(text, start, wanted):
    decoder = json.JSONDecoder()
    idx = _skip_ws(text, start)
    if idx >= len(text) or text[idx] != "{":
        raise HarError("HAR inválido: falta objeto.")
    idx += 1
    while True:
        idx = _skip_ws(text, idx)
        if idx >= len(text):
            raise HarError("HAR inválido: JSON truncado.")
        if text[idx] == "}":
            raise HarError(f"HAR inválido: falta {wanted}.")
        if text[idx] == ",":
            idx += 1
            continue
        try:
            key, idx = decoder.raw_decode(text, idx)
        except json.JSONDecodeError as exc:
            raise HarError(f"HAR inválido: {exc}") from exc
        idx = _skip_ws(text, idx)
        if idx >= len(text) or text[idx] != ":":
            raise HarError("HAR inválido: falta ':' após chave.")
        idx = _skip_ws(text, idx + 1)
        if idx >= len(text):
            raise HarError("HAR inválido: JSON truncado.")
        if key == wanted:
            return idx
        try:
            _, idx = decoder.raw_decode(text, idx)
        except json.JSONDecodeError as exc:
            raise HarError(f"HAR inválido: {exc}") from exc


def iter_har_entries(source):
    """Percorre log.entries uma a uma, sem materializar a lista inteira."""
    path = Path(source)
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise HarError("HAR inválido: não é UTF-8.") from exc
    if text.startswith("\ufeff"):
        text = text[1:]
    log_start = _object_value_start(text, 0, "log")
    entries_start = _object_value_start(text, log_start, "entries")
    idx = _skip_ws(text, entries_start)
    if idx >= len(text) or text[idx] != "[":
        raise HarError("HAR inválido: falta log.entries.")
    idx += 1
    decoder = json.JSONDecoder()
    while True:
        idx = _skip_ws(text, idx)
        if idx >= len(text):
            raise HarError("HAR inválido: entries truncado.")
        if text[idx] == "]":
            return
        if text[idx] == ",":
            idx += 1
            continue
        try:
            entry, idx = decoder.raw_decode(text, idx)
        except json.JSONDecodeError as exc:
            raise HarError(f"HAR inválido: {exc}") from exc
        yield entry


def secret_fingerprint(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def redact(value, keep=4):
    text = str(value)
    if len(text) <= keep * 2 + 3:
        return text
    return f"{text[:keep]}…{text[-2:]}(len={len(text)})"


def retire_db_path():
    for candidate in retire_candidates():
        if candidate.is_file():
            return candidate
    return None


def _retire_hits(url, raw, db_path):
    data = json.loads(Path(db_path).read_text(encoding="utf-8"))
    fname = urlparse(url).path.rsplit("/", 1)[-1]
    digest = hashlib.sha1(raw).hexdigest() if raw else None
    found = []
    skipped_rx = 0
    for name, comp in data.items():
        if name == "retire-example" or not isinstance(comp, dict):
            continue
        extractors = comp.get("extractors") or {}
        hashes = extractors.get("hashes") or {}
        if digest and digest in hashes:
            found.append((name, hashes[digest]))
            continue
        for kind in ("uri", "filename"):
            haystack = url if kind == "uri" else fname
            for pat in extractors.get(kind) or []:
                try:
                    rx = re.compile(str(pat).replace("§§version§§", _VERSION_RX), re.I)
                except re.error:
                    skipped_rx += 1
                    continue
                match = rx.search(haystack)
                if match and match.lastindex:
                    version = match.group(1)
                    if version and re.match(r"^\d", version):
                        found.append((name, version))
    return found, skipped_rx


def _headers(part):
    found = {}
    for header in part.get("headers") or []:
        name = str(header.get("name") or "").lower()
        value = header.get("value")
        if not name:
            continue
        found.setdefault(name, []).append("" if value is None else str(value))
    return found


def _decode_body(content, url):
    text = content.get("text")
    if not text:
        return ""
    if content.get("encoding") == "base64":
        try:
            return base64.b64decode(text).decode("utf-8", "replace")
        except ValueError as exc:
            raise HarError(f"Corpo base64 inválido em {url}.") from exc
    if not isinstance(text, str):
        raise HarError(f"Corpo HAR sem texto em {url}.")
    return text


def _is_js(url, mime):
    mime = (mime or "").split(";")[0].lower()
    path = urlparse(url).path.lower()
    return "javascript" in mime or path.endswith(".js")


def _b64url_json(part):
    padded = part + "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def object_slots(method, url, status):
    if not isinstance(status, int) or status < 200 or status >= 300:
        return []
    parsed = urlparse(url)
    values = []

    def replacer(match):
        values.append(match.group(2))
        return f"/{match.group(1)}/{{id}}"

    normalized = _PATH_OBJECT.sub(replacer, parsed.path or "/")
    template = f"{parsed.netloc.casefold()}{normalized}"
    verb = str(method or "GET").upper()
    slots = []
    if values:
        slots.append(
            {
                "method": verb,
                "template": template,
                "param": "path",
                "id_fp": secret_fingerprint("|".join(values)),
            }
        )
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key.casefold() not in _OBJECT_QUERY:
            continue
        slots.append(
            {
                "method": verb,
                "template": template,
                "param": key.casefold(),
                "id_fp": secret_fingerprint(value),
            }
        )
    return slots


def _write_jsonl(path, items):
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(item, ensure_ascii=False) for item in items]
    path.write_text(("\n".join(lines) + "\n") if lines else "", encoding="utf-8")


def _read_jsonl(path):
    if not path.is_file():
        return []
    rows = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise HarError(f"JSONL inválido em {path}:{number}") from exc
        if not isinstance(item, dict):
            raise HarError(f"JSONL inválido em {path}:{number}")
        rows.append(item)
    return rows


def _merge_lines(path, values):
    existing = []
    if path.is_file():
        existing = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    merged = sorted(set(existing) | set(values))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(("\n".join(merged) + "\n") if merged else "", encoding="utf-8")
    return merged


def ingest_har(har_path, output_dir, target, in_scope=None, out_scope=None, account="a"):
    source = Path(har_path)
    if not source.is_file():
        raise HarError(f"HAR ausente: {source}")
    size = source.stat().st_size
    if size > MAX_HAR_BYTES:
        raise HarError(f"HAR acima de {MAX_HAR_BYTES} bytes ({size}).")
    if account not in _ACCOUNTS:
        raise HarError(f"Conta HAR inválida: {account}")
    capture_name, provenance = _ACCOUNTS[account]
    output = Path(output_dir)
    dest = output / "har" / capture_name
    dest.parent.mkdir(parents=True, exist_ok=True)
    if source.resolve() != dest.resolve():
        dest.write_bytes(source.read_bytes())

    urls = []
    hosts = set()
    findings = []
    requests = []
    js_written = 0
    skipped = 0
    retire_rx_skipped = 0
    retire = retire_db_path()
    content_dir = output / "js" / "content"
    content_dir.mkdir(parents=True, exist_ok=True)

    for index, entry in enumerate(iter_har_entries(dest)):
        if not isinstance(entry, dict):
            raise HarError(f"Entrada HAR {index} não é um objeto.")
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        url = request.get("url")
        if not isinstance(url, str) or not url_allowed(url, target, in_scope, out_scope):
            skipped += 1
            continue
        urls.append(url)
        hosts.add(urlparse(url).netloc)
        status = response.get("status")
        if isinstance(status, str) and status.isdigit():
            status = int(status)
        requests.extend(object_slots(request.get("method"), url, status))
        req_headers = _headers(request)
        res_headers = _headers(response)
        acao = (res_headers.get("access-control-allow-origin") or [""])[0]
        acac = (res_headers.get("access-control-allow-credentials") or [""])[0].lower()
        if acao == "*" and acac == "true":
            findings.append(
                {
                    "severity": "high",
                    "name": "CORS * com credenciais",
                    "matched_at": url,
                    "template_id": "har/cors",
                }
            )
        content = response.get("content") or {}
        mime = content.get("mimeType") or ""
        body = _decode_body(content, url) if content.get("text") else ""
        if _is_js(url, mime) and body:
            raw = body.encode("utf-8")
            digest = hashlib.sha256(raw).hexdigest()
            (content_dir / f"{digest}.js").write_text(body, encoding="utf-8")
            js_written += 1
            if retire is not None:
                hits, rx_skip = _retire_hits(url, raw, retire)
                retire_rx_skipped += rx_skip
                for lib, version in hits:
                    findings.append(
                        {
                            "severity": "medium",
                            "name": f"{lib} {version}",
                            "matched_at": url,
                            "template_id": "har/retire",
                        }
                    )
        blobs = [url, body]
        blobs.extend(req_headers.get("authorization") or [])
        for blob in blobs:
            if not blob:
                continue
            for label, pattern, severity in SECRET_PATTERNS:
                match = pattern.search(blob)
                if not match:
                    continue
                value = match.group(0)
                if label == "JWT":
                    header = {}
                    try:
                        header = _b64url_json(value.split(".", 1)[0])
                    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                        raise HarError(f"JWT ilegível em {url}.") from exc
                    if str(header.get("alg", "")).lower() == "none":
                        findings.append(
                            {
                                "severity": "high",
                                "name": "JWT alg=none",
                                "matched_at": url,
                                "template_id": "har/jwt-none",
                            }
                        )
                        continue
                    if severity != "high":
                        continue
                findings.append(
                    {
                        "severity": severity,
                        "name": label,
                        "matched_at": url,
                        "template_id": "har/secret",
                        "detail": f"{label}: {redact(value)}",
                        "fingerprint": secret_fingerprint(value),
                    }
                )

    unique_urls = _merge_lines(output / "har" / "urls.txt", urls)
    _merge_lines(output / "har" / "hosts.txt", hosts)
    from recon_ai.derive import append_provenance, write_buckets

    all_urls = _merge_lines(output / "urls" / "all_urls.txt", unique_urls)
    append_provenance(output, unique_urls, provenance)
    write_buckets(output, all_urls)
    account_dir = output / "har" / account
    seen = set()
    account_findings = []
    for item in findings:
        key = (item["template_id"], item["matched_at"], item["name"])
        if key in seen:
            continue
        seen.add(key)
        account_findings.append(item)
    _write_jsonl(account_dir / "findings.jsonl", account_findings)
    _write_jsonl(account_dir / "requests.jsonl", requests)
    union = []
    union_seen = set()
    for label in ("a", "b"):
        for item in _read_jsonl(output / "har" / label / "findings.jsonl"):
            key = (item.get("template_id"), item.get("matched_at"), item.get("name"))
            if key in union_seen:
                continue
            union_seen.add(key)
            union.append(item)
    _write_jsonl(output / "har" / "findings.jsonl", union)
    lines = union
    detail = (
        f"{len(unique_urls)} urls; {js_written} js; {len(lines)} findings; "
        f"{skipped} fora do escopo"
    )
    if retire is None:
        detail += "; retire skip (jsrepository.json ausente)"
    else:
        detail += f"; retire {retire.name}"
        if retire_rx_skipped:
            detail += f" ({retire_rx_skipped} regex JS ignoradas)"
    return {
        "urls": len(unique_urls),
        "js": js_written,
        "findings": len(lines),
        "skipped": skipped,
        "detail": detail,
        "retire": str(retire) if retire else None,
    }
