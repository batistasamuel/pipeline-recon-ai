import json
import os
import re
from urllib.parse import urljoin, urlparse

from recon_ai.scope import LOOPBACK_HOSTS, is_literal_host, parse_host_port

ANSI = re.compile(r"\x1b\[[0-9;]*[mK]")
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ENDPOINT = re.compile(r"(?:/api/[A-Za-z0-9_/-]+|/v[0-9]+/[A-Za-z0-9_/-]+)")


def host_in_domain(host, domain):
    host = host.lower().strip(".")
    domain = domain.lower()
    return bool(host) and (host == domain or host.endswith("." + domain))


def _target_aliases(target):
    host, port = parse_host_port(target)
    aliases = {host} if host else set()
    loopback = os.environ.get("RECON_LOOPBACK_HOST", "").strip().lower()
    if host in LOOPBACK_HOSTS and loopback:
        aliases.add(loopback)
    return aliases, host, port


def host_matches_target(host, port, target):
    aliases, target_host, target_port = _target_aliases(target)
    host = (host or "").lower().strip(".")
    if not host or not target_host:
        return False
    if host not in aliases and not host_in_domain(host, target_host):
        return False
    if target_port is None:
        return True
    return port == target_port


def _scope_lists(domain, in_scope, out_scope):
    allow = [item.casefold().strip() for item in (in_scope or []) if str(item).strip()]
    deny = [item.casefold().strip() for item in (out_scope or []) if str(item).strip()]
    if not allow:
        allow = [domain.casefold()]
    return allow, deny


def name_allowed(token, domain, in_scope=None, out_scope=None):
    from recon_ai.scope import entry_covers_host

    token = (token or "").lower().strip(".")
    if not token:
        return False
    allow, deny = _scope_lists(domain, in_scope, out_scope)
    if any(entry_covers_host(token, entry) or token == entry for entry in deny):
        return False
    aliases, target_host, _port = _target_aliases(domain)
    if is_literal_host(domain) and (token in aliases or token == domain.lower() or token == target_host):
        return True
    return any(entry_covers_host(token, entry) or token == entry for entry in allow)


def names_from_text(text, domain, in_scope=None, out_scope=None):
    found = set()
    for token in re.split(r"[^A-Za-z0-9._-]+", text):
        token = token.lower().strip(".")
        if name_allowed(token, domain, in_scope, out_scope):
            found.add(token)
    return sorted(found)


def _host_port_from_url(line):
    scheme, rest = line.split("://", 1)
    authority = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    host, port = parse_host_port(authority)
    if host is not None and port is None:
        port = 443 if scheme.lower() == "https" else 80
    return host, port


def url_allowed(line, domain, in_scope=None, out_scope=None):
    lower = line.lower()
    if not lower.startswith(("http://", "https://")):
        return False
    host, port = _host_port_from_url(line)
    if not host:
        return False
    allow, deny = _scope_lists(domain, in_scope, out_scope)
    if any(host_matches_target(host, port, entry) for entry in deny):
        return False
    if any(host_matches_target(host, port, entry) for entry in allow):
        return True
    return host_matches_target(host, port, domain)


def urls_for_domain(lines, domain, in_scope=None, out_scope=None):
    kept = []
    for raw in lines:
        line = raw.strip()
        if url_allowed(line, domain, in_scope, out_scope):
            kept.append(line)
    return sorted(set(kept))


CNAME_LINE = re.compile(r"^(\S+)\s+\[CNAME\]\s+\[([^\]]+)\]", re.I)
SOURCE_MAP = re.compile(r"sourceMappingURL=(\S+)")
JS_ABSOLUTE = re.compile(
    r"https?://[^\s\"'`<>]+?\.js(?:\?[^\s\"'`<>]*)?(?=$|[\s\"'`<>)#])",
    re.I,
)
JS_ROOTED = re.compile(r"(?:^|[\s\"'`(=])(/[A-Za-z0-9_./~-]+\.js(?:\?[A-Za-z0-9_=&%./~-]*)?)", re.I)
JS_RELATIVE = re.compile(r"""["'](\.{1,2}/[^"'\\\s]+?\.js(?:\?[^"'\\\s]*)?)["']""", re.I)


def parse_cname(text):
    rows = []
    for line in ANSI.sub("", text).splitlines():
        match = CNAME_LINE.match(line.strip())
        if not match:
            continue
        host = match.group(1).lower().strip(".")
        target = match.group(2).lower().strip(".")
        if host and target:
            rows.append((host, target))
    return rows


def source_map_url(body, script_url, domain, in_scope=None, out_scope=None):
    match = SOURCE_MAP.search(body or "")
    if not match:
        return None
    ref = match.group(1).strip().strip("\"'")
    if not ref or ref.startswith("data:"):
        return None
    absolute = urljoin(script_url, ref)
    if urlparse(absolute).netloc.casefold() != urlparse(script_url).netloc.casefold():
        return None
    if not url_allowed(absolute, domain, in_scope, out_scope):
        return None
    return absolute


def referenced_scripts(body, script_url, domain, in_scope=None, out_scope=None):
    found = list(JS_ABSOLUTE.findall(body or ""))
    found.extend(urljoin(script_url, item) for item in JS_ROOTED.findall(body or ""))
    found.extend(urljoin(script_url, item) for item in JS_RELATIVE.findall(body or ""))
    kept = []
    for url in found:
        if url_allowed(url, domain, in_scope, out_scope):
            kept.append(url)
    return sorted(set(kept))


def parse_dns(text):
    rows = []
    for line in ANSI.sub("", text).splitlines():
        if not line.strip():
            continue
        host = line.split()[0]
        for ip in IP.findall(line):
            rows.append((host, ip))
    return rows


def hosts_without_wildcard(rows, wildcard_ips):
    by_host = {}
    for host, ip in rows:
        by_host.setdefault(host, set()).add(ip)
    if not wildcard_ips:
        return sorted(by_host)
    banned = set(wildcard_ips)
    return sorted(host for host, ips in by_host.items() if ips - banned)


def classify_http(text):
    live, unauthorized, forbidden = set(), set(), set()
    for raw in text.splitlines():
        if not raw.strip():
            continue
        item = json.loads(raw)
        url = item.get("url")
        if not url:
            continue
        code = item.get("status_code", item.get("status-code", 0)) or 0
        if 200 <= code < 400:
            live.add(url)
        elif code == 401:
            unauthorized.add(url)
        elif code == 403:
            forbidden.add(url)
    return sorted(live), sorted(unauthorized), sorted(forbidden)


def js_urls(lines):
    found = []
    for line in lines:
        lower = line.lower()
        if ".js" in lower and (lower.endswith(".js") or ".js?" in lower or ".js#" in lower):
            found.append(line.strip())
    return sorted(set(found))


def endpoints_in_js(text):
    return sorted(set(ENDPOINT.findall(text)))


def nuclei_findings(text):
    findings = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSONL inválido na linha {number}") from exc
        info = item.get("info") or {}
        findings.append(
            {
                "severity": info.get("severity"),
                "name": info.get("name"),
                "matched_at": item.get("matched-at") or item.get("host"),
                "template_id": item.get("template-id") or item.get("template_id"),
            }
        )
    return findings
