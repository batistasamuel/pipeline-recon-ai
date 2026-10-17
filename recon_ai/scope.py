import os
import re
from pathlib import Path

DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)
IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost"})


def valid_domain(domain):
    return bool(domain) and DOMAIN_RE.match(domain) is not None


def parse_host_port(value):
    if not value:
        return None, None
    text = value.strip().lower()
    if text.count(":") == 1:
        host, port_s = text.split(":")
        if not host or not port_s.isdigit():
            return None, None
        port = int(port_s)
        if port < 1 or port > 65535:
            return None, None
        return host, port
    if ":" in text:
        return None, None
    return text, None


def looks_like_ipv4(host):
    return bool(host) and re.fullmatch(r"\d+(?:\.\d+){3}", host) is not None


def valid_ipv4_target(value):
    host, _port = parse_host_port(value)
    return bool(host) and IPV4_RE.match(host) is not None


def valid_target(value):
    host, port = parse_host_port(value)
    if host is None:
        return False
    if looks_like_ipv4(host):
        return IPV4_RE.match(host) is not None
    return port is None and valid_domain(host)


def is_literal_host(value):
    return valid_ipv4_target(value)


def probe_address(value):
    host, port = parse_host_port(value)
    alias = os.environ.get("RECON_LOOPBACK_HOST", "").strip()
    if alias and host in LOOPBACK_HOSTS:
        host = alias
    if port is not None:
        return f"{host}:{port}"
    return host


def output_safe_name(value):
    return value.replace(":", "_")


def domain_in_scope(domain, scope_file):
    """0 presente, 1 ausente, 2 arquivo ilegível."""
    path = Path(scope_file)
    if not path.is_file():
        return 2
    wanted = domain.casefold()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0]
        line = "".join(line.split()).casefold()
        if line and line == wanted:
            return 0
    return 1


def _entry_host(entry):
    text = (entry or "").strip().lower()
    if text.startswith("*."):
        text = text[2:]
    host, _port = parse_host_port(text)
    return host or text


def entry_covers_host(host, entry):
    host = (host or "").lower().strip(".")
    entry = (entry or "").strip().lower()
    if not host or not entry:
        return False
    if entry.startswith("*."):
        base = entry[2:]
        return host == base or host.endswith("." + base)
    if host == entry or host.endswith("." + _entry_host(entry)):
        return True
    entry_host, _port = parse_host_port(entry)
    return bool(entry_host) and (host == entry_host or host.endswith("." + entry_host))


def target_in_scope_list(target, entries):
    if not entries:
        return True
    wanted = target.casefold()
    host, _port = parse_host_port(wanted)
    for entry in entries:
        item = str(entry).casefold().strip()
        if not item:
            continue
        if item == wanted or item == (host or wanted):
            return True
        if entry_covers_host(host or wanted, item):
            return True
    return False
