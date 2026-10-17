import os
import re
from pathlib import Path
from urllib.parse import urlparse

from recon_ai.derive import origin_host

TEMPLATES_PATH = Path(__file__).resolve().parent / "dork_templates.txt"
ENGINES = ("bing", "google", "duck", "yahoo", "ask", "shodan")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
TECH_EXTRA = (
    ("jenkins", 'site:{site} intitle:"Dashboard [Jenkins]" OR inurl:jenkins'),
    ("gitlab", 'site:{site} intitle:"GitLab" inurl:"users/sign_in"'),
    ("wordpress", "site:{site} inurl:wp-login.php OR inurl:wp-config"),
    ("phpmyadmin", 'site:{site} inurl:phpmyadmin intitle:"phpMyAdmin"'),
    ("jira", 'site:{site} inurl:"/browse/" intitle:"Jira"'),
)


class DorkError(ValueError):
    pass


def load_templates():
    if not TEMPLATES_PATH.is_file():
        raise DorkError(f"Templates de dork ausentes: {TEMPLATES_PATH}")
    lines = [line.strip() for line in TEMPLATES_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        raise DorkError("Templates de dork vazios.")
    return lines


def _interesting_sites(fingerprints, target):
    sites = []
    seen = {target.casefold()}
    for row in fingerprints:
        blob = " ".join([row.get("title") or "", " ".join(row.get("tech") or [])]).casefold()
        host = origin_host(row.get("url") or "")
        if not host or host in seen:
            continue
        if any(name in blob for name, _query in TECH_EXTRA):
            seen.add(host)
            sites.append((host, blob))
    return sites


def generate_queries(target, fingerprints, max_queries):
    site = target.casefold().strip(".")
    queries = [template.replace("{site}", site) for template in load_templates()]
    for host, blob in _interesting_sites(fingerprints, site):
        for name, template in TECH_EXTRA:
            if name in blob:
                queries.append(template.replace("{site}", host))
    unique = []
    seen = set()
    for item in queries:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
        if len(unique) >= max_queries:
            break
    return unique


def parse_hits(text):
    found = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        match = URL_RE.search(line)
        if not match:
            continue
        url = match.group(0).rstrip(").,;]")
        parsed = urlparse(url)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            found.append(url)
    return found


def shodan_key(spec):
    tools = (spec or {}).get("tools") or {}
    item = tools.get("dorks") or {}
    key = str(item.get("shodan_key") or "").strip()
    if key and key != "-":
        return key
    return (os.environ.get("SHODAN_API_KEY") or "").strip()


def pages_for(max_results):
    return max(1, min(5, (int(max_results) + 9) // 10))
