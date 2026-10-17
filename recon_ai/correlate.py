import json
from pathlib import Path
from urllib.parse import urlparse

from recon_ai import db
from recon_ai.derive import (
    hosts_in_js,
    origin_host,
    read_bucket,
    read_fingerprints,
    read_js_secrets,
    read_provenance,
)
from recon_ai.ingest import _lines
from recon_ai.parse import host_in_domain


class CorrelateError(ValueError):
    pass


PANEL_HINTS = ("jenkins", "gitlab", "phpmyadmin", "wordpress", "wp-login", "jira", "confluence")
PANEL_PATHS = ("/manage", "/wp-login", "/wp-admin", "/phpmyadmin", "/users/sign_in", "/browse/")
SENSITIVE = (
    ".env",
    ".sql",
    ".bak",
    ".backup",
    "wp-config",
    "phpinfo",
    "docker-compose",
    "swagger",
    "openapi",
    "graphql",
)


def _jsonl(path):
    if not path.is_file():
        return []
    rows = []
    for number, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CorrelateError(f"JSONL inválido em {path}:{number}") from exc
        if not isinstance(item, dict):
            raise CorrelateError(f"JSONL inválido em {path}:{number}")
        rows.append(item)
    return rows


def _host_set(urls):
    return {origin_host(url) for url in urls if origin_host(url)}


def _join_url(base, path):
    if path.startswith("http://") or path.startswith("https://"):
        return path
    parsed = urlparse(base)
    root = f"{parsed.scheme}://{parsed.netloc}"
    if not path.startswith("/"):
        path = "/" + path
    return root + path


def _live_urls(output):
    return _lines(output / "live" / "live_hosts.txt")


def _gated_urls(output):
    return (
        _lines(output / "live" / "unauthorized.txt")
        + _lines(output / "live" / "forbidden.txt")
        + _lines(output / "dorks" / "gated.txt")
    )


def _nuclei_rows(output):
    rows = []
    for name in ("results.jsonl", "takeover.jsonl", "har.jsonl"):
        rows.extend(_jsonl(output / "nuclei" / name))
    return rows


def _har_rows(output):
    return _jsonl(output / "har" / "findings.jsonl")


def _is_cors(item):
    template = str(item.get("template-id") or item.get("template_id") or "")
    name = str(item.get("name") or (item.get("info") or {}).get("name") or "")
    blob = f"{template} {name}".casefold()
    return "cors" in blob


def _nuclei_host(item):
    url = item.get("matched-at") or item.get("host") or item.get("matched_at") or ""
    return origin_host(url), url


def _lib_token(name):
    return (name or "").casefold().split()[0] if name else ""


def _sensitive(url):
    lower = url.casefold()
    return any(token in lower for token in SENSITIVE)


def _write_findings(output, findings):
    folder = output / "corr"
    folder.mkdir(parents=True, exist_ok=True)
    seen = set()
    lines = []
    unique = []
    for item in findings:
        key = (item["template_id"], item["matched_at"], item["name"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
        lines.append(json.dumps(item, ensure_ascii=False))
    path = folder / "findings.jsonl"
    path.write_text(("\n".join(lines) + "\n") if lines else "", encoding="utf-8")
    return unique


def _account_requests(output, account):
    path = output / "har" / account / "requests.jsonl"
    if not path.is_file():
        return None
    rows = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CorrelateError(f"requests.jsonl inválido em {path}:{number}") from exc
        if not isinstance(item, dict):
            raise CorrelateError(f"requests.jsonl inválido em {path}:{number}")
        rows.append(item)
    return rows


def _cross_account_findings(output):
    left = _account_requests(output, "a")
    right = _account_requests(output, "b")
    if left is None or right is None:
        return []

    def index(rows):
        grouped = {}
        for item in rows:
            key = (item.get("method"), item.get("template"), item.get("param"))
            if not all(key) or not item.get("id_fp"):
                continue
            grouped.setdefault(key, set()).add(item["id_fp"])
        return grouped

    first = index(left)
    second = index(right)
    findings = []
    for method, template, param in sorted(set(first) & set(second)):
        if first[(method, template, param)] == second[(method, template, param)]:
            continue
        findings.append(
            {
                "severity": "info",
                "name": "IDOR entre contas",
                "matched_at": f"{method} {template}",
                "template_id": "corr/idor-cross-account",
                "detail": param,
            }
        )
        if len(findings) >= 80:
            break
    return findings


def _cap(rows, limit=80):
    return rows[:limit]


def _js_not_crawled(endpoints, urls):
    blob = "\n".join(urls).casefold()
    findings = []
    for path in endpoints:
        if path.casefold() in blob:
            continue
        findings.append(
            {
                "severity": "info",
                "name": "Path JS ausente do crawl",
                "matched_at": path,
                "template_id": "corr/js-not-crawled",
            }
        )
    return _cap(findings)


def _crtsh_split(output):
    path = output / "subdomains" / "provenance.tsv"
    resolved = {line.strip().casefold().strip(".") for line in _lines(output / "dns" / "resolved_hosts.txt")}
    grouped = {}
    if path.is_file():
        for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not raw.strip():
                continue
            if "\t" not in raw:
                raise CorrelateError(f"provenance.tsv inválido em {path}:{number}")
            name, source = raw.split("\t", 1)
            grouped.setdefault(name.casefold().strip("."), set()).add(source.strip())
    resolved_only = []
    unresolved = 0
    for name, sources in grouped.items():
        if sources != {"crtsh"}:
            continue
        if name in resolved:
            resolved_only.append(name)
        else:
            unresolved += 1
    return resolved_only, unresolved


def _crtsh_findings(output):
    names, _unresolved = _crtsh_split(output)
    return _cap(
        [
            {
                "severity": "info",
                "name": "Nome só no crt.sh e resolvido",
                "matched_at": name,
                "template_id": "corr/crtsh-only",
            }
            for name in names
        ]
    )


def _dangling_findings(output, domain):
    path = output / "dns" / "cnames.tsv"
    if not path.is_file():
        return []
    live_hosts = _host_set(_lines(output / "live" / "live_hosts.txt"))
    scanned = {line.strip().casefold() for line in _lines(output / "dns" / "takeover_scanned.txt")}
    findings = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        if "\t" not in raw:
            raise CorrelateError(f"cnames.tsv inválido em {path}:{number}")
        host, target = raw.split("\t", 1)
        host = host.casefold().strip(".")
        target = target.casefold().strip(".")
        if not host or not target or host_in_domain(target, domain or ""):
            continue
        if host in live_hosts or host in scanned:
            continue
        findings.append(
            {
                "severity": "info",
                "name": "CNAME de terceiro sem passagem nuclei",
                "matched_at": f"{host} -> {target}",
                "template_id": "corr/dangling-cname",
            }
        )
    return _cap(findings)


def _bucket_candidates(output, interesting):
    catalog = (
        ("graphql", "corr/graphql-candidate", "Candidato GraphQL"),
        ("debug", "corr/debug-candidate", "Candidato debug"),
        ("upload", "corr/upload-candidate", "Candidato upload"),
    )
    findings = []
    for bucket, template, name in catalog:
        emitted = 0
        for url in read_bucket(output, bucket):
            if url not in interesting:
                continue
            findings.append(
                {
                    "severity": "info",
                    "name": name,
                    "matched_at": url,
                    "template_id": template,
                }
            )
            emitted += 1
            if emitted >= 80:
                break
    return findings


def _write_checklist(output, findings, locale=None):
    from recon_ai.i18n import DEFAULT_LOCALE, t

    chosen = locale or DEFAULT_LOCALE
    gated = _gated_urls(output)
    idor = read_bucket(output, "idor")
    har_only = [item for item in findings if item["template_id"] == "corr/har-not-crawled"]
    secrets = [item for item in findings if item["template_id"] == "corr/secret-live-session"]
    delta = [item for item in findings if item["template_id"] == "corr/delta-unscanned"]
    cross = [item for item in findings if item["template_id"] == "corr/idor-cross-account"]
    _resolved_crt, unresolved_crt = _crtsh_split(output)
    both_accounts = (output / "har" / "a" / "requests.jsonl").is_file() and (
        output / "har" / "b" / "requests.jsonl"
    ).is_file()
    items = [
        {"key": "checklist.title", "args": {}},
        {"key": "checklist.gated", "args": {"n": len(gated)}},
        {"key": "checklist.idor_urls", "args": {"n": len(idor)}},
        {"key": "checklist.har_only", "args": {"n": len(har_only)}},
        {"key": "checklist.secrets", "args": {"n": len(secrets)}},
        {"key": "checklist.delta", "args": {"n": len(delta)}},
        {
            "key": "checklist.idor_pairs" if both_accounts else "checklist.idor_manual",
            "args": {"n": len(cross)} if both_accounts else {},
        },
        {"key": "checklist.crtsh_unresolved", "args": {"n": unresolved_crt}},
        {"key": "checklist.no_exploit", "args": {}},
    ]
    lines = [t(item["key"], chosen, **(item.get("args") or {})) for item in items]
    folder = output / "corr"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "checklist.json").write_text(json.dumps(items, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (folder / "checklist.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return lines


def correlate_run(output_dir, target, connection=None, run_id=None, locale=None):
    output = Path(output_dir)
    try:
        provenance = read_provenance(output)
        fingerprints = read_fingerprints(output)
        js_secrets = read_js_secrets(output)
        shadow = hosts_in_js(output, target)
    except ValueError as exc:
        raise CorrelateError(str(exc)) from exc
    endpoints = _lines(output / "js" / "endpoints.txt")
    all_subs = {item.casefold().strip(".") for item in _lines(output / "subdomains" / "all_subs.txt")}
    live = _live_urls(output)
    gated = _gated_urls(output)
    har_urls = _lines(output / "har" / "urls.txt")
    dork_live = _lines(output / "dorks" / "live.txt")
    nuclei = _nuclei_rows(output)
    har_findings = _har_rows(output)
    findings = []

    gated_hosts = _host_set(gated)
    live_hosts = _host_set(live)
    har_hosts = _host_set(har_urls)
    live200 = {row["url"] for row in fingerprints if 200 <= int(row.get("status_code") or 0) < 400}
    live200 |= set(dork_live)

    gated_pairs = 0
    for path in endpoints:
        for base in gated:
            if gated_pairs >= 80:
                break
            findings.append(
                {
                    "severity": "info",
                    "name": "Path JS em host 401/403",
                    "matched_at": _join_url(base, path),
                    "template_id": "corr/js-on-gated-host",
                }
            )
            gated_pairs += 1
        if gated_pairs >= 80:
            break

    crawl = {"katana", "gau", "waybackurls"}
    for url in har_urls:
        sources = provenance.get(url, set())
        if not (sources & crawl):
            findings.append(
                {
                    "severity": "low",
                    "name": "URL HAR ausente do crawl",
                    "matched_at": url,
                    "template_id": "corr/har-not-crawled",
                }
            )

    har_secrets = [item for item in har_findings if item.get("template_id") == "har/secret"]
    js_by_fp = {item.get("fingerprint"): item for item in js_secrets if item.get("fingerprint")}
    for item in har_secrets:
        match = js_by_fp.get(item.get("fingerprint"))
        if not match:
            continue
        findings.append(
            {
                "severity": "high",
                "name": "Segredo JS em uso na sessão",
                "matched_at": item.get("matched_at") or item.get("matched-at"),
                "template_id": "corr/secret-live-session",
            }
        )

    har_cors_hosts = {origin_host(item.get("matched_at") or "") for item in har_findings if item.get("template_id") == "har/cors"}
    for item in nuclei:
        if not _is_cors(item):
            continue
        host, url = _nuclei_host(item)
        if host and host in har_cors_hosts:
            findings.append(
                {
                    "severity": "high",
                    "name": "CORS com credenciais no browser",
                    "matched_at": url,
                    "template_id": "corr/cors-credentialed",
                }
            )

    for item in har_findings:
        if item.get("template_id") != "har/jwt-none":
            continue
        url = item.get("matched_at") or ""
        if origin_host(url) in live_hosts:
            findings.append(
                {
                    "severity": "high",
                    "name": "JWT alg=none em host vivo",
                    "matched_at": url,
                    "template_id": "corr/jwt-none-on-live",
                }
            )

    nuclei_blob = []
    for item in nuclei:
        info = item.get("info") or {}
        nuclei_blob.append((item, _lib_token(info.get("name") or item.get("template-id") or ""), _nuclei_host(item)))
    for item in har_findings:
        if item.get("template_id") != "har/retire":
            continue
        token = _lib_token(item.get("name"))
        if not token:
            continue
        har_host = origin_host(item.get("matched_at") or "")
        for nuclei_item, nuclei_token, (host, url) in nuclei_blob:
            template = str(nuclei_item.get("template-id") or "")
            if token not in nuclei_token and token not in template.casefold():
                continue
            if har_host and host and har_host != host:
                continue
            findings.append(
                {
                    "severity": "medium",
                    "name": f"Retire + CVE {item.get('name')}",
                    "matched_at": url or item.get("matched_at"),
                    "template_id": "corr/retire-cve",
                }
            )

    archive_live = set(_lines(output / "urls" / "archive_live.txt"))
    for url, sources in provenance.items():
        archive = sources & {"gau", "waybackurls"}
        if not archive or "katana" in sources:
            continue
        if url in archive_live:
            findings.append(
                {
                    "severity": "low",
                    "name": "URL de arquivo ainda viva",
                    "matched_at": url,
                    "template_id": "corr/archive-still-live",
                }
            )

    unauthorized_hosts = _host_set(_lines(output / "live" / "unauthorized.txt"))
    for url in read_bucket(output, "idor"):
        host = origin_host(url)
        if host in unauthorized_hosts or host in har_hosts:
            findings.append(
                {
                    "severity": "info",
                    "name": "Candidato IDOR",
                    "matched_at": url,
                    "template_id": "corr/idor-candidate",
                }
            )

    panel_urls = set(read_bucket(output, "swagger")) | set(endpoints)
    for path in PANEL_PATHS:
        for base in live + gated:
            panel_urls.add(_join_url(base, path))
    for row in fingerprints:
        blob = " ".join([row.get("title") or "", " ".join(row.get("tech") or [])]).casefold()
        if not any(hint in blob for hint in PANEL_HINTS):
            continue
        host = origin_host(row.get("url") or "")
        hit = next((url for url in panel_urls if origin_host(url) == host), None)
        findings.append(
            {
                "severity": "info",
                "name": "Painel alinhado à stack",
                "matched_at": hit or row.get("url"),
                "template_id": "corr/tech-panel",
            }
        )

    for host in sorted(shadow):
        if host in all_subs or host == (target or "").casefold().strip("."):
            continue
        findings.append(
            {
                "severity": "info",
                "name": "Hostname no JS fora da enum",
                "matched_at": host,
                "template_id": "corr/shadow-host",
            }
        )

    if connection is not None and run_id is not None:
        previous = db.previous_ok_run(connection, run_id, target)
        if previous:
            before = {value for kind, value in db.list_assets(connection, previous) if kind == "live"}
            after = set(live)
            entered = sorted(after - before)
            nuclei_hosts = {_nuclei_host(item)[0] for item in nuclei}
            nuclei_skip = not nuclei
            for url in entered:
                host = origin_host(url)
                if nuclei_skip or host not in nuclei_hosts:
                    findings.append(
                        {
                            "severity": "info",
                            "name": "Host novo sem finding Nuclei",
                            "matched_at": url,
                            "template_id": "corr/delta-unscanned",
                        }
                    )

    crawl_urls = {url for url, sources in provenance.items() if sources & crawl}
    findings.extend(_cross_account_findings(output))
    findings.extend(_js_not_crawled(endpoints, _lines(output / "urls" / "all_urls.txt")))
    findings.extend(_crtsh_findings(output))
    findings.extend(_dangling_findings(output, target))
    findings.extend(_bucket_candidates(output, live200 | archive_live | set(har_urls)))

    for url in dork_live:
        if _sensitive(url):
            findings.append(
                {
                    "severity": "high",
                    "name": "Exposição indexada e viva",
                    "matched_at": url,
                    "template_id": "corr/dork-live-exposure",
                }
            )
        if url not in crawl_urls:
            findings.append(
                {
                    "severity": "low",
                    "name": "Dork vivo ausente do crawl",
                    "matched_at": url,
                    "template_id": "corr/dork-unknown-to-crawl",
                }
            )
        if "swagger" in url.casefold() or "openapi" in url.casefold() or "api-docs" in url.casefold():
            findings.append(
                {
                    "severity": "low",
                    "name": "OpenAPI/Swagger vivo",
                    "matched_at": url,
                    "template_id": "corr/openapi-live",
                }
            )

    unique = _write_findings(output, findings)
    from recon_ai.i18n import t

    _write_checklist(output, unique, locale)
    return {
        "findings": len(unique),
        "detail": t("phase.corr_ok", locale, n=len(unique)),
        "detail_key": "phase.corr_ok",
        "detail_args": {"n": len(unique)},
    }
