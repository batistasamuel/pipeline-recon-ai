import json
import urllib.error
import urllib.request
from pathlib import Path


def apply_skip(findings):
    for finding in findings:
        evidence = dict(finding.get("evidence") or {})
        evidence["verified"] = "skip"
        finding["evidence"] = evidence
    return findings


def _host(matched_at):
    text = (matched_at or "").strip()
    if "://" in text:
        from urllib.parse import urlparse

        return (urlparse(text).hostname or "").casefold()
    return text.split("/", 1)[0].casefold()


def _cname_targets(output_dir, host):
    path = Path(output_dir) / "dns" / "cnames.tsv"
    if not path.is_file():
        return []
    found = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw.strip():
            continue
        parts = raw.split("\t")
        if len(parts) < 2:
            continue
        if parts[0].casefold().rstrip(".") == host:
            found.append(parts[1].strip())
    return found


def _secret_still_on_disk(output_dir, fingerprint):
    path = Path(output_dir) / "js" / "secrets.jsonl"
    if not path.is_file() or not fingerprint:
        return False
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if item.get("fingerprint") == fingerprint:
            return True
    return False


def _head(url, opener=None):
    request = urllib.request.Request(url, method="HEAD")
    request.add_header("User-Agent", "recon-ai-verify")
    open_fn = opener or urllib.request.urlopen
    with open_fn(request, timeout=10) as response:
        return getattr(response, "status", None) or response.getcode()


def verify_findings(findings, output_dir, enabled=False, resolver=None, opener=None):
    if not enabled:
        return apply_skip(findings)
    for finding in findings:
        evidence = dict(finding.get("evidence") or {})
        template = finding.get("template_id") or ""
        matched = finding.get("matched_at") or ""
        if evidence.get("verified") and evidence.get("verified") != "skip":
            finding["evidence"] = evidence
            continue
        try:
            if template.endswith("dangling-cname"):
                host = _host(matched)
                targets = resolver(host) if resolver is not None else _cname_targets(output_dir, host)
                evidence["verified"] = "yes" if targets else "no"
            elif template in {"corr/tech-panel", "corr/openapi-live", "corr/dork-live-exposure"} and matched.startswith("http"):
                code = _head(matched, opener)
                evidence["verified"] = "yes" if 200 <= int(code) < 400 else "no"
            elif evidence.get("secret_fp"):
                evidence["verified"] = "yes" if _secret_still_on_disk(output_dir, evidence["secret_fp"]) else "no"
            else:
                evidence["verified"] = "skip"
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            evidence["verified"] = "no"
        finding["evidence"] = evidence
    return findings


def persist_verified(connection, run_id, findings):
    import json

    for finding in findings:
        if finding.get("id") is None:
            continue
        connection.execute(
            "UPDATE finding SET evidence = ? WHERE id = ? AND run_id = ?",
            (json.dumps(finding.get("evidence") or {}, ensure_ascii=False), finding["id"], run_id),
        )
    connection.commit()
