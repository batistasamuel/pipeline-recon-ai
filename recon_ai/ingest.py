import json
from pathlib import Path


def _lines(path):
    file_path = Path(path)
    if not file_path.is_file():
        return []
    return [line.strip() for line in file_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


def read_phases(output_dir):
    path = Path(output_dir) / "phases.tsv"
    if not path.is_file():
        raise ValueError(f"phases.tsv ausente em {output_dir}")
    rows = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw.strip():
            continue
        parts = raw.split("\t")
        if len(parts) < 2:
            raise ValueError(f"linha inválida em phases.tsv: {raw}")
        name, status = parts[0], parts[1]
        if len(parts) >= 4:
            duration_s = int(parts[2]) if parts[2] else 0
            detail = parts[3]
        else:
            duration_s = None
            detail = parts[2] if len(parts) > 2 else ""
        exit_code = 0 if status in ("ok", "warn", "skip", "running") else 1
        rows.append(
            {
                "name": name,
                "status": status,
                "exit_code": exit_code,
                "duration_s": duration_s,
                "stderr_path": str(Path(output_dir) / "logs"),
                "detail": detail,
                "detail_key": parts[4] if len(parts) > 4 else "",
                "detail_args": parts[5] if len(parts) > 5 else "",
            }
        )
    return rows


def read_assets(output_dir):
    root = Path(output_dir)
    pairs = (
        ("subdomain", root / "subdomains" / "all_subs.txt"),
        ("host", root / "dns" / "resolved_hosts.txt"),
        ("live", root / "live" / "live_hosts.txt"),
        ("unauthorized", root / "live" / "unauthorized.txt"),
        ("forbidden", root / "live" / "forbidden.txt"),
    )
    assets = []
    for kind, path in pairs:
        for value in _lines(path):
            assets.append((kind, value))
    return assets


def read_urls(output_dir):
    root = Path(output_dir)
    return sorted(set(_lines(root / "urls" / "all_urls.txt") + _lines(root / "har" / "urls.txt")))


def _read_jsonl_findings(path, kind):
    from recon_ai.catalog import build_finding

    if not path.is_file():
        return []
    findings = []
    for number, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSONL inválido em {path}:{number}") from exc
        if not isinstance(item, dict):
            raise ValueError(f"JSONL inválido em {path}:{number}")
        findings.append(build_finding(item, kind))
    return findings


def read_findings(output_dir):
    root = Path(output_dir)
    nuclei = []
    for name in ("results.jsonl", "takeover.jsonl", "har.jsonl"):
        nuclei.extend(_read_jsonl_findings(root / "nuclei" / name, "nuclei"))
    return (
        nuclei
        + _read_jsonl_findings(root / "har" / "findings.jsonl", "har")
        + _read_jsonl_findings(root / "corr" / "findings.jsonl", "corr")
    )


def run_status(phases):
    if any(row["status"] == "cancelled" for row in phases):
        return "cancelled"
    if any(row["status"] == "fail" for row in phases):
        return "failed"
    return "ok"
