import json
import os
import sqlite3
from pathlib import Path


def connect_readonly(path):
    database = Path(path)
    if not database.is_file():
        raise FileNotFoundError(f"Banco ausente: {database}")
    from recon_ai import db

    migrated = db.connect(database)
    migrated.close()
    connection = sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def list_runs(connection):
    rows = connection.execute(
        """
        SELECT id, target, status, output_dir, threads, started_at, finished_at
        FROM run ORDER BY started_at DESC
        """
    ).fetchall()
    return [dict(row) for row in rows]


def _counts(connection, sql, run_id):
    rows = connection.execute(sql, (run_id,)).fetchall()
    return [{"name": row[0] or "", "count": row[1]} for row in rows]


def run_view(connection, run_id, locale=None):
    from recon_ai.i18n import DEFAULT_LOCALE, display_detail, display_name, render_checklist, require_locale

    chosen = require_locale(locale or DEFAULT_LOCALE)
    run = connection.execute("SELECT * FROM run WHERE id = ?", (run_id,)).fetchone()
    if run is None:
        return None
    phases = connection.execute(
        """
        SELECT name, status, duration_s, detail, detail_key, detail_args
        FROM phase WHERE run_id = ? ORDER BY id
        """,
        (run_id,),
    ).fetchall()
    baseline = connection.execute(
        "SELECT baseline_id FROM delta_run WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    delta = connection.execute(
        """
        SELECT entity, change, key, before, after
        FROM delta_item WHERE run_id = ? ORDER BY change, entity, key
        """,
        (run_id,),
    ).fetchall()
    findings_rows = connection.execute(
        "SELECT id, severity, name, matched_at, template_id FROM finding WHERE run_id = ? ORDER BY id",
        (run_id,),
    ).fetchall()
    findings_by_id = {row["id"]: dict(row) for row in findings_rows}
    finding_dicts = []
    for row in findings_rows:
        item = dict(row)
        item["name"] = display_name(item.get("template_id"), item.get("name"), chosen)
        finding_dicts.append(item)
    candidates = [row for row in finding_dicts if str(row.get("template_id") or "").startswith("corr/")]
    ai_rows = connection.execute(
        "SELECT task, provider, model, payload FROM ai_result WHERE run_id = ? ORDER BY id",
        (run_id,),
    ).fetchall()
    routes = []
    classification = None
    ai_meta = []
    for row in ai_rows:
        ai_meta.append({"task": row["task"], "provider": row["provider"], "model": row["model"]})
        try:
            payload = json.loads(row["payload"])
        except json.JSONDecodeError:
            continue
        if row["task"] == "routes":
            routes.extend(payload.get("routes") or [])
        if row["task"] == "classification":
            items = []
            for item in payload.get("items") or []:
                finding = findings_by_id.get(item.get("finding_id"), {})
                items.append(
                    {
                        "finding_id": item.get("finding_id"),
                        "decision": item.get("decision"),
                        "reason": item.get("reason"),
                        "severity": finding.get("severity"),
                        "name": display_name(finding.get("template_id"), finding.get("name"), chosen),
                        "matched_at": finding.get("matched_at"),
                        "template_id": finding.get("template_id"),
                    }
                )
            classification = {"items": items}
    url_count = connection.execute(
        "SELECT count(*) FROM url WHERE run_id = ?",
        (run_id,),
    ).fetchone()[0]
    spec = None
    try:
        spec_row = connection.execute("SELECT payload FROM run_spec WHERE run_id = ?", (run_id,)).fetchone()
    except sqlite3.OperationalError:
        spec_row = None
    if spec_row:
        try:
            spec = json.loads(spec_row["payload"])
        except json.JSONDecodeError:
            spec = None
    phase_rows = []
    for row in phases:
        item = dict(row)
        item["detail"] = display_detail(item.get("detail"), item.get("detail_key"), item.get("detail_args"), chosen)
        phase_rows.append(item)
    current = next((row["name"] for row in phase_rows if row["status"] == "running"), None)
    from recon_ai.phases import PHASES

    by_name = {row["name"]: row["status"] for row in phase_rows}
    if "ai" not in by_name and ai_rows:
        by_name["ai"] = "ok"
    flow = [{"name": name, "status": by_name.get(name, "pending")} for name in PHASES]
    checklist = []
    clusters = []
    drafts = []
    root = os.environ.get("RECON_RESULTS")
    if root:
        output = Path(root) / run["output_dir"]
        checklist = render_checklist(output, chosen)
        from recon_ai.cluster import read_clusters
        from recon_ai.drafts import read_index

        clusters = read_clusters(output)
        try:
            drafts = read_index(output)
        except (OSError, json.JSONDecodeError):
            drafts = []
    return {
        "run": dict(run),
        "spec": spec,
        "current_phase": current,
        "flow": flow,
        "phases": phase_rows,
        "assets": _counts(
            connection,
            "SELECT kind, count(*) FROM asset WHERE run_id = ? GROUP BY kind ORDER BY kind",
            run_id,
        ),
        "findings": _counts(
            connection,
            "SELECT severity, count(*) FROM finding WHERE run_id = ? GROUP BY severity ORDER BY severity",
            run_id,
        ),
        "urls": url_count,
        "baseline_id": baseline["baseline_id"] if baseline else None,
        "delta": [dict(row) for row in delta],
        "routes": routes,
        "classification": classification,
        "ai": ai_meta,
        "candidates": candidates,
        "checklist": checklist,
        "clusters": clusters,
        "drafts": drafts,
    }


def report(connection, target=None, run_id=None, kind=None, severity=None, limit=100, locale=None):
    from recon_ai.i18n import display_name
    asset_where = ["(? IS NULL OR r.target = ?)", "(? IS NULL OR r.id = ?)", "(? IS NULL OR a.kind = ?)"]
    asset_args = [target, target, run_id, run_id, kind, kind]
    asset_sql = f"""
        SELECT r.target, r.id AS run_id, a.kind, a.value
        FROM asset a JOIN run r ON r.id = a.run_id
        WHERE {' AND '.join(asset_where)}
        ORDER BY a.value
    """
    asset_total = connection.execute(
        f"SELECT count(*) FROM ({asset_sql}) AS counted",
        asset_args,
    ).fetchone()[0]
    assets = connection.execute(asset_sql + " LIMIT ?", [*asset_args, limit]).fetchall()

    finding_where = ["(? IS NULL OR r.target = ?)", "(? IS NULL OR r.id = ?)", "(? IS NULL OR f.severity = ?)"]
    finding_args = [target, target, run_id, run_id, severity, severity]
    finding_sql = f"""
        SELECT r.target, r.id AS run_id, f.severity, f.name, f.matched_at, f.template_id
        FROM finding f JOIN run r ON r.id = f.run_id
        WHERE {' AND '.join(finding_where)}
        ORDER BY f.severity, f.template_id
    """
    finding_total = connection.execute(
        f"SELECT count(*) FROM ({finding_sql}) AS counted",
        finding_args,
    ).fetchone()[0]
    findings = connection.execute(finding_sql + " LIMIT ?", [*finding_args, limit]).fetchall()
    finding_rows = []
    for row in findings:
        item = dict(row)
        item["name"] = display_name(item.get("template_id"), item.get("name"), locale)
        finding_rows.append(item)
    return {
        "assets": {"total": asset_total, "rows": [dict(row) for row in assets]},
        "findings": {"total": finding_total, "rows": finding_rows},
    }
