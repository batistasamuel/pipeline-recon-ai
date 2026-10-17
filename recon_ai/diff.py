from pathlib import Path

from recon_ai import db

MARKER = "\n--- delta ---\n"


def _grouped(rows, key_fn, state_fn):
    grouped = {}
    for row in rows:
        grouped.setdefault(key_fn(row), set()).add(state_fn(row))
    return grouped


def _states(values):
    return ",".join(sorted(value for value in values if value))


def _changes(previous, current, entity):
    entered = []
    left = []
    changed = []
    for key in sorted(set(current) - set(previous)):
        entered.append({"entity": entity, "change": "entered", "key": key, "after": _states(current[key])})
    for key in sorted(set(previous) - set(current)):
        left.append({"entity": entity, "change": "left", "key": key, "before": _states(previous[key])})
    for key in sorted(set(previous) & set(current)):
        if previous[key] != current[key]:
            changed.append(
                {
                    "entity": entity,
                    "change": "changed",
                    "key": key,
                    "before": _states(previous[key]),
                    "after": _states(current[key]),
                }
            )
    return entered, left, changed


def compare(previous_assets, current_assets, previous_findings, current_findings):
    assets_before = _grouped(previous_assets, lambda row: row[1], lambda row: row[0])
    assets_after = _grouped(current_assets, lambda row: row[1], lambda row: row[0])
    findings_before = _grouped(
        previous_findings,
        lambda row: f"{row['template_id'] or ''} @ {row['matched_at'] or ''}",
        lambda row: row["severity"] or "",
    )
    findings_after = _grouped(
        current_findings,
        lambda row: f"{row['template_id'] or ''} @ {row['matched_at'] or ''}",
        lambda row: row["severity"] or "",
    )
    entered, left, changed = _changes(assets_before, assets_after, "asset")
    finding_entered, finding_left, finding_changed = _changes(findings_before, findings_after, "finding")
    return {
        "entered": entered + finding_entered,
        "left": left + finding_left,
        "changed": changed + finding_changed,
    }


def render(delta):
    lines = []
    if delta["baseline_id"] is None:
        lines.append("Base                    : nenhuma")
    else:
        lines.append(f"Base                    : {delta['baseline_id']}")
    empty = not delta["entered"] and not delta["left"] and not delta["changed"]
    if delta["baseline_id"] and empty:
        lines.append("Delta                   : vazio")
        return "\n".join(lines) + "\n"
    for title, key in (("Entraram", "entered"), ("Saíram", "left"), ("Mudaram", "changed")):
        lines.append(title)
        rows = delta[key]
        if not rows:
            lines.append("-")
            continue
        for row in rows:
            if row["change"] == "changed":
                lines.append(f"- {row['entity']} {row['key']} {row['before']} -> {row['after']}")
            else:
                lines.append(f"- {row['entity']} {row['key']}")
    return "\n".join(lines) + "\n"


def write_summary(path, body):
    summary = Path(path)
    current = summary.read_text(encoding="utf-8") if summary.is_file() else ""
    if MARKER in f"\n{current}":
        current = current.split(MARKER, 1)[0].rstrip() + "\n"
    elif current and not current.endswith("\n"):
        current += "\n"
    summary.write_text(current + MARKER + body, encoding="utf-8")


def write_delta(connection, run_id, output_dir):
    run = db.get_run(connection, run_id)
    baseline_id = db.previous_ok_run(connection, run_id, run["target"])
    previous_assets = db.list_assets(connection, baseline_id) if baseline_id else []
    previous_findings = db.list_findings(connection, baseline_id) if baseline_id else []
    delta = compare(
        previous_assets,
        db.list_assets(connection, run_id),
        previous_findings,
        db.list_findings(connection, run_id),
    )
    delta["baseline_id"] = baseline_id
    items = delta["entered"] + delta["left"] + delta["changed"]
    db.save_delta(connection, run_id, baseline_id, items)
    write_summary(Path(output_dir) / "resumo.txt", render(delta))
    return delta
