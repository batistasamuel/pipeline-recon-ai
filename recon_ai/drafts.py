import json
import re
from pathlib import Path

from recon_ai.catalog import draft_filename, entry_for, finding_class

DRAFT_STATUSES = {"draft", "ready", "rejected"}
INDEX_NAME = "index.json"


class DraftError(ValueError):
    pass


def validate_draft(payload):
    if not isinstance(payload, dict) or set(payload) != {"title", "summary", "impact", "steps", "evidence_notes"}:
        raise DraftError("Rascunho fora do schema.")
    for field in ("title", "summary", "impact", "evidence_notes"):
        value = payload[field]
        if not isinstance(value, str) or not value.strip():
            raise DraftError("Rascunho fora do schema.")
    steps = payload["steps"]
    if not isinstance(steps, list) or not steps:
        raise DraftError("Rascunho fora do schema.")
    for step in steps:
        if not isinstance(step, str) or not step.strip():
            raise DraftError("Rascunho fora do schema.")
    return payload


def drafts_dir(output_dir):
    path = Path(output_dir) / "drafts"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _index_path(output_dir):
    return drafts_dir(output_dir) / INDEX_NAME


def read_index(output_dir):
    path = _index_path(output_dir)
    if not path.is_file():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def write_index(output_dir, rows):
    _index_path(output_dir).write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return rows


def set_status(output_dir, cluster_key, status):
    if status not in DRAFT_STATUSES:
        raise DraftError("Status de rascunho inválido.")
    rows = read_index(output_dir)
    found = False
    for row in rows:
        if row.get("cluster_key") == cluster_key or row.get("file") == draft_filename(cluster_key):
            row["status"] = status
            found = True
    if not found:
        raise DraftError("Rascunho inexistente.")
    write_index(output_dir, rows)
    return rows


def read_markdown(output_dir, cluster_key):
    path = drafts_dir(output_dir) / draft_filename(cluster_key)
    if not path.is_file():
        raise DraftError("Rascunho inexistente.")
    return path.read_text(encoding="utf-8")


def deterministic_steps(findings, locale=None):
    from recon_ai.i18n import t

    steps = []
    seen = set()
    for finding in findings:
        evidence = finding.get("evidence") or {}
        matched = finding.get("matched_at") or ""
        curl = evidence.get("curl") or ""
        if matched and matched not in seen:
            steps.append(t("catalog.step.open", locale, url=matched))
            seen.add(matched)
        if curl and curl not in seen:
            steps.append(curl)
            seen.add(curl)
        if (finding.get("template_id") or "").endswith("dangling-cname") and matched:
            host = matched.split("://", 1)[-1].split("/", 1)[0]
            steps.append(t("catalog.step.cname", locale, host=host))
    if not steps:
        steps.append(t("catalog.step.open", locale, url=(findings[0].get("matched_at") if findings else "")))
    return steps


def render_markdown(cluster, findings, draft, locale=None):
    from recon_ai.i18n import t

    sample = findings[0] if findings else {}
    evidence = sample.get("evidence") or {}
    meta = entry_for(sample.get("template_id"), evidence)
    cwe = evidence.get("cwe") or meta.get("cwe") or "—"
    asset = sample.get("matched_at") or "—"
    remediation = t(meta["remediation_key"], locale) if meta.get("remediation_key") else "—"
    references = evidence.get("references") or meta.get("references") or []
    lines = [
        f"# {draft['title']}",
        "",
        t("catalog.section.summary", locale),
        "",
        draft["summary"],
        "",
        t("catalog.section.classification", locale),
        "",
        f"- CWE: {cwe}",
        f"- {t('catalog.field.severity', locale)}: {sample.get('severity') or '—'}",
        f"- {t('catalog.field.asset', locale)}: {asset}",
        f"- {t('catalog.field.class', locale)}: {cluster.get('class')}",
        "",
        t("catalog.section.impact", locale),
        "",
        draft["impact"],
        "",
        t("catalog.section.steps", locale),
        "",
    ]
    for index, step in enumerate(draft["steps"], start=1):
        lines.append(f"{index}. {step}")
    lines.extend(["", t("catalog.section.evidence", locale), "", draft["evidence_notes"], ""])
    detail = evidence.get("detail")
    if detail:
        lines.extend([f"- {detail}", ""])
    if evidence.get("curl"):
        lines.extend(["```", evidence["curl"], "```", ""])
    lines.extend([t("catalog.section.remediation", locale), "", remediation, ""])
    lines.extend([t("catalog.section.references", locale), ""])
    if references:
        for ref in references:
            lines.append(f"- {ref}")
    else:
        lines.append("—")
    lines.append("")
    return "\n".join(lines)


def write_draft(output_dir, cluster, findings, draft, locale=None):
    validate_draft(draft)
    folder = drafts_dir(output_dir)
    key = cluster["cluster_key"]
    name = draft_filename(key)
    (folder / name).write_text(render_markdown(cluster, findings, draft, locale), encoding="utf-8")
    rows = [row for row in read_index(output_dir) if row.get("cluster_key") != key]
    sample = findings[0] if findings else {}
    evidence = sample.get("evidence") or {}
    meta = entry_for(sample.get("template_id"), evidence)
    rows.append(
        {
            "cluster_key": key,
            "file": name,
            "class": cluster.get("class") or finding_class(sample),
            "template_id": sample.get("template_id"),
            "title": draft["title"],
            "cwe": evidence.get("cwe") or meta.get("cwe") or "",
            "status": "draft",
            "count": cluster.get("count") or len(findings),
        }
    )
    write_index(output_dir, rows)
    return name


SAFE_KEY = re.compile(r"[^A-Za-z0-9._-]+")


def lookup_key(output_dir, raw):
    rows = read_index(output_dir)
    for row in rows:
        if row.get("cluster_key") == raw or row.get("file") == raw or row.get("file") == draft_filename(raw):
            return row["cluster_key"]
    raise DraftError("Rascunho inexistente.")
