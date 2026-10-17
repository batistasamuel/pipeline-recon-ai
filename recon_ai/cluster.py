import json
from pathlib import Path

from recon_ai.catalog import cluster_key, finding_class


def group_findings(findings):
    groups = {}
    for finding in findings:
        klass = finding_class(finding)
        key = finding.get("cluster_key") or cluster_key(
            finding.get("template_id"), finding.get("matched_at"), klass
        )
        bucket = groups.setdefault(
            key,
            {
                "cluster_key": key,
                "class": klass,
                "template_id": finding.get("template_id"),
                "count": 0,
                "ids": [],
                "sample": finding.get("matched_at"),
            },
        )
        bucket["count"] += 1
        if finding.get("id") is not None:
            bucket["ids"].append(finding["id"])
        if not bucket.get("sample"):
            bucket["sample"] = finding.get("matched_at")
    return list(groups.values())


def write_clusters(output_dir, findings):
    rows = group_findings(findings)
    path = Path(output_dir) / "clusters.json"
    path.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return rows


def read_clusters(output_dir):
    path = Path(output_dir) / "clusters.json"
    if not path.is_file():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def reportable_findings(findings):
    return [finding for finding in findings if finding_class(finding) == "reportable"]
