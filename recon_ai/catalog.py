from urllib.parse import urlparse

CLASSES = {"reportable", "note", "coverage"}

ENTRIES = {
    "corr/dangling-cname": {
        "class": "reportable",
        "cwe": "CWE-284",
        "title_key": "catalog.title.dangling_cname",
        "remediation_key": "catalog.remediate.dangling_cname",
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
            "https://cwe.mitre.org/data/definitions/284.html",
        ],
    },
    "har/secret": {
        "class": "reportable",
        "cwe": "CWE-798",
        "title_key": "catalog.title.secret",
        "remediation_key": "catalog.remediate.secret",
        "references": ["https://cwe.mitre.org/data/definitions/798.html", "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_cryptographic_key"],
    },
    "corr/secret-live-session": {
        "class": "reportable",
        "cwe": "CWE-798",
        "title_key": "catalog.title.secret_live",
        "remediation_key": "catalog.remediate.secret",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
    },
    "har/cors": {
        "class": "reportable",
        "cwe": "CWE-942",
        "title_key": "catalog.title.cors",
        "remediation_key": "catalog.remediate.cors",
        "references": ["https://cwe.mitre.org/data/definitions/942.html"],
    },
    "corr/cors-credentialed": {
        "class": "reportable",
        "cwe": "CWE-942",
        "title_key": "catalog.title.cors",
        "remediation_key": "catalog.remediate.cors",
        "references": ["https://cwe.mitre.org/data/definitions/942.html"],
    },
    "har/jwt-none": {
        "class": "reportable",
        "cwe": "CWE-347",
        "title_key": "catalog.title.jwt_none",
        "remediation_key": "catalog.remediate.jwt_none",
        "references": ["https://cwe.mitre.org/data/definitions/347.html"],
    },
    "corr/jwt-none-on-live": {
        "class": "reportable",
        "cwe": "CWE-347",
        "title_key": "catalog.title.jwt_none",
        "remediation_key": "catalog.remediate.jwt_none",
        "references": ["https://cwe.mitre.org/data/definitions/347.html"],
    },
    "corr/tech-panel": {
        "class": "reportable",
        "cwe": "CWE-200",
        "title_key": "catalog.title.panel",
        "remediation_key": "catalog.remediate.panel",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },
    "corr/openapi-live": {
        "class": "reportable",
        "cwe": "CWE-200",
        "title_key": "catalog.title.openapi",
        "remediation_key": "catalog.remediate.panel",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },
    "corr/retire-cve": {
        "class": "reportable",
        "cwe": "CWE-1104",
        "title_key": "catalog.title.retire",
        "remediation_key": "catalog.remediate.retire",
        "references": ["https://cwe.mitre.org/data/definitions/1104.html"],
    },
    "har/retire": {
        "class": "reportable",
        "cwe": "CWE-1104",
        "title_key": "catalog.title.retire",
        "remediation_key": "catalog.remediate.retire",
        "references": ["https://cwe.mitre.org/data/definitions/1104.html"],
    },
    "corr/dork-live-exposure": {
        "class": "reportable",
        "cwe": "CWE-200",
        "title_key": "catalog.title.exposure",
        "remediation_key": "catalog.remediate.panel",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
    },
    "corr/idor-cross-account": {
        "class": "reportable",
        "cwe": "CWE-639",
        "title_key": "catalog.title.idor",
        "remediation_key": "catalog.remediate.idor",
        "references": ["https://cwe.mitre.org/data/definitions/639.html"],
    },
    "corr/har-not-crawled": {"class": "coverage", "cwe": "", "title_key": "catalog.title.coverage", "remediation_key": "", "references": []},
    "corr/js-not-crawled": {"class": "coverage", "cwe": "", "title_key": "catalog.title.coverage", "remediation_key": "", "references": []},
    "corr/shadow-host": {"class": "note", "cwe": "", "title_key": "catalog.title.note", "remediation_key": "", "references": []},
    "corr/crtsh-only": {"class": "note", "cwe": "", "title_key": "catalog.title.note", "remediation_key": "", "references": []},
    "corr/delta-unscanned": {"class": "note", "cwe": "", "title_key": "catalog.title.note", "remediation_key": "", "references": []},
    "corr/idor-candidate": {"class": "note", "cwe": "CWE-639", "title_key": "catalog.title.note", "remediation_key": "", "references": []},
    "corr/archive-still-live": {"class": "note", "cwe": "", "title_key": "catalog.title.note", "remediation_key": "", "references": []},
    "corr/js-on-gated-host": {"class": "note", "cwe": "", "title_key": "catalog.title.note", "remediation_key": "", "references": []},
    "corr/graphql-candidate": {"class": "note", "cwe": "", "title_key": "catalog.title.note", "remediation_key": "", "references": []},
    "corr/debug-candidate": {"class": "note", "cwe": "", "title_key": "catalog.title.note", "remediation_key": "", "references": []},
    "corr/upload-candidate": {"class": "note", "cwe": "", "title_key": "catalog.title.note", "remediation_key": "", "references": []},
    "corr/dork-unknown-to-crawl": {"class": "note", "cwe": "", "title_key": "catalog.title.note", "remediation_key": "", "references": []},
}


def _as_list(value):
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return [str(value)]


def path_shape(matched_at):
    text = (matched_at or "").strip()
    if not text:
        return ""
    if "://" not in text:
        return text.casefold().rstrip(".")
    parsed = urlparse(text)
    host = (parsed.hostname or "").casefold()
    path = parsed.path or "/"
    return f"{host}{path}"


def host_of(matched_at):
    text = (matched_at or "").strip()
    if "://" in text:
        return (urlparse(text).hostname or "").casefold()
    return text.casefold().rstrip(".").split("/", 1)[0]


def cluster_key(template_id, matched_at, klass=None):
    if klass in {"coverage", "note"}:
        return f"{template_id or ''}|{host_of(matched_at)}"
    return f"{template_id or ''}|{path_shape(matched_at)}"


def draft_filename(key):
    return key.replace("|", "__").replace("/", "_") + ".md"


def nuclei_evidence(item):
    info = item.get("info") or {}
    classification = info.get("classification") or {}
    cwes = _as_list(classification.get("cwe-id") or classification.get("cwe_id"))
    cves = _as_list(classification.get("cve-id") or classification.get("cve_id"))
    references = _as_list(info.get("reference"))
    extracted = item.get("extracted-results") or item.get("extracted_results") or []
    if not isinstance(extracted, list):
        extracted = [extracted]
    return {
        "cwe": ",".join(cwes),
        "cve": ",".join(cves),
        "cvss": classification.get("cvss-metrics") or classification.get("cvss_metrics") or "",
        "cvss_score": classification.get("cvss-score") or classification.get("cvss_score") or "",
        "references": references,
        "curl": item.get("curl-command") or item.get("curl_command") or "",
        "matcher": item.get("matcher-name") or item.get("matcher_name") or "",
        "extracted": [str(part) for part in extracted if part],
        "description": info.get("description") or "",
        "secret_fp": "",
        "detail": "",
        "excerpt_ref": "",
        "provenance": "nuclei",
    }


def har_evidence(item):
    fingerprint = item.get("fingerprint") or ""
    detail = item.get("detail") or ""
    return {
        "cwe": "",
        "cve": "",
        "cvss": "",
        "cvss_score": "",
        "references": [],
        "curl": "",
        "matcher": "",
        "extracted": [],
        "description": "",
        "secret_fp": fingerprint,
        "detail": detail,
        "excerpt_ref": "",
        "provenance": item.get("template_id") or item.get("template-id") or "",
    }


def entry_for(template_id, evidence=None):
    evidence = evidence or {}
    found = ENTRIES.get(template_id)
    if found:
        return dict(found)
    if evidence.get("cwe") or evidence.get("cve"):
        return {
            "class": "reportable",
            "cwe": evidence.get("cwe") or "",
            "title_key": "catalog.title.nuclei",
            "remediation_key": "catalog.remediate.generic",
            "references": evidence.get("references") or [],
        }
    return {
        "class": "note",
        "cwe": "",
        "title_key": "catalog.title.note",
        "remediation_key": "",
        "references": [],
    }


def hydrate_finding(finding):
    evidence = finding.get("evidence") or {}
    if isinstance(evidence, str) and evidence.strip():
        import json

        try:
            evidence = json.loads(evidence)
        except json.JSONDecodeError:
            evidence = {}
        finding["evidence"] = evidence
    klass = finding_class(finding)
    finding["class"] = klass
    if not finding.get("cluster_key"):
        finding["cluster_key"] = cluster_key(finding.get("template_id"), finding.get("matched_at"), klass)
    return finding


def finding_class(finding):
    raw = finding.get("class")
    if raw in CLASSES:
        return raw
    evidence = finding.get("evidence") or {}
    if isinstance(evidence, str) and evidence.strip():
        import json

        try:
            evidence = json.loads(evidence)
        except json.JSONDecodeError:
            evidence = {}
    return entry_for(finding.get("template_id"), evidence)["class"]


def build_finding(item, kind):
    if kind == "nuclei":
        info = item.get("info") or {}
        severity = info.get("severity") or item.get("severity")
        name = info.get("name") or item.get("name")
        matched = item.get("matched-at") or item.get("matched_at") or item.get("host")
        template_id = item.get("template-id") or item.get("template_id")
        evidence = nuclei_evidence(item)
    else:
        severity = item.get("severity")
        name = item.get("name")
        matched = item.get("matched_at") or item.get("matched-at") or item.get("host")
        template_id = item.get("template_id") or item.get("template-id")
        evidence = har_evidence(item)
        if kind == "corr":
            evidence["provenance"] = template_id or "corr"
    meta = entry_for(template_id, evidence)
    if meta.get("cwe") and not evidence.get("cwe"):
        evidence["cwe"] = meta["cwe"]
    if meta.get("references") and not evidence.get("references"):
        evidence["references"] = list(meta["references"])
    return {
        "severity": severity,
        "name": name,
        "matched_at": matched,
        "template_id": template_id,
        "kind": kind,
        "class": meta["class"],
        "cluster_key": cluster_key(template_id, matched, meta["class"]),
        "evidence": evidence,
    }
