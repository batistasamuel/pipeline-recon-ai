SCAN_PHASES = ("subdomains", "dns", "http", "urls", "dorks", "js", "nuclei", "report")
PHASES = SCAN_PHASES + ("har", "correlate", "ai")


def first_incomplete(rows):
    """Primeira fase cujo status não é ok. rows são dicts com name e status."""
    by_name = {}
    for row in rows:
        by_name[row["name"]] = row["status"]
    for name in PHASES:
        if by_name.get(name) not in {"ok", "skip"}:
            return name
    return None
