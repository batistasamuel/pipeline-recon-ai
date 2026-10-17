import sqlite3
from datetime import datetime, timezone
from uuid import uuid4


def connect(path):
    connection = sqlite3.connect(path, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS run (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            output_dir TEXT NOT NULL,
            threads INTEGER NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT
        );
        CREATE TABLE IF NOT EXISTS phase (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL REFERENCES run(id),
            name TEXT NOT NULL,
            status TEXT NOT NULL,
            exit_code INTEGER,
            duration_s INTEGER,
            stderr_path TEXT,
            detail TEXT
        );
        CREATE TABLE IF NOT EXISTS asset (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL REFERENCES run(id),
            kind TEXT NOT NULL,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS url (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL REFERENCES run(id),
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS finding (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL REFERENCES run(id),
            severity TEXT,
            name TEXT,
            matched_at TEXT,
            template_id TEXT
        );
        CREATE TABLE IF NOT EXISTS delta_run (
            run_id TEXT PRIMARY KEY REFERENCES run(id),
            baseline_id TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS delta_item (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL REFERENCES run(id),
            entity TEXT NOT NULL,
            change TEXT NOT NULL,
            key TEXT NOT NULL,
            before TEXT,
            after TEXT
        );
        CREATE TABLE IF NOT EXISTS ai_result (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL REFERENCES run(id),
            task TEXT NOT NULL,
            provider TEXT NOT NULL,
            model TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS run_spec (
            run_id TEXT PRIMARY KEY REFERENCES run(id),
            payload TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS run_control (
            run_id TEXT PRIMARY KEY REFERENCES run(id),
            cancel INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    columns = {row[1] for row in connection.execute("PRAGMA table_info(phase)")}
    if "detail_key" not in columns:
        connection.execute("ALTER TABLE phase ADD COLUMN detail_key TEXT")
    if "detail_args" not in columns:
        connection.execute("ALTER TABLE phase ADD COLUMN detail_args TEXT")
    finding_columns = {row[1] for row in connection.execute("PRAGMA table_info(finding)")}
    for name, definition in (
        ("kind", "TEXT"),
        ("class", "TEXT"),
        ("cluster_key", "TEXT"),
        ("evidence", "TEXT"),
    ):
        if name not in finding_columns:
            connection.execute(f"ALTER TABLE finding ADD COLUMN {name} {definition}")
    connection.commit()
    return connection


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def save_spec(connection, run_id, spec):
    import json

    connection.execute("DELETE FROM run_spec WHERE run_id = ?", (run_id,))
    connection.execute(
        "INSERT INTO run_spec (run_id, payload) VALUES (?, ?)",
        (run_id, json.dumps(spec, ensure_ascii=False)),
    )
    connection.commit()


def get_spec(connection, run_id):
    import json

    row = connection.execute("SELECT payload FROM run_spec WHERE run_id = ?", (run_id,)).fetchone()
    if row is None:
        return None
    return json.loads(row["payload"])


def request_cancel(connection, run_id):
    connection.execute(
        "INSERT INTO run_control (run_id, cancel) VALUES (?, 1) ON CONFLICT(run_id) DO UPDATE SET cancel = 1",
        (run_id,),
    )
    connection.commit()


def cancel_requested(connection, run_id):
    row = connection.execute("SELECT cancel FROM run_control WHERE run_id = ?", (run_id,)).fetchone()
    return bool(row and row["cancel"])


def clear_cancel(connection, run_id):
    connection.execute("DELETE FROM run_control WHERE run_id = ?", (run_id,))
    connection.commit()


def running_run(connection):
    row = connection.execute(
        "SELECT id FROM run WHERE status = 'running' ORDER BY started_at DESC LIMIT 1"
    ).fetchone()
    return row["id"] if row else None


def upsert_phase(
    connection,
    run_id,
    name,
    status,
    duration_s=0,
    detail="",
    stderr_path="",
    detail_key="",
    detail_args="",
):
    exit_code = 0 if status in ("ok", "warn", "skip", "running") else 1
    existing = connection.execute(
        "SELECT id FROM phase WHERE run_id = ? AND name = ?",
        (run_id, name),
    ).fetchone()
    if existing:
        connection.execute(
            """
            UPDATE phase
            SET status = ?, exit_code = ?, duration_s = ?, detail = ?, stderr_path = ?,
                detail_key = ?, detail_args = ?
            WHERE id = ?
            """,
            (status, exit_code, duration_s, detail, stderr_path, detail_key, detail_args, existing["id"]),
        )
    else:
        connection.execute(
            """
            INSERT INTO phase (
                run_id, name, status, exit_code, duration_s, stderr_path, detail, detail_key, detail_args
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (run_id, name, status, exit_code, duration_s, stderr_path, detail, detail_key, detail_args),
        )
    connection.commit()


def new_run(connection, target, output_dir, threads, spec=None):
    run_id = uuid4().hex
    connection.execute(
        """
        INSERT INTO run (id, target, status, output_dir, threads, started_at)
        VALUES (?, ?, 'running', ?, ?, ?)
        """,
        (run_id, target.casefold(), output_dir, threads, now()),
    )
    connection.commit()
    if spec is not None:
        save_spec(connection, run_id, spec)
        clear_cancel(connection, run_id)
    return run_id


def get_run(connection, run_id):
    row = connection.execute("SELECT * FROM run WHERE id = ?", (run_id,)).fetchone()
    return dict(row) if row else None


class RunError(ValueError):
    pass


def delete_run(connection, run_id):
    run = get_run(connection, run_id)
    if run is None:
        return None
    if run["status"] == "running":
        raise RunError("Run ainda em execução.")
    for table in (
        "ai_result",
        "delta_item",
        "delta_run",
        "finding",
        "url",
        "asset",
        "phase",
        "run_spec",
        "run_control",
    ):
        connection.execute(f"DELETE FROM {table} WHERE run_id = ?", (run_id,))
    connection.execute("DELETE FROM run WHERE id = ?", (run_id,))
    connection.commit()
    return run


def list_phases(connection, run_id):
    rows = connection.execute(
        """
        SELECT name, status, exit_code, duration_s, stderr_path, detail, detail_key, detail_args
        FROM phase WHERE run_id = ? ORDER BY id
        """,
        (run_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def runs_for_target(connection, target):
    rows = connection.execute(
        "SELECT id, status, output_dir, started_at FROM run WHERE target = ? ORDER BY started_at",
        (target.casefold(),),
    ).fetchall()
    return [dict(row) for row in rows]


def replace_run_details(connection, run_id, phases, assets, urls, findings):
    connection.execute("DELETE FROM phase WHERE run_id = ?", (run_id,))
    connection.execute("DELETE FROM asset WHERE run_id = ?", (run_id,))
    connection.execute("DELETE FROM url WHERE run_id = ?", (run_id,))
    connection.execute("DELETE FROM finding WHERE run_id = ?", (run_id,))
    prepared = []
    for row in phases:
        item = dict(row)
        item.setdefault("detail_key", "")
        item.setdefault("detail_args", "")
        prepared.append(item)
    connection.executemany(
        """
        INSERT INTO phase (
            run_id, name, status, exit_code, duration_s, stderr_path, detail, detail_key, detail_args
        )
        VALUES (
            :run_id, :name, :status, :exit_code, :duration_s, :stderr_path, :detail, :detail_key, :detail_args
        )
        """,
        prepared,
    )
    connection.executemany(
        "INSERT INTO asset (run_id, kind, value) VALUES (?, ?, ?)",
        ((run_id, kind, value) for kind, value in assets),
    )
    connection.executemany(
        "INSERT INTO url (run_id, value) VALUES (?, ?)",
        ((run_id, value) for value in urls),
    )
    connection.executemany(
        """
        INSERT INTO finding (
            run_id, severity, name, matched_at, template_id, kind, class, cluster_key, evidence
        )
        VALUES (
            :run_id, :severity, :name, :matched_at, :template_id, :kind, :class, :cluster_key, :evidence
        )
        """,
        [_finding_row(run_id, item) for item in findings],
    )
    connection.commit()


def reap_stale_runs(connection):
    """Runs ainda marcados como running pertencem a um processo que já morreu."""
    from recon_ai.i18n import DEFAULT_LOCALE, t

    stamp = now()
    detail = t("phase.interrupted", DEFAULT_LOCALE)
    cursor = connection.execute(
        "UPDATE run SET status = 'failed', finished_at = ? WHERE status = 'running'",
        (stamp,),
    )
    connection.execute(
        """
        UPDATE phase
        SET status = 'fail', exit_code = 1, detail = ?, detail_key = 'phase.interrupted'
        WHERE status = 'running'
        """,
        (detail,),
    )
    connection.commit()
    return cursor.rowcount


def mark_running(connection, run_id):
    connection.execute(
        "UPDATE run SET status = 'running', finished_at = NULL WHERE id = ?",
        (run_id,),
    )
    connection.commit()


def finish_run(connection, run_id, status):
    connection.execute(
        "UPDATE run SET status = ?, finished_at = ? WHERE id = ?",
        (status, now(), run_id),
    )
    connection.commit()


def list_assets(connection, run_id):
    rows = connection.execute(
        "SELECT kind, value FROM asset WHERE run_id = ? ORDER BY value, kind",
        (run_id,),
    ).fetchall()
    return [(row["kind"], row["value"]) for row in rows]


def previous_ok_run(connection, run_id, target):
    row = connection.execute(
        """
        SELECT id FROM run
        WHERE target = ? AND status = 'ok' AND id != ?
        ORDER BY finished_at DESC, started_at DESC
        LIMIT 1
        """,
        (target, run_id),
    ).fetchone()
    return row["id"] if row else None


def save_delta(connection, run_id, baseline_id, items):
    connection.execute("DELETE FROM delta_item WHERE run_id = ?", (run_id,))
    connection.execute("DELETE FROM delta_run WHERE run_id = ?", (run_id,))
    connection.execute(
        "INSERT INTO delta_run (run_id, baseline_id, created_at) VALUES (?, ?, ?)",
        (run_id, baseline_id, now()),
    )
    connection.executemany(
        """
        INSERT INTO delta_item (run_id, entity, change, key, before, after)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            (run_id, item["entity"], item["change"], item["key"], item.get("before"), item.get("after"))
            for item in items
        ],
    )
    connection.commit()


def clear_delta(connection, run_id):
    connection.execute("DELETE FROM delta_item WHERE run_id = ?", (run_id,))
    connection.execute("DELETE FROM delta_run WHERE run_id = ?", (run_id,))
    connection.commit()


def _finding_row(run_id, item):
    import json

    from recon_ai.catalog import cluster_key, entry_for

    if isinstance(item, dict):
        evidence = item.get("evidence") or {}
        template_id = item.get("template_id")
        matched = item.get("matched_at")
        meta = entry_for(template_id, evidence if isinstance(evidence, dict) else {})
        payload = evidence if isinstance(evidence, str) else json.dumps(evidence, ensure_ascii=False)
        return {
            "run_id": item.get("run_id") or run_id,
            "severity": item.get("severity"),
            "name": item.get("name"),
            "matched_at": matched,
            "template_id": template_id,
            "kind": item.get("kind") or "",
            "class": item.get("class") or meta["class"],
            "cluster_key": item.get("cluster_key")
            or cluster_key(template_id, matched, item.get("class") or meta["class"]),
            "evidence": payload,
        }
    if len(item) >= 5:
        owner, severity, name, matched, template_id = item[:5]
    else:
        owner, severity, name, matched, template_id = run_id, item[0], item[1], item[2], item[3]
    meta = entry_for(template_id, {})
    return {
        "run_id": owner,
        "severity": severity,
        "name": name,
        "matched_at": matched,
        "template_id": template_id,
        "kind": "",
        "class": meta["class"],
        "cluster_key": cluster_key(template_id, matched, meta["class"]),
        "evidence": "{}",
    }


def list_findings(connection, run_id):
    import json

    rows = connection.execute(
        """
        SELECT id, severity, name, matched_at, template_id, kind, class, cluster_key, evidence
        FROM finding WHERE run_id = ? ORDER BY id
        """,
        (run_id,),
    ).fetchall()
    findings = []
    for row in rows:
        item = dict(row)
        raw = item.get("evidence")
        if not raw:
            item["evidence"] = {}
        elif isinstance(raw, str):
            try:
                item["evidence"] = json.loads(raw)
            except json.JSONDecodeError:
                item["evidence"] = {}
        findings.append(item)
    return findings


def save_ai_results(connection, run_id, rows):
    stamp = now()
    connection.execute("DELETE FROM ai_result WHERE run_id = ?", (run_id,))
    connection.executemany(
        """
        INSERT INTO ai_result (run_id, task, provider, model, payload, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            (run_id, task, provider, model, payload, stamp)
            for task, provider, model, payload in rows
        ],
    )
    connection.commit()
