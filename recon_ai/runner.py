import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from recon_ai import db
from recon_ai.har import HarError, ingest_har
from recon_ai.ingest import read_assets, read_findings, read_phases, read_urls, run_status
from recon_ai.phases import PHASES, first_incomplete
from recon_ai.plan import command
from recon_ai.scope import output_safe_name


def _script():
    override = os.environ.get("RECON_SCRIPT")
    if override:
        return override
    container = Path("/usr/local/bin/recon-claude-grok.sh")
    if container.is_file():
        return str(container)
    return str(Path(__file__).resolve().parents[1] / "recon-claude-grok.sh")


def _env(settings):
    env = os.environ.copy()
    for name, item in settings["tools"].items():
        if not isinstance(item, dict):
            continue
        if item.get("threads") is not None:
            env[f"RECON_THREADS_{name.upper()}"] = str(item["threads"])
        if name == "nuclei" and item.get("rate_limit") is not None:
            env["RECON_RATE_NUCLEI"] = str(item["rate_limit"])
    env["RECON_AMASS_TIMEOUT"] = str(settings.get("amass_timeout", 5))
    return env


def execute(script, domain, settings, output, from_phase, cwd, connection=None, run_id=None, runner=None):
    env = _env(settings)
    if script is not None or os.environ.get("RECON_ENGINE") == "bash":
        cmd = command(script or _script(), domain, settings["threads"], output, from_phase)
        completed = subprocess.run(cmd, cwd=cwd, env=env)
        return completed.returncode
    from recon_ai.pipeline import Pipeline

    pipeline = Pipeline(domain, settings, Path(cwd) / output, env, runner, connection, run_id)
    return pipeline.run(from_phase)


def output_name(domain):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"recon_{output_safe_name(domain)}_{stamp}"


def _phase_locale(spec):
    from recon_ai.i18n import DEFAULT_LOCALE, require_locale

    return require_locale((spec or {}).get("lang") or DEFAULT_LOCALE)


def _phase_text(spec, key, args=None):
    from recon_ai.i18n import t

    return t(key, _phase_locale(spec), **(args or {}))


def _write_phase_tsv(output_dir, name, status, duration, detail, detail_key="", detail_args=""):
    path = Path(output_dir) / "phases.tsv"
    rows = {}
    if path.is_file():
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not raw.strip():
                continue
            parts = raw.split("\t")
            rows[parts[0]] = raw
    line = f"{name}\t{status}\t{duration}\t{detail}"
    if detail_key or detail_args:
        line = f"{line}\t{detail_key}\t{detail_args}"
    rows[name] = line
    ordered = [rows[item] for item in PHASES if item in rows]
    extra = [line for key, line in rows.items() if key not in PHASES]
    path.write_text("\n".join(ordered + extra) + "\n", encoding="utf-8")


def _mark_phase(connection, run_id, output_dir, name, status, duration, detail, logs, detail_key="", detail_args=""):
    db.upsert_phase(
        connection,
        run_id,
        name,
        status,
        duration,
        detail,
        logs,
        detail_key,
        detail_args,
    )
    _write_phase_tsv(output_dir, name, status, duration, detail, detail_key, detail_args)


def record(connection, run_id, output_dir, finish=True):
    phases = read_phases(output_dir)
    for row in phases:
        row["run_id"] = run_id
    db.replace_run_details(
        connection,
        run_id,
        phases,
        read_assets(output_dir),
        read_urls(output_dir),
        read_findings(output_dir),
    )
    status = run_status(phases)
    if status == "failed":
        stored = "failed"
    elif status == "cancelled":
        stored = "cancelled"
    else:
        stored = "ok"
    if finish:
        finish_recorded(connection, run_id, stored, output_dir)
    return stored


def apply_har_phase(connection, run_id, output_dir, spec, from_phase=None, runner=None):
    from recon_ai.pipeline import Cancelled

    logs = str(Path(output_dir) / "logs")
    existing = {row["name"]: row["status"] for row in db.list_phases(connection, run_id)}
    if from_phase == "ai" and existing.get("har") in {"ok", "skip"}:
        return existing["har"]
    if db.cancel_requested(connection, run_id):
        raise Cancelled()
    captures = [
        (account, spec.get(key))
        for account, key in (("a", "har_path"), ("b", "har_b_path"))
        if spec.get(key)
    ]
    started = time.monotonic()
    running = _phase_text(spec, "phase.running")
    _mark_phase(connection, run_id, output_dir, "har", "running", 0, running, logs, "phase.running")
    if not captures:
        skipped = _phase_text(spec, "phase.har_skip")
        _mark_phase(connection, run_id, output_dir, "har", "skip", 0, skipped, logs, "phase.har_skip")
        record(connection, run_id, output_dir, finish=False)
        return "skip"
    details = []
    try:
        for account, har_path in captures:
            stats = ingest_har(
                har_path,
                output_dir,
                spec["target"],
                spec.get("in_scope"),
                spec.get("out_scope"),
                account=account,
            )
            details.append(
                _phase_text(
                    spec,
                    "phase.har_account",
                    {"account": account, "detail": stats["detail"]},
                )
            )
    except HarError as exc:
        duration = int(time.monotonic() - started)
        detail = str(exc)
        _mark_phase(connection, run_id, output_dir, "har", "fail", duration, detail, logs)
        record(connection, run_id, output_dir, finish=False)
        return "failed"
    from recon_ai.pipeline import scan_har_nuclei

    def cancel_check():
        if db.cancel_requested(connection, run_id):
            raise Cancelled()

    def on_progress(done, total):
        elapsed = int(time.monotonic() - started)
        progress = _phase_text(spec, "phase.har_nuclei_progress", {"done": done, "total": total})
        _mark_phase(
            connection,
            run_id,
            output_dir,
            "har",
            "running",
            elapsed,
            " | ".join(details + [progress]),
            logs,
            "phase.har_nuclei_progress",
            json.dumps({"done": done, "total": total}, ensure_ascii=False, separators=(",", ":")),
        )

    scanned = scan_har_nuclei(
        output_dir,
        spec,
        runner,
        on_progress=on_progress,
        cancel_check=cancel_check,
    )
    if scanned < 0:
        duration = int(time.monotonic() - started)
        detail = _phase_text(spec, "phase.har_nuclei_fail")
        _mark_phase(
            connection, run_id, output_dir, "har", "fail", duration, detail, logs, "phase.har_nuclei_fail"
        )
        record(connection, run_id, output_dir, finish=False)
        return "failed"
    if scanned:
        details.append(_phase_text(spec, "phase.har_nuclei_urls", {"n": scanned}))
    duration = int(time.monotonic() - started)
    detail = " | ".join(details)
    _mark_phase(connection, run_id, output_dir, "har", "ok", duration, detail, logs)
    record(connection, run_id, output_dir, finish=False)
    return "ok"


def apply_correlate_phase(connection, run_id, output_dir, spec, from_phase=None):
    from recon_ai.correlate import CorrelateError, correlate_run
    from recon_ai.pipeline import Cancelled

    logs = str(Path(output_dir) / "logs")
    existing = {row["name"]: row["status"] for row in db.list_phases(connection, run_id)}
    if from_phase == "ai" and existing.get("correlate") in {"ok", "skip"}:
        return existing["correlate"]
    if db.cancel_requested(connection, run_id):
        raise Cancelled()
    started = time.monotonic()
    running = _phase_text(spec, "phase.running")
    _mark_phase(connection, run_id, output_dir, "correlate", "running", 0, running, logs, "phase.running")
    try:
        stats = correlate_run(output_dir, spec["target"], connection, run_id, locale=spec.get("lang"))
    except CorrelateError as exc:
        duration = int(time.monotonic() - started)
        detail = str(exc)
        _mark_phase(connection, run_id, output_dir, "correlate", "fail", duration, detail, logs)
        record(connection, run_id, output_dir, finish=False)
        return "failed"
    duration = int(time.monotonic() - started)
    args = json.dumps(stats.get("detail_args") or {}, ensure_ascii=False, separators=(",", ":"))
    _mark_phase(
        connection,
        run_id,
        output_dir,
        "correlate",
        "ok",
        duration,
        stats["detail"],
        logs,
        stats.get("detail_key") or "",
        args if stats.get("detail_args") else "",
    )
    record(connection, run_id, output_dir, finish=False)
    return "ok"


def finish_recorded(connection, run_id, stored, output_dir):
    db.finish_run(connection, run_id, stored)
    if stored == "ok":
        from recon_ai.diff import write_delta

        write_delta(connection, run_id, output_dir)
    else:
        db.clear_delta(connection, run_id)
    return stored


def analyze_run(
    connection,
    run_id,
    results_root,
    client=None,
    on_progress=None,
    cloud=None,
    ai_delay_ms=None,
    cloud_mode=None,
):
    from recon_ai.ai import AiError, OllamaClient, analyze
    from recon_ai.pipeline import Cancelled

    run = db.get_run(connection, run_id)
    if run is None:
        raise AiError(f"Run inexistente: {run_id}")
    output_dir = Path(results_root) / run["output_dir"]
    spec = db.get_spec(connection, run_id) or {}
    if cloud is None:
        cloud = bool(spec.get("cloud"))
    if ai_delay_ms is None:
        ai_delay_ms = spec.get("ai_delay_ms")
    if cloud_mode is None:
        cloud_mode = spec.get("cloud_mode")
    started = time.monotonic()
    running = _phase_text(spec, "phase.running")
    logs = str(output_dir / "logs")
    _mark_phase(connection, run_id, output_dir, "ai", "running", 0, running, logs, "phase.running")

    def progress(index, total, name, part):
        if db.cancel_requested(connection, run_id):
            raise Cancelled()
        if on_progress is not None:
            on_progress(index, total, name, part)
        else:
            print(f"rotas: {index}/{total} {name} parte {part}", flush=True)

    if db.cancel_requested(connection, run_id):
        raise Cancelled()
    try:
        if client is not None:
            used = client
        elif cloud:
            from recon_ai.cloud import make_cloud_client

            used = make_cloud_client(mode=cloud_mode)
        else:
            used = OllamaClient(os.environ.get("RECON_OLLAMA_URL", "http://ollama:11434"))
        rows = analyze(
            connection,
            run_id,
            results_root,
            used,
            cloud=cloud,
            on_progress=progress,
            ai_delay_ms=ai_delay_ms,
            parallel=bool(cloud) and cloud_mode == "parallel",
        )
    except Cancelled:
        duration = int(time.monotonic() - started)
        detail = _phase_text(spec, "phase.cancelled")
        _mark_phase(connection, run_id, output_dir, "ai", "cancelled", duration, detail, logs, "phase.cancelled")
        return "cancelled"
    except AiError as exc:
        duration = int(time.monotonic() - started)
        detail = str(exc)
        _mark_phase(connection, run_id, output_dir, "ai", "fail", duration, detail, logs)
        return "failed"
    classification = next(item for item in rows if item[0] == "classification")
    routes = next(item for item in rows if item[0] == "routes")
    n_items = len((classification[3] or {}).get("items") or [])
    n_routes = len((routes[3] or {}).get("routes") or [])
    provider = f"{classification[1]}/{routes[1]}"
    args = {"items": n_items, "routes": n_routes, "provider": provider}
    detail = _phase_text(spec, "phase.ai_ok", args)
    duration = int(time.monotonic() - started)
    _mark_phase(
        connection,
        run_id,
        output_dir,
        "ai",
        "ok",
        duration,
        detail,
        logs,
        "phase.ai_ok",
        json.dumps(args, ensure_ascii=False, separators=(",", ":")),
    )
    return "ok"


def resume_from(connection, run_id):
    run = db.get_run(connection, run_id)
    if run is None:
        return None, None
    phase = first_incomplete(db.list_phases(connection, run_id))
    return run, phase
