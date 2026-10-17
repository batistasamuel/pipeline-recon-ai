from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

import typer

from recon_ai import db
from recon_ai.control import (
    ControlError,
    build_spec,
    config_dir,
    database_path,
    load_job_overlay,
    results_root,
    run_job,
    settings_or_error,
    state_home,
    stop_run,
    verify_image,
)
from recon_ai.i18n import locale_from_env, t
from recon_ai.job import JobError
from recon_ai.runner import resume_from
from recon_ai.runtime import prepare_state

app = typer.Typer(add_completion=False, no_args_is_help=True)
_CLI = locale_from_env()


def _fail(exc):
    typer.echo(f"[!] {exc}", err=True)
    raise typer.Exit(exc.code) from exc


def reap_if_present():
    path = database_path()
    if not path.is_file():
        return 0
    connection = db.connect(path)
    return db.reap_stale_runs(connection)


def start_run(
    domain,
    threads,
    dry_run,
    config,
    from_phase=None,
    output=None,
    run_id=None,
    webhook=False,
    in_scope=None,
    out_scope=None,
    disabled=None,
    job_path=None,
    har_path=None,
    har_b_path=None,
    lang=None,
    cloud=False,
    verify=False,
    ai_delay_ms=None,
    cloud_mode=None,
):
    if webhook:
        typer.echo(f"[!] {t('cli.webhook_msg', _CLI)}", err=True)
        raise typer.Exit(2)
    try:
        settings = settings_or_error(config, threads)
        overlay = load_job_overlay(job_path) if job_path else None
        spec = build_spec(domain, settings, in_scope, out_scope, disabled, overlay)
        if har_path:
            spec["har_path"] = str(har_path)
        if har_b_path:
            spec["har_b_path"] = str(har_b_path)
        if lang:
            spec["lang"] = lang
        if cloud:
            spec["cloud"] = True
        if verify:
            spec["verify"] = True
        from recon_ai.job import JobError as _JobError
        from recon_ai.pace import PaceError, coerce_ai_delay_ms, coerce_cloud_mode

        try:
            spec["ai_delay_ms"] = coerce_ai_delay_ms(ai_delay_ms)
            spec["cloud_mode"] = coerce_cloud_mode(cloud_mode)
        except PaceError as exc:
            raise _JobError(str(exc)) from exc
        result = run_job(spec, dry_run=dry_run, from_phase=from_phase, output=output, run_id=run_id)
    except (ControlError, JobError) as exc:
        code = getattr(exc, "code", 2)
        typer.echo(f"[!] {exc}", err=True)
        raise typer.Exit(code) from exc
    if result.get("plan"):
        typer.echo(result["plan"])
        raise typer.Exit(0)
    typer.echo(f"run_id: {result['run_id']}")
    raise typer.Exit(result["code"])


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    check: bool = typer.Option(False, "--check", help=t("cli.check", _CLI)),
):
    reap_if_present()
    if ctx.invoked_subcommand is not None:
        return
    if check:
        prepare_state(state_home(), config_dir())
        try:
            verify_image()
        except ControlError as exc:
            _fail(exc)
        raise typer.Exit(0)
    raise typer.Exit(2)


@app.command(help=t("cli.run_doc", _CLI))
def run(
    domain: str,
    threads: Optional[int] = typer.Option(None, "--threads"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    config: Optional[str] = typer.Option(None, "--config"),
    scope: Optional[list[str]] = typer.Option(None, "--scope"),
    exclude: Optional[list[str]] = typer.Option(None, "--exclude"),
    disable: Optional[list[str]] = typer.Option(None, "--disable"),
    job: Optional[str] = typer.Option(None, "--job"),
    har: Optional[str] = typer.Option(None, "--har", help=t("cli.har", _CLI)),
    har_b: Optional[str] = typer.Option(None, "--har-b", help=t("cli.har_b", _CLI)),
    webhook: bool = typer.Option(False, "--webhook", help=t("cli.webhook", _CLI)),
    lang: Optional[str] = typer.Option(None, "--lang", help=t("cli.lang", _CLI)),
    cloud: bool = typer.Option(False, "--cloud", help=t("cli.cloud", _CLI)),
    verify: bool = typer.Option(False, "--verify", help=t("cli.verify", _CLI)),
    ai_delay_ms: int = typer.Option(2000, "--ai-delay-ms", help=t("cli.ai_delay", _CLI)),
    cloud_mode: str = typer.Option("sequential", "--cloud-mode", help=t("cli.cloud_mode", _CLI)),
):
    """Executa o pipeline, a análise local e grava o run no SQLite."""
    start_run(
        domain,
        threads,
        dry_run,
        config,
        webhook=webhook,
        in_scope=scope,
        out_scope=exclude,
        disabled=disable,
        job_path=job,
        har_path=har,
        har_b_path=har_b,
        lang=lang,
        cloud=cloud,
        verify=verify,
        ai_delay_ms=ai_delay_ms,
        cloud_mode=cloud_mode,
    )


@app.command(help=t("cli.resume_doc", _CLI))
def resume(
    run_id: str,
    threads: Optional[int] = typer.Option(None, "--threads"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    config: Optional[str] = typer.Option(None, "--config"),
    webhook: bool = typer.Option(False, "--webhook", help=t("cli.webhook", _CLI)),
    lang: Optional[str] = typer.Option(None, "--lang", help=t("cli.lang", _CLI)),
):
    """Continua um run a partir da primeira fase que não está ok."""
    connection = db.connect(database_path())
    db.reap_stale_runs(connection)
    found, phase = resume_from(connection, run_id)
    if found is None:
        typer.echo(f"[!] {t('cli.missing_run', _CLI, run_id=run_id)}", err=True)
        raise typer.Exit(2)
    if phase is None:
        typer.echo(f"run_id: {run_id}")
        typer.echo(t("cli.nothing", _CLI))
        raise typer.Exit(0)
    spec = db.get_spec(connection, run_id)
    if spec is None:
        start_run(
            found["target"],
            threads if threads is not None else found["threads"],
            dry_run,
            config,
            from_phase=phase,
            output=found["output_dir"],
            run_id=run_id,
            webhook=webhook,
            lang=lang,
        )
        return
    if threads is not None:
        spec["threads"] = threads
    if lang:
        spec["lang"] = lang
    try:
        result = run_job(spec, dry_run=dry_run, from_phase=phase, output=found["output_dir"], run_id=run_id)
    except ControlError as exc:
        _fail(exc)
    if result.get("plan"):
        typer.echo(result["plan"])
        raise typer.Exit(0)
    typer.echo(f"run_id: {result['run_id']}")
    raise typer.Exit(result["code"])


@app.command("stop", help=t("cli.stop_doc", _CLI))
def stop_command(run_id: str):
    """Pede a interrupção de um run em execução."""
    try:
        stop_run(run_id)
    except ControlError as exc:
        _fail(exc)
    typer.echo(f"stop: {run_id}")
    raise typer.Exit(0)


@app.command("export", help=t("cli.export_doc", _CLI))
def export_command(
    run_id: str,
    fmt: str = typer.Option("pdf", "--format", help=t("cli.format", _CLI)),
    output: Optional[str] = typer.Option(None, "--output"),
    draft: Optional[str] = typer.Option(None, "--draft", help=t("cli.draft", _CLI)),
):
    """Gera o relatório consolidado em PDF ou Word."""
    from recon_ai.export import ExportError, write_export

    try:
        path = write_export(
            database_path(),
            results_root(),
            run_id,
            fmt,
            Path(output) if output else None,
            locale=_CLI,
            draft=draft,
        )
    except ExportError as exc:
        typer.echo(f"[!] {exc}", err=True)
        raise typer.Exit(exc.code) from exc
    typer.echo(str(path))
    raise typer.Exit(0)


@app.command(help=t("cli.ai_doc", _CLI))
def ai(
    run_id: str,
    cloud: bool = typer.Option(False, "--cloud", help=t("cli.cloud", _CLI)),
    ai_delay_ms: int = typer.Option(2000, "--ai-delay-ms", help=t("cli.ai_delay", _CLI)),
    cloud_mode: str = typer.Option("sequential", "--cloud-mode", help=t("cli.cloud_mode", _CLI)),
):
    """Classifica findings já gravados e extrai rotas dos JS já baixados."""
    from recon_ai.ai import MODEL, CloudNotAvailable
    from recon_ai.runner import analyze_run

    connection = db.connect(database_path())
    if db.get_run(connection, run_id) is None:
        typer.echo(f"[!] {t('cli.missing_run', _CLI, run_id=run_id)}", err=True)
        raise typer.Exit(2)

    def on_progress(index, total, name, part):
        print(f"rotas: {index}/{total} {name} parte {part}", file=sys.stderr, flush=True)

    try:
        from recon_ai.pace import PaceError, coerce_ai_delay_ms, coerce_cloud_mode

        try:
            delay = coerce_ai_delay_ms(ai_delay_ms)
            mode = coerce_cloud_mode(cloud_mode)
        except PaceError as exc:
            typer.echo(f"[!] {exc}", err=True)
            raise typer.Exit(2) from exc
        status = analyze_run(
            connection,
            run_id,
            results_root(),
            on_progress=on_progress,
            cloud=cloud,
            ai_delay_ms=delay,
            cloud_mode=mode,
        )
    except CloudNotAvailable as exc:
        typer.echo(f"[!] {exc}", err=True)
        raise typer.Exit(2) from exc
    if status != "ok":
        phase = next((row for row in db.list_phases(connection, run_id) if row["name"] == "ai"), None)
        detail = phase["detail"] if phase else status
        typer.echo(f"[!] {detail}", err=True)
        raise typer.Exit(1)
    others_failed = any(
        row["name"] != "ai" and row["status"] == "fail" for row in db.list_phases(connection, run_id)
    )
    if not others_failed:
        db.finish_run(connection, run_id, "ok")
    stored = connection.execute(
        "SELECT task, provider, model FROM ai_result WHERE run_id = ? ORDER BY id",
        (run_id,),
    )
    for row in stored:
        used = row["model"] or "nenhum"
        typer.echo(f"{row['task']}: provider={row['provider']} model={used}")
    typer.echo(f"modelo_pinado: {MODEL}")
    raise typer.Exit(0)


def main_entry():
    args = sys.argv[1:]
    reserved = {"run", "resume", "ai", "stop", "export"}
    if args and not args[0].startswith("-") and args[0] not in reserved:
        sys.argv = [sys.argv[0], "run", *args]
    try:
        app()
    except SystemExit as exc:
        code = exc.code
        sys.exit(code if isinstance(code, int) else 1)
