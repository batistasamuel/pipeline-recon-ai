import json
import os
from pathlib import Path

from recon_ai import db
from recon_ai.config import ConfigError, load_settings
from recon_ai.job import JobError, apply_job_file, normalize_spec, spec_from_settings
from recon_ai.plan import describe
from recon_ai.pipeline import Cancelled
from recon_ai.runner import analyze_run, apply_correlate_phase, apply_har_phase, execute, finish_recorded, output_name, record
from recon_ai.runtime import prepare_state
from recon_ai.scope import domain_in_scope, target_in_scope_list, valid_target


class ControlError(Exception):
    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def results_root():
    override = os.environ.get("RECON_RESULTS")
    if override:
        return Path(override)
    if Path("/results").is_dir():
        return Path("/results")
    return Path.cwd()


def scope_file():
    return Path(os.environ.get("RECON_SCOPE", "/scope/scopes.txt"))


def database_path():
    override = os.environ.get("RECON_DB")
    if override:
        return Path(override)
    return results_root() / "recon.db"


def config_dir():
    return Path(os.environ.get("RECON_CONFIG", "/config"))


def config_file(explicit):
    if explicit:
        return Path(explicit)
    default = Path(os.environ.get("RECON_CONFIG", "/config")) / "recon.yaml"
    if default.is_file():
        return default
    return None


def state_home():
    override = os.environ.get("RECON_STATE_HOME")
    if override:
        return Path(override)
    return results_root() / "state" / "home"


def refuse_scope(target, in_scope=None):
    if in_scope and not target_in_scope_list(target, in_scope):
        raise ControlError(f"Alvo fora do escopo declarado: {target}", 3)
    code = domain_in_scope(target, scope_file())
    if code == 2:
        raise ControlError(f"Arquivo de escopo ausente: {scope_file()}", 3)
    if code == 1:
        raise ControlError(f"Domínio fora do escopo: {target}", 3)


def verify_image():
    script = os.environ.get("RECON_VERIFY", "/usr/local/lib/recon/verify-image.sh")
    if not Path(script).is_file():
        raise ControlError(f"Verificação da imagem ausente: {script}", 4)
    import subprocess

    completed = subprocess.run(["bash", script])
    if completed.returncode != 0:
        raise ControlError("Imagem divergente do lockfile.", completed.returncode)


def build_spec(target, settings, in_scope=None, out_scope=None, disabled=None, job_overlay=None):
    spec = spec_from_settings(target, settings, in_scope, out_scope, disabled)
    if job_overlay:
        spec = apply_job_file(spec, job_overlay)
    return spec


def load_job_overlay(path):
    raw = Path(path).read_text(encoding="utf-8")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ControlError("Job file inválido.", 2) from exc
    if not isinstance(payload, dict):
        raise ControlError("Job file precisa ser um mapa.", 2)
    return payload


def run_job(
    spec,
    *,
    dry_run=False,
    from_phase=None,
    output=None,
    run_id=None,
    verify=True,
    runner=None,
    ai_client=None,
    connection=None,
):
    try:
        spec = normalize_spec(spec, spec.get("threads"))
    except JobError as exc:
        raise ControlError(str(exc), 2) from exc
    target = spec["target"]
    if not valid_target(target):
        raise ControlError("Alvo inválido.", 2)
    refuse_scope(target, spec.get("in_scope"))
    from recon_ai.job import settings_from_spec

    settings = settings_from_spec(spec)
    target_dir = output or output_name(target)
    if dry_run:
        return {
            "run_id": None,
            "status": "dry_run",
            "code": 0,
            "plan": describe(target, settings["threads"], settings["tools"], target_dir, from_phase),
        }
    if verify:
        prepare_state(state_home(), config_dir())
        verify_image()
    root = results_root()
    root.mkdir(parents=True, exist_ok=True)
    owned = connection is None
    if connection is None:
        connection = db.connect(database_path())
    if run_id is None:
        db.reap_stale_runs(connection)
        run_id = db.new_run(connection, target, target_dir, spec["threads"], spec)
    else:
        db.mark_running(connection, run_id)
        db.save_spec(connection, run_id, spec)
        db.clear_cancel(connection, run_id)
    output_dir = root / target_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    staged_any = False
    for key, filename in (("har_path", "capture.har"), ("har_b_path", "capture-b.har")):
        if not spec.get(key):
            continue
        staged = output_dir / "har" / filename
        staged.parent.mkdir(parents=True, exist_ok=True)
        source = Path(spec[key])
        if source.is_file() and source.resolve() != staged.resolve():
            staged.write_bytes(source.read_bytes())
        spec[key] = str(staged)
        staged_any = True
    if staged_any:
        db.save_spec(connection, run_id, spec)
    code = execute(None, target, settings, target_dir, from_phase, root, connection, run_id, runner)
    try:
        status = record(connection, run_id, output_dir, finish=False)
    except ValueError as exc:
        db.finish_run(connection, run_id, "failed")
        raise ControlError(str(exc), 1) from exc
    if code == 2:
        status = finish_recorded(connection, run_id, "cancelled", output_dir)
    else:
        try:
            har_status = apply_har_phase(connection, run_id, output_dir, spec, from_phase, runner)
        except Cancelled:
            status = finish_recorded(connection, run_id, "cancelled", output_dir)
            if owned:
                connection.close()
            return {"run_id": run_id, "status": status, "code": 1}
        has_har = bool(spec.get("har_path") or spec.get("har_b_path"))
        if har_status == "failed":
            status = finish_recorded(connection, run_id, "failed", output_dir)
        elif not has_har and (code != 0 or status != "ok"):
            status = finish_recorded(connection, run_id, "failed", output_dir)
        else:
            try:
                corr_status = apply_correlate_phase(connection, run_id, output_dir, spec, from_phase)
            except Cancelled:
                status = finish_recorded(connection, run_id, "cancelled", output_dir)
                if owned:
                    connection.close()
                return {"run_id": run_id, "status": status, "code": 1}
            if corr_status == "failed":
                status = finish_recorded(connection, run_id, "failed", output_dir)
            else:
                ai_status = analyze_run(connection, run_id, root, client=ai_client)
                if ai_status == "cancelled":
                    status = finish_recorded(connection, run_id, "cancelled", output_dir)
                elif ai_status != "ok":
                    status = finish_recorded(connection, run_id, "failed", output_dir)
                else:
                    status = finish_recorded(connection, run_id, "ok", output_dir)
    if owned:
        connection.close()
    return {"run_id": run_id, "status": status, "code": 0 if status == "ok" else 1}


def stop_run(run_id, connection=None):
    owned = connection is None
    if connection is None:
        path = database_path()
        if not path.is_file():
            raise ControlError(f"Run inexistente: {run_id}", 2)
        connection = db.connect(path)
    found = db.get_run(connection, run_id)
    if found is None:
        raise ControlError(f"Run inexistente: {run_id}", 2)
    if found["status"] != "running":
        raise ControlError(f"Run não está em execução: {run_id}", 2)
    db.request_cancel(connection, run_id)
    if owned:
        connection.close()
    return run_id


def settings_or_error(explicit, threads):
    try:
        return load_settings(config_file(explicit), threads)
    except ConfigError as exc:
        raise ControlError(str(exc), 2) from exc
