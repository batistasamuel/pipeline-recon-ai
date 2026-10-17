import json
import os
import shutil
import threading
import traceback
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from recon_ai import db
from recon_ai.ai import (
    INPUT_TOKEN_BUDGET,
    MODEL,
    AiError,
    OllamaClient,
    estimate_prompt_tokens,
)
from recon_ai.control import ControlError, refuse_scope, run_job, stop_run
from recon_ai.export import ExportError, render_export
from recon_ai.har import MAX_HAR_BYTES
from recon_ai.job import JobError, normalize_spec, tool_catalog
from recon_ai.runner import output_name
from recon_ai.view import connect_readonly, list_runs, report, run_view

def _page():
    return Path(__file__).with_name("ui_page.html").read_text(encoding="utf-8")


PAGE = _page()


def _purge_output(results_dir, output_dir):
    if not output_dir:
        return
    root = Path(results_dir).resolve()
    target = (root / output_dir).resolve()
    if target == root or root not in target.parents:
        return
    if target.is_dir():
        shutil.rmtree(target)
SCAN_LOCK = threading.Lock()
AI_CHAT_LOCK = threading.Lock()


def _read_body(handler):
    length = int(handler.headers.get("Content-Length") or 0)
    if length <= 0:
        return {}
    raw = handler.rfile.read(length)
    if not raw:
        return {}
    try:
        payload = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("JSON inválido.") from exc
    if not isinstance(payload, dict):
        raise ValueError("JSON inválido.")
    return payload


def _read_run_post(handler):
    ctype = handler.headers.get("Content-Type") or ""
    if not ctype.startswith("multipart/form-data"):
        return _read_body(handler), None, None
    length = int(handler.headers.get("Content-Length") or 0)
    if length > (MAX_HAR_BYTES * 2) + 65536:
        raise ValueError(f"HAR acima de {MAX_HAR_BYTES} bytes.")
    raw = handler.rfile.read(length) if length > 0 else b""
    message = BytesParser(policy=policy.default).parsebytes(
        f"Content-Type: {ctype}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + raw
    )
    spec_raw = None
    har_bytes = None
    har_b_bytes = None
    for part in message.iter_parts():
        name = part.get_param("name", header="content-disposition")
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        if name == "spec":
            spec_raw = payload.decode("utf-8")
        elif name == "har":
            har_bytes = payload
        elif name == "har_b":
            har_b_bytes = payload
    if not spec_raw:
        raise ValueError("multipart sem spec.")
    try:
        spec = json.loads(spec_raw)
    except json.JSONDecodeError as exc:
        raise ValueError("JSON inválido.") from exc
    if not isinstance(spec, dict):
        raise ValueError("JSON inválido.")
    if har_bytes is not None and len(har_bytes) > MAX_HAR_BYTES:
        raise ValueError(f"HAR acima de {MAX_HAR_BYTES} bytes.")
    if har_b_bytes is not None and len(har_b_bytes) > MAX_HAR_BYTES:
        raise ValueError(f"HAR acima de {MAX_HAR_BYTES} bytes.")
    return spec, har_bytes, har_b_bytes


def _requested_locale(parsed):
    from recon_ai.i18n import DEFAULT_LOCALE, I18nError, require_locale

    raw = parse_qs(parsed.query).get("lang", [None])[0]
    if raw is None or str(raw).strip() == "":
        return DEFAULT_LOCALE
    try:
        return require_locale(str(raw).strip())
    except I18nError as exc:
        raise ValueError(str(exc)) from exc


def _run_id_from(path):
    rest = path.removeprefix("/api/runs/").strip("/")
    if not rest:
        return None, None
    parts = rest.split("/", 1)
    return parts[0], parts[1] if len(parts) > 1 else ""


def make_server(database, host, port, results=None, ai_client=None):
    results_dir = Path(results) if results else Path(os.environ.get("RECON_RESULTS", Path(database).parent))
    ollama_url = os.environ.get("RECON_OLLAMA_URL", "http://ollama:11434")
    Path(database).parent.mkdir(parents=True, exist_ok=True)
    connection = db.connect(database)
    db.reap_stale_runs(connection)
    connection.close()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self._send(200, "text/html; charset=utf-8", _page().encode("utf-8"))
                return
            if parsed.path in {"/api/i18n", "/api/tools"}:
                try:
                    locale = _requested_locale(parsed)
                except ValueError as exc:
                    self._json(400, {"error": str(exc)})
                    return
                if parsed.path == "/api/i18n":
                    from recon_ai.i18n import catalog_messages

                    self._json(200, {"lang": locale, "messages": catalog_messages(locale)})
                    return
                self._json(200, tool_catalog(locale))
                return
            if parsed.path == "/api/ai":
                self._json(
                    200,
                    {
                        "model": MODEL,
                        "input_token_budget": INPUT_TOKEN_BUDGET,
                        "estimate": "utf8_bytes_div_3",
                    },
                )
                return
            if parsed.path.startswith("/api/runs/"):
                run_id, extra = _run_id_from(parsed.path)
                if extra == "export":
                    query = parse_qs(parsed.query)
                    fmt = query.get("format", ["pdf"])[0]
                    draft = query.get("draft", [""])[0] or None
                    try:
                        locale = _requested_locale(parsed)
                    except ValueError as exc:
                        self._json(400, {"error": str(exc)})
                        return
                    try:
                        connection = db.connect(database)
                        payload = run_view(connection, run_id, locale)
                        if payload is None:
                            connection.close()
                            self._json(404, {"error": "run ausente"})
                            return
                        if payload["run"]["status"] == "running":
                            connection.close()
                            self._json(409, {"error": "Run ainda em execução."})
                            return
                        findings = connection.execute(
                            "SELECT severity, name, matched_at, template_id FROM finding WHERE run_id = ? ORDER BY id",
                            (run_id,),
                        ).fetchall()
                        connection.close()
                        from recon_ai.i18n import display_name

                        payload["finding_rows"] = []
                        for row in findings:
                            item = dict(row)
                            item["name"] = display_name(item.get("template_id"), item.get("name"), locale)
                            payload["finding_rows"].append(item)
                        content_type, body = render_export(
                            payload,
                            results_dir / payload["run"]["output_dir"],
                            fmt,
                            locale,
                            draft=draft,
                        )
                    except ExportError as exc:
                        self._json(400, {"error": str(exc)})
                        return
                    name = (
                        f"rascunho.{'docx' if fmt.lower() in {'docx', 'word'} else 'pdf'}"
                        if draft
                        else f"relatorio.{'docx' if fmt.lower() in {'docx', 'word'} else 'pdf'}"
                    )
                    self.send_response(200)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Content-Disposition", f'attachment; filename="{name}"')
                    self.end_headers()
                    self.wfile.write(body)
                    return
            try:
                connection = connect_readonly(database)
            except FileNotFoundError as exc:
                self._json(503, {"error": str(exc)})
                return
            try:
                if parsed.path == "/api/runs":
                    payload = list_runs(connection)
                elif parsed.path.startswith("/api/runs/"):
                    try:
                        locale = _requested_locale(parsed)
                    except ValueError as exc:
                        self._json(400, {"error": str(exc)})
                        return
                    run_id, extra = _run_id_from(parsed.path)
                    if extra.startswith("drafts/") and run_id:
                        from recon_ai.drafts import DraftError, lookup_key, read_markdown

                        key = unquote(extra.split("/", 1)[1])
                        payload = run_view(connection, run_id, locale)
                        if payload is None:
                            self._json(404, {"error": "run ausente"})
                            return
                        try:
                            cluster = lookup_key(results_dir / payload["run"]["output_dir"], key)
                            text = read_markdown(results_dir / payload["run"]["output_dir"], cluster)
                        except DraftError as exc:
                            self._json(404, {"error": str(exc)})
                            return
                        self._json(200, {"cluster_key": cluster, "markdown": text})
                        return
                    if extra:
                        self._json(404, {"error": "nao encontrado"})
                        return
                    payload = run_view(connection, run_id, locale)
                    if payload is None:
                        self._json(404, {"error": "run ausente"})
                        return
                elif parsed.path == "/api/report":
                    try:
                        locale = _requested_locale(parsed)
                    except ValueError as exc:
                        self._json(400, {"error": str(exc)})
                        return
                    query = parse_qs(parsed.query)
                    payload = report(
                        connection,
                        target=query.get("target", [""])[0] or None,
                        run_id=query.get("run_id", [""])[0] or None,
                        kind=query.get("kind", [""])[0] or None,
                        severity=query.get("severity", [""])[0] or None,
                        locale=locale,
                    )
                else:
                    self._json(404, {"error": "nao encontrado"})
                    return
            finally:
                connection.close()
            self._json(200, payload)

        def do_POST(self):
            parsed = urlparse(self.path)
            if parsed.path == "/api/ai/complete":
                self._consult_ai()
                return
            if parsed.path == "/api/runs":
                try:
                    body, har_bytes, har_b_bytes = _read_run_post(self)
                    spec = normalize_spec(body, body.get("threads"))
                    refuse_scope(spec["target"], spec.get("in_scope"))
                except (JobError, ValueError) as exc:
                    self._json(400, {"error": str(exc)})
                    return
                except ControlError as exc:
                    self._json(403 if exc.code == 3 else 400, {"error": str(exc)})
                    return
                if not SCAN_LOCK.acquire(blocking=False):
                    self._json(409, {"error": "Já existe um scan em execução."})
                    return
                connection = db.connect(database)
                db.reap_stale_runs(connection)
                if db.running_run(connection):
                    SCAN_LOCK.release()
                    connection.close()
                    self._json(409, {"error": "Já existe um scan em execução."})
                    return
                target_dir = output_name(spec["target"])
                if har_bytes is not None:
                    dest = results_dir / target_dir / "har" / "capture.har"
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(har_bytes)
                    spec["har_path"] = str(dest)
                if har_b_bytes is not None:
                    dest_b = results_dir / target_dir / "har" / "capture-b.har"
                    dest_b.parent.mkdir(parents=True, exist_ok=True)
                    dest_b.write_bytes(har_b_bytes)
                    spec["har_b_path"] = str(dest_b)
                run_id = db.new_run(connection, spec["target"], target_dir, spec["threads"], spec)
                connection.close()

                def worker():
                    try:
                        run_job(spec, output=target_dir, run_id=run_id, verify=True)
                    except Exception:
                        traceback.print_exc()
                        try:
                            failed = db.connect(database)
                            db.finish_run(failed, run_id, "failed")
                            failed.execute(
                                """
                                UPDATE phase
                                SET status = 'fail', exit_code = 1, detail = ?
                                WHERE run_id = ? AND status = 'running'
                                """,
                                ("exceção na thread do scan; traceback no log da UI", run_id),
                            )
                            failed.commit()
                            failed.close()
                        except Exception:
                            traceback.print_exc()
                    finally:
                        SCAN_LOCK.release()

                threading.Thread(target=worker, daemon=True).start()
                self._json(202, {"run_id": run_id})
                return
            if parsed.path.startswith("/api/runs/"):
                run_id, extra = _run_id_from(parsed.path)
                if extra.startswith("drafts/") and run_id:
                    from recon_ai.drafts import DRAFT_STATUSES, DraftError, lookup_key, set_status

                    key = unquote(extra.split("/", 1)[1])
                    try:
                        body = _read_body(self)
                    except ValueError as exc:
                        self._json(400, {"error": str(exc)})
                        return
                    status = body.get("status")
                    if status not in DRAFT_STATUSES:
                        self._json(400, {"error": "Status de rascunho inválido."})
                        return
                    connection = db.connect(database)
                    payload = run_view(connection, run_id)
                    if payload is None:
                        connection.close()
                        self._json(404, {"error": "run ausente"})
                        return
                    if payload["run"]["status"] == "running":
                        connection.close()
                        self._json(409, {"error": "Run ainda em execução."})
                        return
                    output = results_dir / payload["run"]["output_dir"]
                    connection.close()
                    try:
                        cluster = lookup_key(output, key)
                        set_status(output, cluster, status)
                    except DraftError as exc:
                        self._json(404, {"error": str(exc)})
                        return
                    self._json(200, {"cluster_key": cluster, "status": status})
                    return
                if extra == "stop" and run_id:
                    connection = db.connect(database)
                    try:
                        stop_run(run_id, connection)
                    except ControlError as exc:
                        connection.close()
                        self._json(404 if "inexistente" in str(exc) else 409, {"error": str(exc)})
                        return
                    connection.close()
                    self._json(200, {"run_id": run_id, "status": "stopping"})
                    return
            self._json(404, {"error": "nao encontrado"})

        def do_DELETE(self):
            parsed = urlparse(self.path)
            if not parsed.path.startswith("/api/runs/"):
                self._json(404, {"error": "nao encontrado"})
                return
            run_id, extra = _run_id_from(parsed.path)
            if extra or not run_id:
                self._json(404, {"error": "nao encontrado"})
                return
            connection = db.connect(database)
            try:
                run = db.delete_run(connection, run_id)
            except db.RunError as exc:
                connection.close()
                self._json(409, {"error": str(exc)})
                return
            connection.close()
            if run is None:
                self._json(404, {"error": "run ausente"})
                return
            _purge_output(results_dir, run.get("output_dir"))
            self._json(200, {"run_id": run_id, "deleted": True})

        def _consult_ai(self):
            try:
                body = _read_body(self)
            except ValueError as exc:
                self._json(400, {"error": str(exc)})
                return
            prompt = body.get("prompt")
            if not isinstance(prompt, str) or not prompt.strip():
                self._json(400, {"error": "Prompt vazio."})
                return
            estimated = estimate_prompt_tokens(prompt)
            if estimated > INPUT_TOKEN_BUDGET:
                self._json(
                    400,
                    {
                        "error": "Prompt acima do orçamento de entrada.",
                        "estimated_prompt_tokens": estimated,
                        "input_token_budget": INPUT_TOKEN_BUDGET,
                    },
                )
                return
            if SCAN_LOCK.locked():
                self._json(409, {"error": "IA ocupada pelo scan."})
                return
            connection = db.connect(database)
            try:
                busy = db.running_run(connection)
            finally:
                connection.close()
            if busy:
                self._json(409, {"error": "IA ocupada pelo scan."})
                return
            if not AI_CHAT_LOCK.acquire(blocking=False):
                self._json(409, {"error": "Consulta já em curso."})
                return
            try:
                client = ai_client or OllamaClient(ollama_url)
                usage = client.complete_with_usage(prompt, json_format=False)
            except AiError as exc:
                self._json(503, {"error": str(exc)})
                return
            finally:
                AI_CHAT_LOCK.release()
            result = usage["result"]
            content = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
            self._json(
                200,
                {
                    "model": MODEL,
                    "content": content,
                    "estimated_prompt_tokens": estimated,
                    "prompt_eval_count": usage.get("prompt_eval_count"),
                    "eval_count": usage.get("eval_count"),
                },
            )

        def _json(self, status, payload):
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self._send(status, "application/json", body)

        def _send(self, status, content_type, body):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            return

    return ThreadingHTTPServer((host, port), Handler)


def main():
    database = os.environ.get("RECON_DB", "/results/recon.db")
    Path(database).parent.mkdir(parents=True, exist_ok=True)
    db.connect(database).close()
    host = os.environ.get("RECON_UI_HOST", "127.0.0.1")
    port = int(os.environ.get("RECON_UI_PORT", "8765"))
    server = make_server(database, host, port)
    print(f"controle em http://{host}:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
