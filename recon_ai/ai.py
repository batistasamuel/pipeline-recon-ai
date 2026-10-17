import hashlib
import json
import math
import re
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from recon_ai import db

MODEL = "qwen2.5:7b"
DECISIONS = {"keep", "review", "false_positive"}
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
NUM_CTX = 16384
MAX_OUTPUT_TOKENS = 2500
SAFETY_MARGIN_TOKENS = 1000
MAX_PREDICT_TOKENS = MAX_OUTPUT_TOKENS
INPUT_TOKEN_BUDGET = NUM_CTX - MAX_OUTPUT_TOKENS - SAFETY_MARGIN_TOKENS
CLASSIFY_OUTPUT_BUDGET = MAX_PREDICT_TOKENS - 500
CLASSIFY_REASON_BUDGET = (
    "Sinal correlacionado sem evidência de vulnerabilidade explorável "
    "no contexto observado; revisar manualmente o artefato e o host."
)
JS_CHUNK_CHARS = 20000
JS_CHUNK_OVERLAP = 400
FOCUS_WINDOW_CHARS = 2400
FOCUS_MAX_CHARS = 4000
MAX_ROUTES_PER_CALL = 24
MIN_SPLIT_CHARS = 400
MANIFEST_NAME = "ai_manifest.jsonl"
TRUNCATED_PREFIX = "Resposta do Ollama truncada"


class AiError(Exception):
    pass


class CloudNotAvailable(AiError):
    pass


def validate_classification(payload, allowed_ids):
    if not isinstance(payload, dict) or set(payload) != {"items"}:
        raise AiError("Classificação fora do schema.")
    items = payload["items"]
    if not isinstance(items, list):
        raise AiError("Classificação fora do schema.")
    seen = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {"finding_id", "decision", "reason"}:
            raise AiError("Classificação fora do schema.")
        finding_id = item["finding_id"]
        if finding_id not in allowed_ids or finding_id in seen:
            raise AiError("Classificação cita um finding desconhecido.")
        if item["decision"] not in DECISIONS:
            raise AiError("Decisão inválida.")
        reason = item["reason"]
        if not isinstance(reason, str) or not reason.strip():
            raise AiError("Justificativa ausente.")
        seen.add(finding_id)
    if seen != set(allowed_ids):
        raise AiError("Classificação não cobre todos os findings.")
    return payload


def validate_routes(payload):
    if not isinstance(payload, dict) or set(payload) != {"routes"}:
        raise AiError("Rotas fora do schema.")
    routes = payload["routes"]
    if not isinstance(routes, list):
        raise AiError("Rotas fora do schema.")
    for route in routes:
        if not isinstance(route, dict) or "path" not in route:
            raise AiError("Rota sem path.")
        extra = set(route) - {"path", "method"}
        if extra:
            raise AiError("Rota fora do schema.")
        path = route["path"]
        if not isinstance(path, str) or not path.startswith("/"):
            raise AiError("Path de rota inválido.")
        if "HOST_" in path or "IP_" in path or "EMAIL_" in path:
            raise AiError("Path de rota inválido.")
        method = route.get("method")
        if method is not None and method not in METHODS:
            raise AiError("Método de rota inválido.")
    return payload


def estimate_prompt_tokens(text):
    if not text:
        return 0
    return max(1, math.ceil(len(text.encode("utf-8")) / 3))


class OllamaClient:
    provider = "ollama"
    model = MODEL

    def __init__(self, base_url, timeout=600):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def complete(self, prompt):
        return self.complete_with_usage(prompt)["result"]

    def complete_with_usage(self, prompt, json_format=True):
        payload = {
            "model": MODEL,
            "stream": False,
            "keep_alive": "30m",
            "options": {
                "num_ctx": NUM_CTX,
                "temperature": 0,
                "num_predict": MAX_PREDICT_TOKENS,
            },
            "messages": [{"role": "user", "content": prompt}],
        }
        if json_format:
            payload["format"] = "json"
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except TimeoutError as exc:
            raise AiError("Ollama excedeu o tempo da chamada.") from exc
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise AiError(f"Ollama respondeu HTTP {exc.code}. {detail}") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise AiError("Ollama excedeu o tempo da chamada.") from exc
            raise AiError(
                "Ollama não está acessível. Suba com: docker compose --profile ai up -d ollama"
            ) from exc
        if data.get("model") and not str(data["model"]).startswith(MODEL):
            raise AiError(f"Modelo divergente: {data.get('model')}.")
        content = (data.get("message") or {}).get("content")
        if not isinstance(content, str):
            raise AiError("Resposta do Ollama sem conteúdo JSON." if json_format else "Resposta do Ollama sem conteúdo.")
        done_reason = data.get("done_reason")
        eval_count = data.get("eval_count")
        if json_format:
            try:
                result = json.loads(content)
            except json.JSONDecodeError as exc:
                if _output_hit_limit(done_reason, eval_count):
                    raise AiError(
                        f"{TRUNCATED_PREFIX} (done_reason={done_reason}, eval_count={eval_count})."
                    ) from exc
                raise AiError("Resposta do Ollama não é JSON.") from exc
        else:
            result = content
        return {
            "result": result,
            "prompt_eval_count": data.get("prompt_eval_count"),
            "eval_count": eval_count,
            "done_reason": done_reason,
        }


def js_chunks(output_dir, chunk_chars=JS_CHUNK_CHARS, overlap=JS_CHUNK_OVERLAP):
    content = Path(output_dir) / "js" / "content"
    if not content.is_dir() or chunk_chars < 1:
        return []
    if overlap >= chunk_chars:
        overlap = 0
    seen = set()
    chunks = []
    for path in sorted(content.glob("*.js")):
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if not text:
            continue
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        start = 0
        part = 1
        while start < len(text):
            chunks.append((path.name, part, text[start : start + chunk_chars]))
            if start + chunk_chars >= len(text):
                break
            start += chunk_chars - overlap
            part += 1
    return chunks


def validate_tech(payload):
    if not isinstance(payload, dict) or set(payload) != {"items"}:
        raise AiError("Stack fora do schema.")
    items = payload["items"]
    if not isinstance(items, list):
        raise AiError("Stack fora do schema.")
    for item in items:
        if not isinstance(item, dict):
            raise AiError("Stack fora do schema.")
        extra = set(item) - {"name", "version", "note"}
        if extra or "name" not in item:
            raise AiError("Stack fora do schema.")
        name = item["name"]
        if not isinstance(name, str) or not name.strip():
            raise AiError("Stack fora do schema.")
        for field in ("version", "note"):
            if field in item and not isinstance(item[field], str):
                raise AiError("Stack fora do schema.")
    return payload


def _tech_names(output_dir):
    from recon_ai.derive import read_fingerprints

    seen = []
    for row in read_fingerprints(output_dir):
        for item in row.get("tech") or []:
            text = item.strip() if isinstance(item, str) else ""
            if text and text not in seen:
                seen.append(text)
    return seen


def _tech_prompt(names, locale=None):
    from recon_ai.i18n import t

    lines = [t("ai.tech_intro", locale)]
    lines.extend(names)
    return "\n".join(lines)


def _provider_of(client):
    name = getattr(client, "provider", None)
    if name:
        return name
    inner = getattr(client, "inner", None)
    return getattr(inner, "provider", None) or "ollama"


def _model_of(client):
    name = getattr(client, "model", None)
    if name:
        return name
    inner = getattr(client, "inner", None)
    return getattr(inner, "model", None) or MODEL


def _classification_prompt(findings, locale=None):
    from recon_ai.i18n import t

    lines = [
        t("ai.classify_intro", locale),
        t("ai.classify_decision", locale),
        t("ai.classify_reason", locale),
    ]
    for finding in findings:
        lines.append(
            f"id={finding['id']} severity={finding['severity']} "
            f"template={finding['template_id']} name={finding['name']} "
            f"at={finding['matched_at']}"
        )
    return "\n".join(lines)


def estimated_classification_output_tokens(findings):
    items = [
        {
            "finding_id": finding["id"],
            "decision": "false_positive",
            "reason": CLASSIFY_REASON_BUDGET,
        }
        for finding in findings
    ]
    return estimate_prompt_tokens(json.dumps({"items": items}, ensure_ascii=False))


def classification_batches(findings, output_budget=CLASSIFY_OUTPUT_BUDGET):
    if not findings:
        return []
    batches = []
    current = []
    for finding in findings:
        candidate = current + [finding]
        if current and estimated_classification_output_tokens(candidate) > output_budget:
            batches.append(current)
            current = [finding]
        else:
            current = candidate
    if current:
        batches.append(current)
    return batches


def _routes_prompt(excerpt, locale=None):
    from recon_ai.i18n import t

    return t("ai.routes", locale) + excerpt


LITERAL_PATH = re.compile(r"""["'](/[^"'\\\s]+)["']""")


def literal_paths(text):
    return {path for path in LITERAL_PATH.findall(text) if path.strip("/")}


def _literal_matches(text):
    return [match for match in LITERAL_PATH.finditer(text) if match.group(1).strip("/")]


def route_excerpts(
    excerpt,
    window=FOCUS_WINDOW_CHARS,
    max_paths=MAX_ROUTES_PER_CALL,
    max_chars=FOCUS_MAX_CHARS,
):
    return _excerpts_for_matches(excerpt, _literal_matches(excerpt), window, max_paths, max_chars)


def _excerpts_for_matches(excerpt, matches, window, max_paths, max_chars):
    if not matches:
        return []
    if len(matches) > max_paths:
        mid = len(matches) // 2
        return _excerpts_for_matches(
            excerpt, matches[:mid], window, max_paths, max_chars
        ) + _excerpts_for_matches(excerpt, matches[mid:], window, max_paths, max_chars)
    start = max(0, matches[0].start() - window // 2)
    end = min(len(excerpt), matches[-1].end() + window // 2)
    text = excerpt[start:end]
    if len(text) > max_chars and len(matches) > 1:
        mid = len(matches) // 2
        return _excerpts_for_matches(
            excerpt, matches[:mid], window, max_paths, max_chars
        ) + _excerpts_for_matches(excerpt, matches[mid:], window, max_paths, max_chars)
    return [text]


def _output_hit_limit(done_reason, eval_count):
    if done_reason == "length":
        return True
    return eval_count is not None and eval_count >= MAX_PREDICT_TOKENS


def _is_truncated(exc):
    return str(exc).startswith(TRUNCATED_PREFIX)


def _is_unusable_json(exc):
    text = str(exc).casefold()
    return "json_validate_failed" in text or "não é json" in text


def routes_keeping_slash_paths(payload):
    if not isinstance(payload, dict) or set(payload) != {"routes"}:
        return None
    routes = payload["routes"]
    if not isinstance(routes, list):
        return None
    kept = []
    for route in routes:
        if not isinstance(route, dict):
            continue
        path = route.get("path")
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or not path.strip("/"):
            continue
        if "HOST_" in path or "IP_" in path or "EMAIL_" in path:
            continue
        kept.append(route)
    return {"routes": kept}


def grounded_routes(payload, excerpt):
    kept = [route for route in payload["routes"] if route["path"] in excerpt]
    return {"routes": kept}


def _merge_routes(groups):
    merged = []
    seen = set()
    for routes in groups:
        for route in routes:
            key = (route["path"], route.get("method"))
            if key in seen:
                continue
            seen.add(key)
            merged.append(route)
    return merged


_active_pace = None
_manifest_lock = threading.Lock()


def _invoke(client, prompt):
    from recon_ai.pseudonym import IdentityLeak

    pace = _active_pace
    if pace is not None:
        pace.wait()
    try:
        method = getattr(client, "complete_with_usage", None)
        if method is not None:
            return method(prompt)
        return {
            "result": client.complete(prompt),
            "prompt_eval_count": None,
            "eval_count": None,
            "done_reason": None,
        }
    except IdentityLeak as exc:
        raise AiError(str(exc)) from exc
    finally:
        if pace is not None:
            pace.mark()


def _over_budget(prompt_eval_count):
    return prompt_eval_count is not None and prompt_eval_count > INPUT_TOKEN_BUDGET


def _usage_fields(prompt, usage):
    sent = prompt if usage is None else usage.get("sent_prompt", prompt)
    prompt_eval_count = None if usage is None else usage.get("prompt_eval_count")
    return {
        "prompt_sha256": hashlib.sha256(sent.encode("utf-8")).hexdigest(),
        "prompt_eval_count": prompt_eval_count,
        "eval_count": None if usage is None else usage.get("eval_count"),
        "done_reason": None if usage is None else usage.get("done_reason"),
        "input_budget": INPUT_TOKEN_BUDGET,
        "over_budget": _over_budget(prompt_eval_count),
    }


def _reset_manifest(path):
    path.write_text("", encoding="utf-8")


def _append_manifest(path, row):
    payload = json.dumps(row, ensure_ascii=False) + "\n"
    with _manifest_lock:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()


def _failure_message(schema_errors, transport_errors, manifest_path, classification=False):
    parts = [
        f"{schema_errors} parte(s) com erro de schema",
        f"{transport_errors} com erro de transporte",
    ]
    if classification:
        parts.append("classificação rejeitada")
    return "Análise não publicada: " + ", ".join(parts) + f". Manifest: {manifest_path}"


def _empty_route_manifest(index, name, part, excerpt):
    return {
        "task": "routes",
        "chunk": index,
        "parts": [{"file": name, "part": part, "chars": len(excerpt)}],
        "prompt_sha256": None,
        "prompt_eval_count": None,
        "eval_count": None,
        "done_reason": None,
        "input_budget": INPUT_TOKEN_BUDGET,
        "over_budget": False,
        "valid": True,
        "response": {"routes": []},
        "validation_error": None,
        "error": None,
        "model_called": False,
    }


def _analyze_one_route_chunk(client, index, name, part, excerpt, manifest_path, locale, on_progress, total):
    if on_progress is not None:
        on_progress(index, total, name, part)
    pieces = route_excerpts(excerpt)
    if not pieces:
        _append_manifest(manifest_path, _empty_route_manifest(index, name, part, excerpt))
        return [], 0, 0, False, False, False
    queue = list(pieces)
    chunk_routes = []
    schema_errors = 0
    transport_errors = 0
    had_error = False
    while queue:
        piece = queue.pop(0)
        if not literal_paths(piece):
            continue
        prompt = _routes_prompt(piece, locale)
        try:
            usage = _invoke(client, prompt)
        except AiError as exc:
            if _is_truncated(exc) and len(piece) > MIN_SPLIT_CHARS:
                mid = len(piece) // 2
                queue.insert(0, piece[mid:])
                queue.insert(0, piece[:mid])
                continue
            if _is_unusable_json(exc):
                _append_manifest(
                    manifest_path,
                    {
                        "task": "routes",
                        "chunk": index,
                        "parts": [{"file": name, "part": part, "chars": len(piece)}],
                        **_usage_fields(prompt, None),
                        "valid": True,
                        "response": {"routes": []},
                        "validation_error": None,
                        "error": str(exc),
                        "model_called": True,
                    },
                )
                continue
            _append_manifest(
                manifest_path,
                {
                    "task": "routes",
                    "chunk": index,
                    "parts": [{"file": name, "part": part, "chars": len(piece)}],
                    **_usage_fields(prompt, None),
                    "valid": False,
                    "response": None,
                    "validation_error": None,
                    "error": str(exc),
                    "model_called": True,
                },
            )
            return chunk_routes, schema_errors, 1, True, True, True
        filtered = routes_keeping_slash_paths(usage["result"])
        try:
            validated = validate_routes(usage["result"] if filtered is None else filtered)
        except AiError as exc:
            _append_manifest(
                manifest_path,
                {
                    "task": "routes",
                    "chunk": index,
                    "parts": [{"file": name, "part": part, "chars": len(piece)}],
                    **_usage_fields(prompt, usage),
                    "valid": False,
                    "response": usage["result"],
                    "validation_error": str(exc),
                    "error": None,
                    "model_called": True,
                },
            )
            schema_errors += 1
            had_error = True
            continue
        validated = grounded_routes(validated, piece)
        _append_manifest(
            manifest_path,
            {
                "task": "routes",
                "chunk": index,
                "parts": [{"file": name, "part": part, "chars": len(piece)}],
                **_usage_fields(prompt, usage),
                "valid": True,
                "response": validated,
                "validation_error": None,
                "error": None,
                "model_called": True,
            },
        )
        chunk_routes.extend(validated["routes"])
    return chunk_routes, schema_errors, transport_errors, had_error, True, False


def _collect_routes(client, chunks, manifest_path, locale, on_progress, parallel=False):
    total = len(chunks)
    groups = [[] for _ in chunks]
    schema_errors = 0
    transport_errors = 0
    had_error = False
    called_model = False
    workers = max(1, int(getattr(client, "worker_count", 1) or 1))
    use_pool = parallel and total > 1 and workers > 1

    def run_one(index_name):
        index, (name, part, excerpt) = index_name
        return index, _analyze_one_route_chunk(
            client, index, name, part, excerpt, manifest_path, locale, on_progress, total
        )

    items = list(enumerate(chunks, start=1))
    if use_pool:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(run_one, item) for item in items]
            for future in as_completed(futures):
                index, (routes, schema, transport, failed, called, stopped) = future.result()
                groups[index - 1] = routes
                schema_errors += schema
                transport_errors += transport
                had_error = had_error or failed
                called_model = called_model or called
                if stopped:
                    for other in futures:
                        other.cancel()
                    break
    else:
        for item in items:
            index, (routes, schema, transport, failed, called, stopped) = run_one(item)
            groups[index - 1] = routes
            schema_errors += schema
            transport_errors += transport
            had_error = had_error or failed
            called_model = called_model or called
            if stopped:
                break
    return schema_errors, transport_errors, had_error, called_model, groups


def analyze(
    connection,
    run_id,
    results_root,
    client,
    cloud=False,
    chunk_chars=JS_CHUNK_CHARS,
    on_progress=None,
    ai_delay_ms=None,
    parallel=False,
):
    from recon_ai.pace import Pace, coerce_ai_delay_ms

    run = db.get_run(connection, run_id)
    if run is None:
        raise AiError(f"Run inexistente: {run_id}")
    spec = db.get_spec(connection, run_id) or {}
    locale = spec.get("lang")
    output_dir = Path(results_root) / run["output_dir"]
    if cloud:
        from recon_ai.pseudonym import PseudonymizingClient, collect_identities, write_map

        mapping = collect_identities(spec or {"target": run["target"]}, connection, run_id)
        write_map(output_dir, mapping)
        client = PseudonymizingClient(client, mapping)
    from recon_ai.catalog import hydrate_finding

    findings = [hydrate_finding(item) for item in db.list_findings(connection, run_id)]
    chunks = js_chunks(output_dir, chunk_chars)
    manifest_path = output_dir / MANIFEST_NAME
    _reset_manifest(manifest_path)
    global _active_pace
    previous_pace = _active_pace
    _active_pace = Pace(coerce_ai_delay_ms(ai_delay_ms if ai_delay_ms is not None else spec.get("ai_delay_ms")))
    try:
        schema_errors, transport_errors, had_error, called_model, groups = _collect_routes(
            client,
            chunks,
            manifest_path,
            locale,
            on_progress,
            parallel=parallel,
        )
        if had_error:
            raise AiError(_failure_message(schema_errors, transport_errors, manifest_path))
        from recon_ai.cluster import reportable_findings, write_clusters
        from recon_ai.drafts import drafts_dir
        from recon_ai.verify import persist_verified, verify_findings

        findings = verify_findings(findings, output_dir, enabled=bool(spec.get("verify")))
        persist_verified(connection, run_id, findings)
        clusters = write_clusters(output_dir, findings)
        drafts_dir(output_dir)
        reportable = reportable_findings(findings)
        if reportable:
            classification = _classify(client, reportable, manifest_path, schema_errors, transport_errors, locale)
        else:
            classification = ("classification", "none", "", {"items": []})
        if not chunks:
            routes = ("routes", "none", "", {"routes": []})
        elif called_model:
            routes = ("routes", _provider_of(client), _model_of(client), {"routes": _merge_routes(groups)})
        else:
            routes = ("routes", "none", "", {"routes": _merge_routes(groups)})
        pending = [classification, routes]
        techs = _tech_names(output_dir)
        if techs:
            pending.append(_analyze_tech(client, techs, manifest_path, locale))
        drafts = _analyze_drafts(client, reportable, clusters, output_dir, manifest_path, locale)
        if drafts is not None:
            pending.append(drafts)
        db.save_ai_results(
            connection,
            run_id,
            [
                (task, provider, model, json.dumps(payload, ensure_ascii=False))
                for task, provider, model, payload in pending
            ],
        )
        routes_path = output_dir / "urls" / "ai_routes.txt"
        routes_path.parent.mkdir(parents=True, exist_ok=True)
        paths = []
        for item in (pending[1][3] or {}).get("routes") or []:
            path = item.get("path")
            if path:
                paths.append(path)
        routes_path.write_text(("\n".join(sorted(set(paths))) + "\n") if paths else "", encoding="utf-8")
        return pending
    finally:
        _active_pace = previous_pace


def _classify_parts(batch):
    from recon_ai.cluster import group_findings

    return [
        {"cluster": row["cluster_key"], "count": row["count"], "ids": row["ids"]}
        for row in group_findings(batch)
    ]


def _classify(client, findings, manifest_path, schema_errors, transport_errors, locale=None):
    queue = list(classification_batches(findings))
    items = []
    chunk = 0
    while queue:
        batch = queue.pop(0)
        chunk += 1
        prompt = _classification_prompt(batch, locale)
        try:
            usage = _invoke(client, prompt)
        except AiError as exc:
            if _is_truncated(exc) and len(batch) > 1:
                mid = len(batch) // 2
                queue.insert(0, batch[mid:])
                queue.insert(0, batch[:mid])
                chunk -= 1
                continue
            _append_manifest(
                manifest_path,
                {
                    "task": "classification",
                    "chunk": chunk,
                    "parts": _classify_parts(batch),
                    **_usage_fields(prompt, None),
                    "valid": False,
                    "response": None,
                    "validation_error": None,
                    "error": str(exc),
                    "model_called": True,
                },
            )
            raise AiError(
                _failure_message(schema_errors, transport_errors + 1, manifest_path, classification=True)
            ) from exc
        try:
            payload = validate_classification(usage["result"], {finding["id"] for finding in batch})
        except AiError as exc:
            _append_manifest(
                manifest_path,
                {
                    "task": "classification",
                    "chunk": chunk,
                    "parts": _classify_parts(batch),
                    **_usage_fields(prompt, usage),
                    "valid": False,
                    "response": usage["result"],
                    "validation_error": str(exc),
                    "error": None,
                    "model_called": True,
                },
            )
            raise AiError(
                _failure_message(schema_errors + 1, transport_errors, manifest_path, classification=True)
            ) from exc
        _append_manifest(
            manifest_path,
            {
                "task": "classification",
                "chunk": chunk,
                "parts": _classify_parts(batch),
                **_usage_fields(prompt, usage),
                "valid": True,
                "response": payload,
                "validation_error": None,
                "error": None,
                "model_called": True,
            },
        )
        items.extend(payload["items"])
    merged = validate_classification({"items": items}, {finding["id"] for finding in findings})
    return ("classification", _provider_of(client), _model_of(client), merged)


def _analyze_tech(client, names, manifest_path, locale=None):
    prompt = _tech_prompt(names, locale)
    try:
        usage = _invoke(client, prompt)
    except AiError as exc:
        _append_manifest(
            manifest_path,
            {
                "task": "tech",
                "chunk": None,
                "parts": [],
                **_usage_fields(prompt, None),
                "valid": False,
                "response": None,
                "validation_error": None,
                "error": str(exc),
                "model_called": True,
            },
        )
        raise AiError(_failure_message(0, 1, manifest_path)) from exc
    try:
        payload = validate_tech(usage["result"])
    except AiError as exc:
        _append_manifest(
            manifest_path,
            {
                "task": "tech",
                "chunk": None,
                "parts": [],
                **_usage_fields(prompt, usage),
                "valid": False,
                "response": usage["result"],
                "validation_error": str(exc),
                "error": None,
                "model_called": True,
            },
        )
        raise AiError(_failure_message(1, 0, manifest_path)) from exc
    _append_manifest(
        manifest_path,
        {
            "task": "tech",
            "chunk": None,
            "parts": [],
            **_usage_fields(prompt, usage),
            "valid": True,
            "response": payload,
            "validation_error": None,
            "error": None,
            "model_called": True,
        },
    )
    return ("tech", _provider_of(client), _model_of(client), payload)


def _deterministic_draft(cluster, findings, locale=None):
    from recon_ai.catalog import entry_for
    from recon_ai.drafts import deterministic_steps
    from recon_ai.i18n import t

    sample = findings[0]
    evidence = sample.get("evidence") or {}
    meta = entry_for(sample.get("template_id"), evidence)
    asset = sample.get("matched_at") or ""
    title = t(meta.get("title_key") or "catalog.title.note", locale, asset=asset)
    return {
        "title": title,
        "summary": t("catalog.summary_fallback", locale, name=sample.get("name") or "", asset=asset),
        "impact": t("catalog.impact_fallback", locale),
        "steps": deterministic_steps(findings, locale),
        "evidence_notes": evidence.get("detail")
        or evidence.get("description")
        or t("catalog.evidence_fallback", locale),
    }


def _draft_prompt(cluster, findings, locale=None):
    from recon_ai.i18n import t

    skeleton = _deterministic_draft(cluster, findings, locale)
    sample = findings[0]
    evidence = sample.get("evidence") or {}
    return "\n".join(
        [
            t("ai.draft_intro", locale),
            f"title={skeleton['title']}",
            f"template={sample.get('template_id')}",
            f"cwe={evidence.get('cwe') or ''}",
            f"asset={sample.get('matched_at') or ''}",
            f"detail={evidence.get('detail') or evidence.get('description') or ''}",
        ]
    )


def _analyze_drafts(client, findings, clusters, output_dir, manifest_path, locale=None):
    from recon_ai.drafts import DraftError, validate_draft, write_draft

    reportable = [row for row in clusters if row.get("class") == "reportable"]
    if not reportable:
        return None
    by_key = {}
    for finding in findings:
        by_key.setdefault(finding.get("cluster_key"), []).append(finding)
    written = []
    use_model = _provider_of(client) != "google-ai-studio"
    for index, cluster in enumerate(reportable, start=1):
        members = by_key.get(cluster["cluster_key"]) or []
        if not members:
            continue
        skeleton = _deterministic_draft(cluster, members, locale)
        usage = None
        prompt = _draft_prompt(cluster, members, locale)
        if use_model:
            try:
                usage = _invoke(client, prompt)
            except AiError as exc:
                _append_manifest(
                    manifest_path,
                    {
                        "task": "draft",
                        "chunk": index,
                        "parts": [{"cluster": cluster["cluster_key"], "count": len(members)}],
                        **_usage_fields(prompt, None),
                        "valid": False,
                        "response": None,
                        "validation_error": None,
                        "error": str(exc),
                        "model_called": True,
                    },
                )
                raise AiError(_failure_message(0, 1, manifest_path)) from exc
            payload = dict(usage["result"]) if isinstance(usage["result"], dict) else {}
            payload["title"] = skeleton["title"]
            payload["steps"] = skeleton["steps"]
            if not payload.get("summary"):
                payload["summary"] = skeleton["summary"]
            if not payload.get("impact"):
                payload["impact"] = skeleton["impact"]
            if not payload.get("evidence_notes"):
                payload["evidence_notes"] = skeleton["evidence_notes"]
        else:
            payload = skeleton
        try:
            validated = validate_draft(payload)
        except DraftError as exc:
            _append_manifest(
                manifest_path,
                {
                    "task": "draft",
                    "chunk": index,
                    "parts": [{"cluster": cluster["cluster_key"], "count": len(members)}],
                    **_usage_fields(prompt, usage),
                    "valid": False,
                    "response": payload,
                    "validation_error": str(exc),
                    "error": None,
                    "model_called": use_model,
                },
            )
            raise AiError(_failure_message(1, 0, manifest_path)) from exc
        write_draft(output_dir, cluster, members, validated, locale)
        _append_manifest(
            manifest_path,
            {
                "task": "draft",
                "chunk": index,
                "parts": [{"cluster": cluster["cluster_key"], "count": len(members)}],
                **_usage_fields(prompt, usage),
                "valid": True,
                "response": {"title": validated["title"]},
                "validation_error": None,
                "error": None,
                "model_called": use_model,
            },
        )
        written.append({"cluster_key": cluster["cluster_key"], "title": validated["title"]})
    if not written:
        return None
    return ("draft", _provider_of(client) if use_model else "catalog", _model_of(client) if use_model else "", {"items": written})

