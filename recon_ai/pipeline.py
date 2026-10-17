import json
import os
import signal
import subprocess
import time
from pathlib import Path

from recon_ai.derive import (
    append_provenance,
    scan_js_secrets,
    write_buckets,
    write_fingerprints,
)
from recon_ai.job import SUBDOMAIN_SOURCES, URL_SOURCES, tool_enabled, tool_param
from recon_ai.parse import (
    classify_http,
    endpoints_in_js,
    host_in_domain,
    hosts_without_wildcard,
    js_urls,
    name_allowed,
    names_from_text,
    nuclei_findings,
    parse_cname,
    parse_dns,
    referenced_scripts,
    source_map_url,
    url_allowed,
    urls_for_domain,
)
from recon_ai.phases import PHASES, SCAN_PHASES
from recon_ai.scope import is_literal_host, probe_address


class Cancelled(Exception):
    pass


ARCHIVE_HOST_CAP = 30
ARCHIVE_PROBE_CAP = 200
TAKEOVER_CAP = 30
HAR_NUCLEI_CAP = 50
HAR_NUCLEI_BATCH = 10
HAR_NUCLEI_MAX_HOST_ERROR = 3
JS_HOP_CAP = 50
MAP_CAP = 20


def _write(path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")


def _har_nuclei_args(spec, list_path):
    templates = os.environ.get("NUCLEI_TEMPLATES_DIR", "/opt/nuclei-templates")
    threads = tool_param(spec, "nuclei", "threads", None) or spec.get("threads") or 50
    return [
        "nuclei", "-l", str(list_path),
        "-t", f"{templates}/http/", "-t", f"{templates}/dns/", "-t", f"{templates}/ssl/",
        "-severity", str(tool_param(spec, "nuclei", "severity", "critical,high,medium")),
        "-tags", str(tool_param(spec, "nuclei", "tags", "cve,exposure,misconfiguration,takeover,tech,config,default-login")),
        "-c", str(threads),
        "-rate-limit", str(tool_param(spec, "nuclei", "rate_limit", 150)),
        "-timeout", str(tool_param(spec, "nuclei", "timeout", 10)),
        "-retries", str(tool_param(spec, "nuclei", "retries", 1)),
        "-max-host-error", str(HAR_NUCLEI_MAX_HOST_ERROR),
        "-silent", "-duc", "-or", "-jsonl",
    ]


def scan_har_nuclei(output_dir, spec, runner=None, on_progress=None, cancel_check=None, batch_size=HAR_NUCLEI_BATCH):
    output = Path(output_dir)
    if not tool_enabled(spec, "nuclei"):
        return 0
    live = {
        line.strip()
        for line in (output / "live" / "live_hosts.txt").read_text(encoding="utf-8").splitlines()
        if line.strip()
    } if (output / "live" / "live_hosts.txt").is_file() else set()
    har_file = output / "har" / "urls.txt"
    if not har_file.is_file():
        return 0
    chosen = []
    for line in har_file.read_text(encoding="utf-8").splitlines():
        url = line.strip()
        if not url or url in live:
            continue
        chosen.append(url)
        if len(chosen) >= HAR_NUCLEI_CAP:
            break
    if not chosen:
        return 0
    folder = output / "nuclei"
    _write(folder / "har_nuclei.txt", chosen)
    stdout = folder / "har.jsonl"
    stdout.write_text("", encoding="utf-8")
    step = batch_size if batch_size and batch_size > 0 else len(chosen)
    scanned = 0
    for offset in range(0, len(chosen), step):
        batch = chosen[offset : offset + step]
        part_list = folder / f"har_nuclei_{offset}.txt"
        part_out = folder / f"har_part_{offset}.jsonl"
        _write(part_list, batch)
        if on_progress:
            on_progress(scanned, len(chosen))
        code = _run(
            _har_nuclei_args(spec, part_list),
            part_out,
            output / "logs" / "har_nuclei.err",
            output,
            os.environ.copy(),
            runner,
            cancel_check,
        )
        if code != 0:
            return -1
        chunk = part_out.read_text(encoding="utf-8") if part_out.is_file() else ""
        if chunk:
            with stdout.open("a", encoding="utf-8") as handle:
                handle.write(chunk if chunk.endswith("\n") else chunk + "\n")
        scanned += len(batch)
    if on_progress:
        on_progress(scanned, len(chosen))
    return len(chosen)


def _run(args, stdout_path, stderr_path, cwd, env, runner, cancel_check=None):
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    if cancel_check:
        cancel_check()
    if runner is not None:
        code = runner(args, stdout_path, stderr_path)
        if cancel_check:
            cancel_check()
        return code
    with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
        proc = subprocess.Popen(
            args,
            cwd=cwd,
            env=env,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
    while True:
        try:
            return proc.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            if not cancel_check:
                continue
            try:
                cancel_check()
            except Cancelled:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait()
                raise


def _should(from_phase, name):
    if not from_phase:
        return True
    return PHASES.index(name) >= PHASES.index(from_phase)


class Pipeline:
    def __init__(self, domain, settings, output, env, runner=None, connection=None, run_id=None):
        self.domain = domain
        self.settings = settings
        self.output = Path(output)
        self.env = env
        self.runner = runner
        self.connection = connection
        self.run_id = run_id
        self.logs = self.output / "logs"
        self.phases = []
        self.failed = False
        self.cancelled = False
        self._current = None
        self.counts = {
            "subs": 0,
            "hosts": 0,
            "live": 0,
            "unauthorized": 0,
            "forbidden": 0,
            "urls": 0,
            "js": 0,
            "js_fail": 0,
            "endpoints": 0,
            "nuclei": 0,
        }

    def _job(self):
        return self.settings.get("job") or {}

    def _in_scope(self):
        return self._job().get("in_scope")

    def _out_scope(self):
        return self._job().get("out_scope")

    def _enabled(self, name):
        job = self._job()
        if job:
            return tool_enabled(job, name)
        return True

    def _param(self, name, key, default):
        job = self._job()
        if job:
            return tool_param(job, name, key, default)
        tools = self.settings.get("tools") or {}
        item = tools.get(name) or {}
        if key in item and item[key] is not None:
            return item[key]
        if name == "amass" and key == "timeout_minutes":
            return self.settings.get("amass_timeout", default)
        return default

    def _threads(self, name, fallback=None):
        value = self._param(name, "threads", None)
        if value is None and fallback:
            value = self._param(fallback, "threads", None)
        if value is None:
            value = self.settings.get("threads", 50)
        return str(value)

    def _names(self, text):
        return names_from_text(text, self.domain, self._in_scope(), self._out_scope())

    def _urls(self, lines):
        return urls_for_domain(lines, self.domain, self._in_scope(), self._out_scope())

    def _keep_hosts(self, hosts):
        return [host for host in hosts if name_allowed(host, self.domain, self._in_scope(), self._out_scope())]

    def _keep_urls(self, urls):
        return [url for url in urls if url_allowed(url, self.domain, self._in_scope(), self._out_scope())]

    def _call(self, args, stdout_path, stderr_path):
        return _run(args, stdout_path, stderr_path, self.output, self.env, self.runner, self._check_cancel)

    def _check_cancel(self):
        if self.connection is None or self.run_id is None:
            return
        from recon_ai import db

        if db.cancel_requested(self.connection, self.run_id):
            raise Cancelled()

    def run(self, from_phase=None):
        self.output.mkdir(parents=True, exist_ok=True)
        self.logs.mkdir(parents=True, exist_ok=True)
        order = [name for name in SCAN_PHASES if _should(from_phase, name)]
        try:
            for name in order:
                self._begin(name)
                getattr(self, f"phase_{name}")()
                if self.failed:
                    break
        except Cancelled:
            self.cancelled = True
            if self._current:
                self._record(self._current["name"], "cancelled", self._current["started"], key="phase.cancelled")
        self._write_phases()
        if self.cancelled:
            return 2
        return 1 if self.failed else 0

    def _locale(self):
        from recon_ai.i18n import DEFAULT_LOCALE, require_locale

        return require_locale(self._job().get("lang") or DEFAULT_LOCALE)

    def _text(self, key, args=None):
        from recon_ai.i18n import t

        return t(key, self._locale(), **(args or {}))

    def _render(self, detail="", key=None, args=None):
        if key:
            detail = self._text(key, args)
        payload = json.dumps(args, ensure_ascii=False, separators=(",", ":")) if args else ""
        return detail, key or "", payload

    def _phase_line(self, row):
        duration = row.get("duration", row.get("duration_s", 0))
        line = f"{row['name']}\t{row['status']}\t{duration}\t{row.get('detail') or ''}"
        key = row.get("detail_key") or ""
        args = row.get("detail_args") or ""
        if key or args:
            return f"{line}\t{key}\t{args}"
        return line

    def _begin(self, name):
        self._check_cancel()
        started = time.monotonic()
        self._current = {"name": name, "started": started}
        detail, detail_key, detail_args = self._render(key="phase.running")
        self._persist(name, "running", 0, detail, detail_key, detail_args)
        print(f"[+] {name}: {detail}", flush=True)
        return started

    def _record(self, name, status, started, detail="", key=None, args=None):
        if status == "fail":
            self.failed = True
        detail, detail_key, detail_args = self._render(detail, key, args)
        row = {
            "name": name,
            "status": status,
            "duration": int(time.monotonic() - started),
            "detail": detail,
            "detail_key": detail_key,
            "detail_args": detail_args,
        }
        self.phases = [item for item in self.phases if item["name"] != name]
        self.phases.append(row)
        self._current = None
        self._persist(name, status, row["duration"], detail, detail_key, detail_args)
        self._write_phases()
        print(f"[+] {name}: {detail}", flush=True)

    def _persist(self, name, status, duration, detail, detail_key="", detail_args=""):
        self._write_live(name, status, duration, detail, detail_key, detail_args)
        if self.connection is None or self.run_id is None:
            return
        from recon_ai import db

        db.upsert_phase(
            self.connection,
            self.run_id,
            name,
            status,
            duration,
            detail,
            str(self.logs),
            detail_key,
            detail_args,
        )

    def _write_live(self, name, status, duration, detail, detail_key="", detail_args=""):
        by_name = {row["name"]: row for row in self.phases}
        by_name[name] = {
            "name": name,
            "status": status,
            "duration": duration,
            "detail": detail,
            "detail_key": detail_key,
            "detail_args": detail_args,
        }
        ordered = [by_name[item] for item in PHASES if item in by_name]
        _write(self.output / "phases.tsv", [self._phase_line(row) for row in ordered])

    def _write_phases(self):
        _write(self.output / "phases.tsv", [self._phase_line(row) for row in self.phases])

    def phase_subdomains(self):
        started = self._current["started"] if self._current else time.monotonic()
        folder = self.output / "subdomains"
        folder.mkdir(parents=True, exist_ok=True)
        if is_literal_host(self.domain):
            unique = [self.domain]
            _write(folder / "all_subs.txt", unique)
            _write(folder / "provenance.tsv", [])
            self.counts["subs"] = 1
            self._record("subdomains", "ok", started, key="phase.subs_literal")
            return
        sources = [name for name in SUBDOMAIN_SOURCES if self._enabled(name)]
        if not sources:
            _write(folder / "all_subs.txt", [])
            _write(folder / "provenance.tsv", [])
            self._record("subdomains", "skip", started, key="phase.subs_skip")
            return
        failed = 0
        if self._enabled("subfinder"):
            sub_out = folder / "subfinder.txt"
            code = self._call(
                ["subfinder", "-d", self.domain, "-silent"],
                sub_out,
                self.logs / "subfinder.err",
            )
            if code != 0 or not sub_out.read_text(encoding="utf-8").strip():
                self._call(
                    ["subfinder", "-d", self.domain, "-silent", "-all"],
                    sub_out,
                    self.logs / "subfinder.err",
                )
        if self._enabled("amass"):
            amass_dir = self.output / "amass"
            amass_dir.mkdir(parents=True, exist_ok=True)
            timeout = str(self._param("amass", "timeout_minutes", self.settings.get("amass_timeout", 5)))
            code = self._call(
                [
                    "amass", "enum", "-passive", "-nocolor", "-timeout", timeout,
                    "-tr", "1.1.1.1,8.8.8.8", "-d", self.domain, "-dir", str(amass_dir),
                ],
                folder / "amass.raw",
                self.logs / "amass.err",
            )
            if code != 0:
                failed += 1
        if self._enabled("assetfinder"):
            code = self._call(
                ["timeout", "180", "assetfinder", "--subs-only", self.domain],
                folder / "assetfinder.txt",
                self.logs / "assetfinder.err",
            )
            if code != 0:
                failed += 1
        crt_names = []
        if self._enabled("crtsh"):
            code = self._call(
                [
                    "curl", "-fsS", "--max-time", "120", "-A", "Mozilla/5.0",
                    f"https://crt.sh/?q=%25.{self.domain}&output=json",
                ],
                folder / "crtsh.json",
                self.logs / "crtsh.err",
            )
            if code != 0:
                failed += 1
            else:
                try:
                    payload = json.loads((folder / "crtsh.json").read_text(encoding="utf-8") or "[]")
                    chunks = []
                    for item in payload:
                        chunks.append(str(item.get("name_value") or "").replace("*.", ""))
                    crt_names = self._names("\n".join(chunks))
                except json.JSONDecodeError:
                    failed += 1
            _write(folder / "crtsh.txt", crt_names)
        merged = []
        attributed = []
        for source, filename in (
            ("subfinder", "subfinder.txt"),
            ("amass", "amass.raw"),
            ("assetfinder", "assetfinder.txt"),
        ):
            file_path = folder / filename
            if not file_path.is_file():
                continue
            names = self._names(file_path.read_text(encoding="utf-8", errors="replace"))
            merged.extend(names)
            attributed.extend(f"{name}\t{source}" for name in names)
        merged.extend(crt_names)
        attributed.extend(f"{name}\tcrtsh" for name in crt_names)
        unique = sorted(set(merged))
        _write(folder / "all_subs.txt", unique)
        _write(folder / "provenance.tsv", sorted(set(attributed)))
        self.counts["subs"] = len(unique)
        if not unique:
            self._record("subdomains", "fail", started, key="phase.subs_fail")
            return
        if failed:
            self._record(
                "subdomains",
                "warn",
                started,
                key="phase.subs_warn",
                args={"n": len(unique), "failed": failed},
            )
        else:
            self._record("subdomains", "ok", started, key="phase.subs_ok", args={"n": len(unique)})

    def phase_dns(self):
        started = self._current["started"] if self._current else time.monotonic()
        folder = self.output / "dns"
        folder.mkdir(parents=True, exist_ok=True)
        if is_literal_host(self.domain):
            _write(folder / "resolved_hosts.txt", [probe_address(self.domain)])
            _write(folder / "cnames.tsv", [])
            self.counts["hosts"] = 1
            self._record("dns", "ok", started, key="phase.dns_literal")
            return
        if not self._enabled("dnsx"):
            _write(folder / "resolved_hosts.txt", [])
            _write(folder / "cnames.tsv", [])
            self._record("dns", "skip", started, key="phase.dns_skip")
            return
        subs = self.output / "subdomains" / "all_subs.txt"
        resolved = folder / "resolved.txt"
        code = self._call(
            ["dnsx", "-l", str(subs), "-silent", "-a", "-resp", "-threads", self._threads("dnsx")],
            resolved,
            self.logs / "dnsx.err",
        )
        if code != 0:
            self._record("dns", "fail", started, key="phase.dns_fail")
            return
        rows = parse_dns(resolved.read_text(encoding="utf-8", errors="replace"))
        probe = folder / "wildcard_probe.txt"
        probe_list = folder / "wildcard_name.txt"
        _write(probe_list, [f"wildcard-probe.{self.domain}"])
        self._call(
            ["dnsx", "-l", str(probe_list), "-silent", "-a", "-resp", "-threads", self._threads("dnsx")],
            probe,
            self.logs / "wildcard.err",
        )
        wildcard = {ip for _, ip in parse_dns(probe.read_text(encoding="utf-8", errors="replace") if probe.is_file() else "")}
        hosts = self._keep_hosts(hosts_without_wildcard(rows, wildcard))
        _write(folder / "resolved_hosts.txt", hosts)
        cname_out = folder / "cname.txt"
        code = self._call(
            ["dnsx", "-l", str(subs), "-silent", "-cname", "-resp", "-threads", self._threads("dnsx")],
            cname_out,
            self.logs / "dnsx_cname.err",
        )
        if code != 0:
            self._record("dns", "fail", started, key="phase.dns_cname_fail")
            return
        cnames = parse_cname(cname_out.read_text(encoding="utf-8", errors="replace") if cname_out.is_file() else "")
        _write(folder / "cnames.tsv", [f"{host}\t{target}" for host, target in cnames])
        self.counts["hosts"] = len(hosts)
        note = self._text(
            "phase.dns_note_wild" if wildcard else "phase.dns_note_none",
            {"n": len(wildcard)} if wildcard else None,
        )
        self._record(
            "dns",
            "ok",
            started,
            key="phase.dns_ok",
            args={"hosts": len(hosts), "note": note, "cnames": len(cnames)},
        )

    def phase_http(self):
        started = self._current["started"] if self._current else time.monotonic()
        folder = self.output / "live"
        folder.mkdir(parents=True, exist_ok=True)
        if not self._enabled("httpx"):
            _write(folder / "live_hosts.txt", [])
            _write(folder / "unauthorized.txt", [])
            _write(folder / "forbidden.txt", [])
            write_fingerprints(self.output, "")
            self._record("http", "skip", started, key="phase.http_skip")
            return
        hosts = self.output / "dns" / "resolved_hosts.txt"
        body = folder / "httpx.json"
        if not hosts.is_file() or not hosts.read_text(encoding="utf-8").strip():
            _write(folder / "live_hosts.txt", [])
            _write(folder / "unauthorized.txt", [])
            _write(folder / "forbidden.txt", [])
            write_fingerprints(self.output, "")
            self._record("http", "warn", started, key="phase.http_warn")
            return
        code = self._call(
            [
                "httpx", "-l", str(hosts), "-silent", "-threads", self._threads("httpx"),
                "-status-code", "-title", "-tech-detect", "-follow-redirects",
                "-timeout", str(self._param("httpx", "timeout", 10)),
                "-retries", str(self._param("httpx", "retries", 2)),
                "-json",
            ],
            body,
            self.logs / "httpx.err",
        )
        if code != 0:
            self._record("http", "fail", started, key="phase.http_fail")
            return
        raw = body.read_text(encoding="utf-8", errors="replace")
        write_fingerprints(self.output, raw)
        live, unauthorized, forbidden = classify_http(raw)
        live = self._keep_urls(live)
        unauthorized = self._keep_urls(unauthorized)
        forbidden = self._keep_urls(forbidden)
        _write(folder / "live_hosts.txt", live)
        _write(folder / "unauthorized.txt", unauthorized)
        _write(folder / "forbidden.txt", forbidden)
        self.counts["live"] = len(live)
        self.counts["unauthorized"] = len(unauthorized)
        self.counts["forbidden"] = len(forbidden)
        self._record(
            "http",
            "ok",
            started,
            key="phase.http_ok",
            args={"live": len(live), "unauth": len(unauthorized), "forbidden": len(forbidden)},
        )

    def phase_urls(self):
        started = self._current["started"] if self._current else time.monotonic()
        folder = self.output / "urls"
        folder.mkdir(parents=True, exist_ok=True)
        sources = [name for name in URL_SOURCES if self._enabled(name)]
        if not sources:
            _write(folder / "all_urls.txt", [])
            _write(folder / "archive_live.txt", [])
            write_buckets(self.output, [])
            self._record("urls", "skip", started, key="phase.urls_skip")
            return
        live = self.output / "live" / "live_hosts.txt"
        unique_by = {}
        if self._enabled("katana") and live.is_file() and live.read_text(encoding="utf-8").strip():
            katana = folder / "katana.txt"
            self._call(
                [
                    "katana", "-list", str(live),
                    "-d", str(self._param("katana", "depth", 3)),
                    "-silent", "-jc",
                    "-timeout", str(self._param("katana", "timeout", 10)),
                ],
                katana,
                self.logs / "katana.err",
            )
            if katana.is_file():
                unique_by["katana"] = self._urls(katana.read_text(encoding="utf-8", errors="replace").splitlines())
        for binary, flag in (("gau", "--subs"), ("waybackurls", None)):
            if not self._enabled(binary):
                continue
            unique_by[binary] = self._collect_archive(binary, flag, folder)
        unique = sorted(set(url for urls in unique_by.values() for url in urls))
        _write(folder / "all_urls.txt", unique)
        for source, urls in unique_by.items():
            append_provenance(self.output, urls, source)
        write_buckets(self.output, unique)
        error = self._probe_archive(folder, unique_by)
        if error:
            self._record("urls", "fail", started, key=error)
            return
        self.counts["urls"] = len(unique)
        self._record("urls", "ok", started, key="phase.urls_ok", args={"n": len(unique)})

    def _archive_hosts(self):
        hosts = [self.domain]
        seen = {self.domain.casefold()}
        path = self.output / "dns" / "resolved_hosts.txt"
        if path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                host = line.strip()
                if not host or host.casefold() in seen:
                    continue
                hosts.append(host)
                seen.add(host.casefold())
                if len(hosts) >= ARCHIVE_HOST_CAP:
                    break
        return hosts

    def _collect_archive(self, binary, flag, folder):
        parts = []
        for host in self._archive_hosts():
            args = [binary, host]
            if flag:
                args.extend([flag, "--threads", self._threads(binary)])
            part = folder / f"{binary}.part.txt"
            self._call(args, part, self.logs / f"{binary}.err")
            if part.is_file():
                parts.append(part.read_text(encoding="utf-8", errors="replace"))
        out = folder / f"{binary}.txt"
        out.write_text("".join(parts), encoding="utf-8")
        return self._urls(out.read_text(encoding="utf-8", errors="replace").splitlines())

    def _probe_archive(self, folder, unique_by):
        katana_urls = set(unique_by.get("katana", []))
        candidates = []
        seen = set()
        for source in ("gau", "waybackurls"):
            for url in unique_by.get(source, []):
                if url in katana_urls or url in seen:
                    continue
                seen.add(url)
                candidates.append(url)
                if len(candidates) >= ARCHIVE_PROBE_CAP:
                    break
            if len(candidates) >= ARCHIVE_PROBE_CAP:
                break
        _write(folder / "archive_probe.txt", candidates)
        if not candidates or not self._enabled("httpx"):
            _write(folder / "archive_live.txt", [])
            return None
        jsonl = folder / "archive_httpx.json"
        code = self._call(
            [
                "httpx", "-l", str(folder / "archive_probe.txt"), "-silent", "-status-code", "-json",
                "-threads", self._threads("httpx"),
                "-timeout", str(self._param("httpx", "timeout", 10)),
                "-retries", str(self._param("httpx", "retries", 2)),
            ],
            jsonl,
            self.logs / "archive_httpx.err",
        )
        if code != 0:
            return "phase.urls_archive_fail"
        live, _unauth, _forbidden = classify_http(
            jsonl.read_text(encoding="utf-8", errors="replace") if jsonl.is_file() else ""
        )
        allowed = set(candidates)
        _write(folder / "archive_live.txt", [url for url in self._keep_urls(live) if url in allowed])
        return None

    def phase_dorks(self):
        from recon_ai.dorks import DorkError, ENGINES, generate_queries, pages_for, parse_hits, shodan_key
        from recon_ai.derive import read_fingerprints

        started = self._current["started"] if self._current else time.monotonic()
        folder = self.output / "dorks"
        folder.mkdir(parents=True, exist_ok=True)
        if not self._enabled("dorks"):
            _write(folder / "queries.txt", [])
            _write(folder / "hits.txt", [])
            _write(folder / "live.txt", [])
            _write(folder / "gated.txt", [])
            self._record("dorks", "skip", started, key="phase.dorks_skip")
            return
        engine = str(self._param("dorks", "engine", "bing")).strip().casefold()
        if engine not in ENGINES:
            self._record("dorks", "fail", started, key="phase.dorks_engine", args={"engine": engine})
            return
        if engine == "shodan" and not shodan_key(self._job()):
            self._record("dorks", "fail", started, key="phase.dorks_shodan")
            return
        try:
            queries = generate_queries(
                self.domain,
                read_fingerprints(self.output),
                int(self._param("dorks", "max_queries", 24)),
            )
        except DorkError as exc:
            self._record("dorks", "fail", started, str(exc))
            return
        _write(folder / "queries.txt", queries)
        delay = int(self._param("dorks", "delay_s", 12))
        pages = str(pages_for(self._param("dorks", "max_results", 20)))
        proxy = str(self._param("dorks", "proxy", "-")).strip()
        if engine == "shodan":
            self.env["SHODAN_API_KEY"] = shodan_key(self._job())
        raw_parts = []
        for index, query in enumerate(queries):
            args = ["go-dork", "-q", query, "-e", engine, "-p", pages, "-s"]
            if proxy and proxy != "-":
                args.extend(["-x", proxy])
            part = folder / "raw_part.txt"
            code = self._call(args, part, self.logs / "go-dork.err")
            if code != 0:
                self._record("dorks", "fail", started, key="phase.dorks_godork")
                return
            if part.is_file():
                raw_parts.append(part.read_text(encoding="utf-8", errors="replace"))
            if delay and self.runner is None and index + 1 < len(queries):
                time.sleep(delay)
        raw = "\n".join(raw_parts)
        (folder / "raw.txt").write_text(raw, encoding="utf-8")
        hits = sorted(set(self._keep_urls(parse_hits(raw))))
        _write(folder / "hits.txt", hits)
        live_hits = []
        gated_hits = []
        if hits:
            jsonl = folder / "httpx.json"
            code = self._call(
                [
                    "httpx", "-l", str(folder / "hits.txt"), "-silent", "-status-code", "-json",
                    "-threads", self._threads("httpx"),
                    "-timeout", str(self._param("httpx", "timeout", 10)),
                    "-retries", str(self._param("httpx", "retries", 2)),
                ],
                jsonl,
                self.logs / "dorks_httpx.err",
            )
            if code != 0:
                self._record("dorks", "fail", started, key="phase.dorks_httpx")
                return
            live, unauth, forbidden = classify_http(
                jsonl.read_text(encoding="utf-8", errors="replace") if jsonl.is_file() else ""
            )
            live_hits = self._keep_urls(live)
            gated_hits = self._keep_urls(unauth) + self._keep_urls(forbidden)
        _write(folder / "live.txt", live_hits)
        _write(folder / "gated.txt", gated_hits)
        existing = []
        all_urls = self.output / "urls" / "all_urls.txt"
        if all_urls.is_file():
            existing = [line.strip() for line in all_urls.read_text(encoding="utf-8").splitlines() if line.strip()]
        merged = sorted(set(existing) | set(hits))
        _write(all_urls, merged)
        append_provenance(self.output, hits, "dorks")
        write_buckets(self.output, merged)
        self.counts["urls"] = len(merged)
        self._record(
            "dorks",
            "ok",
            started,
            key="phase.dorks_ok",
            args={"queries": len(queries), "hits": len(hits), "live": len(live_hits)},
        )

    def phase_js(self):
        started = self._current["started"] if self._current else time.monotonic()
        folder = self.output / "js"
        content = folder / "content"
        content.mkdir(parents=True, exist_ok=True)
        if not self._enabled("js_httpx") and not self._enabled("js_curl"):
            _write(folder / "js_urls.txt", [])
            _write(folder / "js_live.txt", [])
            _write(folder / "endpoints.txt", [])
            scan_js_secrets(self.output)
            self._record("js", "skip", started, key="phase.js_skip")
            return
        source = self.output / "urls" / "all_urls.txt"
        lines = source.read_text(encoding="utf-8", errors="replace").splitlines() if source.is_file() else []
        scripts = js_urls(lines)
        _write(folder / "js_urls.txt", scripts)
        self.counts["js"] = len(scripts)
        live = folder / "js_live.txt"
        if scripts and self._enabled("js_httpx"):
            list_file = folder / "js_urls_head.txt"
            _write(list_file, scripts[:200])
            self._call(
                [
                    "httpx", "-l", str(list_file), "-silent", "-mc", "200",
                    "-threads", self._threads("js_httpx", "httpx"),
                    "-timeout", str(self._param("js_httpx", "timeout", 8)),
                ],
                live,
                self.logs / "js_httpx.err",
            )
        else:
            if scripts and not self._enabled("js_httpx"):
                _write(live, scripts[:200])
            else:
                _write(live, [])
        failures = 0
        pairs = []
        if self._enabled("js_curl") and live.is_file():
            for url in [line.strip() for line in live.read_text(encoding="utf-8").splitlines() if line.strip()]:
                text = self._download_js(url, content / f"{abs(hash(url))}.js")
                if text is None:
                    failures += 1
                else:
                    pairs.append((url, text))
            pairs, map_failures = self._download_source_maps(pairs, content)
            failures += map_failures
            hop_error, missed = self._js_hop(pairs, scripts, content, folder)
            failures += missed
            if hop_error:
                self._finish_js(pairs, scripts, failures, started, hop_error, failed=True)
                return
        self._finish_js(pairs, scripts, failures, started)

    def _download_js(self, url, target):
        timeout = str(self._param("js_curl", "timeout", 15))
        code = self._call(
            ["curl", "-fsSL", "--http1.1", "--max-time", timeout, "-A", "Mozilla/5.0", url],
            target,
            self.logs / "js_curl.err",
        )
        if code != 0 or not target.is_file():
            return None
        return target.read_text(encoding="utf-8", errors="replace")

    def _download_source_maps(self, pairs, content):
        maps = []
        seen = set()
        for url, text in pairs:
            mapped = source_map_url(text, url, self.domain, self._in_scope(), self._out_scope())
            if not mapped or mapped in seen:
                continue
            seen.add(mapped)
            maps.append(mapped)
        failures = 0
        downloaded = list(pairs)
        for map_url in maps[:MAP_CAP]:
            text = self._download_js(map_url, content / f"{abs(hash(map_url))}.map")
            if text is None:
                failures += 1
            else:
                downloaded.append((map_url, text))
        return downloaded, failures

    def _js_hop(self, pairs, scripts, content, folder):
        if not self._enabled("js_httpx") or not self._enabled("js_curl"):
            return None, 0
        known = set(scripts)
        all_urls = self.output / "urls" / "all_urls.txt"
        if all_urls.is_file():
            known.update(line.strip() for line in all_urls.read_text(encoding="utf-8").splitlines() if line.strip())
        extra = []
        seen = set()
        for url, text in pairs:
            for ref in referenced_scripts(text, url, self.domain, self._in_scope(), self._out_scope()):
                if ref in known or ref in seen:
                    continue
                seen.add(ref)
                extra.append(ref)
                if len(extra) >= JS_HOP_CAP:
                    break
            if len(extra) >= JS_HOP_CAP:
                break
        if not extra:
            return None, 0
        list_file = folder / "js_hop.txt"
        live = folder / "js_hop_live.txt"
        _write(list_file, extra)
        code = self._call(
            [
                "httpx", "-l", str(list_file), "-silent", "-mc", "200",
                "-threads", self._threads("js_httpx", "httpx"),
                "-timeout", str(self._param("js_httpx", "timeout", 8)),
            ],
            live,
            self.logs / "js_hop_httpx.err",
        )
        if code != 0:
            return "phase.js_hop_fail", 0
        missed = 0
        for url in [line.strip() for line in live.read_text(encoding="utf-8").splitlines() if line.strip()]:
            text = self._download_js(url, content / f"{abs(hash(url))}.js")
            if text is None:
                missed += 1
            else:
                pairs.append((url, text))
        return None, missed

    def _finish_js(self, pairs, scripts, failures, started, detail=None, failed=False):
        found = sorted(set(item for _url, body in pairs for item in endpoints_in_js(body)))
        _write(self.output / "js" / "endpoints.txt", found)
        scan_js_secrets(self.output)
        self.counts["js_fail"] = failures
        self.counts["endpoints"] = len(found)
        if failed:
            self._record("js", "fail", started, key=detail)
            return
        status = "warn" if failures else "ok"
        self._record(
            "js",
            status,
            started,
            key="phase.js_ok",
            args={"scripts": len(scripts), "failures": failures, "endpoints": len(found)},
        )

    def phase_nuclei(self):
        started = self._current["started"] if self._current else time.monotonic()
        folder = self.output / "nuclei"
        folder.mkdir(parents=True, exist_ok=True)
        if not self._enabled("nuclei"):
            _write(folder / "results.jsonl", [])
            self._record("nuclei", "skip", started, key="phase.nuclei_off")
            return
        live = self.output / "live" / "live_hosts.txt"
        jsonl = folder / "results.jsonl"
        main = live.is_file() and bool(live.read_text(encoding="utf-8").strip())
        if main:
            code = self._call(self._nuclei_args(live), jsonl, self.logs / "nuclei.err")
            if code != 0:
                self._record("nuclei", "fail", started, key="phase.nuclei_fail")
                return
        else:
            _write(jsonl, [])
        takeover = self._takeover_hosts()
        scanned_path = self.output / "dns" / "takeover_scanned.txt"
        _write(scanned_path, [])
        takeover_out = folder / "takeover.jsonl"
        if takeover:
            list_path = folder / "takeover_hosts.txt"
            _write(list_path, takeover)
            code = self._call(self._takeover_args(list_path), takeover_out, self.logs / "nuclei_takeover.err")
            if code != 0:
                self._record("nuclei", "fail", started, key="phase.nuclei_takeover_fail")
                return
            _write(scanned_path, takeover)
        else:
            _write(takeover_out, [])
        if not main and not takeover:
            self._record("nuclei", "skip", started, key="phase.nuclei_empty")
            return
        text = jsonl.read_text(encoding="utf-8", errors="replace") if jsonl.is_file() else ""
        if takeover_out.is_file():
            text += takeover_out.read_text(encoding="utf-8", errors="replace")
        findings = nuclei_findings(text)
        self.counts["nuclei"] = len(findings)
        if takeover:
            self._record(
                "nuclei",
                "ok",
                started,
                key="phase.nuclei_ok_takeover",
                args={"n": len(findings), "hosts": len(takeover)},
            )
        else:
            self._record("nuclei", "ok", started, key="phase.nuclei_ok", args={"n": len(findings)})

    def _nuclei_args(self, list_path):
        templates = os.environ.get("NUCLEI_TEMPLATES_DIR", "/opt/nuclei-templates")
        return [
            "nuclei", "-l", str(list_path),
            "-t", f"{templates}/http/", "-t", f"{templates}/dns/", "-t", f"{templates}/ssl/",
            "-severity", str(self._param("nuclei", "severity", "critical,high,medium")),
            "-tags", str(self._param("nuclei", "tags", "cve,exposure,misconfiguration,takeover,tech,config,default-login")),
            "-c", self._threads("nuclei"),
            "-rate-limit", str(self._param("nuclei", "rate_limit", 150)),
            "-timeout", str(self._param("nuclei", "timeout", 10)),
            "-retries", str(self._param("nuclei", "retries", 1)),
            "-silent", "-duc", "-or", "-jsonl",
        ]

    def _takeover_args(self, list_path):
        templates = os.environ.get("NUCLEI_TEMPLATES_DIR", "/opt/nuclei-templates")
        return [
            "nuclei", "-l", str(list_path),
            "-t", f"{templates}/dns/",
            "-tags", "takeover",
            "-c", self._threads("nuclei"),
            "-rate-limit", str(self._param("nuclei", "rate_limit", 150)),
            "-timeout", str(self._param("nuclei", "timeout", 10)),
            "-retries", str(self._param("nuclei", "retries", 1)),
            "-silent", "-duc", "-or", "-jsonl",
        ]

    def _takeover_hosts(self):
        path = self.output / "dns" / "cnames.tsv"
        if not path.is_file():
            return []
        live_hosts = set()
        live = self.output / "live" / "live_hosts.txt"
        if live.is_file():
            from recon_ai.derive import origin_host

            for line in live.read_text(encoding="utf-8").splitlines():
                host = origin_host(line.strip()) if "://" in line else line.strip().casefold()
                if host:
                    live_hosts.add(host.casefold().strip("."))
        chosen = []
        seen = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            if "\t" not in line:
                continue
            host, target = line.split("\t", 1)
            host = host.casefold().strip(".")
            target = target.casefold().strip(".")
            if not host or not target or host_in_domain(target, self.domain):
                continue
            if host in live_hosts or host in seen:
                continue
            seen.add(host)
            chosen.append(host)
            if len(chosen) >= TAKEOVER_CAP:
                break
        return chosen

    def phase_report(self):
        started = self._current["started"] if self._current else time.monotonic()
        counts = self.counts
        if self.cancelled:
            state = self._text("phase.state_cancelled")
        elif self.failed:
            state = self._text("phase.state_failed")
        else:
            state = self._text("phase.state_ok")
        text = "\n".join(
            [
                "==============================================",
                f"  RECON REPORT - {self.domain}",
                "==============================================",
                self._text("phase.resumo_subs", {"n": counts["subs"]}),
                self._text("phase.resumo_hosts", {"n": counts["hosts"]}),
                self._text("phase.resumo_live", {"n": counts["live"]}),
                self._text("phase.resumo_401", {"n": counts["unauthorized"]}),
                self._text("phase.resumo_403", {"n": counts["forbidden"]}),
                self._text("phase.resumo_urls", {"n": counts["urls"]}),
                self._text("phase.resumo_js", {"n": counts["js"]}),
                self._text("phase.resumo_endpoints", {"n": counts["endpoints"]}),
                self._text("phase.resumo_nuclei", {"n": counts["nuclei"]}),
                self._text("phase.resumo_status", {"state": state}),
                "==============================================",
                "",
            ]
        )
        (self.output / "resumo.txt").write_text(text, encoding="utf-8")
        self._record("report", "ok", started, key="phase.report_ok")
