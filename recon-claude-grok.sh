#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${BLUE}[*] $*${NC}" >&2; }
ok()   { echo -e "${GREEN}[+] $*${NC}" >&2; }
warn() { echo -e "${YELLOW}[!] $*${NC}" >&2; }
step() { echo -e "\n${YELLOW}[+] $*${NC}" >&2; }

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -n "${RECON_COMMON:-}" ]; then
    # shellcheck disable=SC1090
    source "$RECON_COMMON"
elif [ -f /usr/local/lib/recon/common.sh ]; then
    # shellcheck disable=SC1091
    source /usr/local/lib/recon/common.sh
else
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/scripts/common.sh"
fi

FAILED=0
PHASE_FILE=""

usage() {
    echo -e "${RED}[!] Uso: recon-claude-grok.sh <dominio> [threads]${NC}" >&2
    echo "    Pelo container: docker compose run --rm recon <dominio> [threads]" >&2
    exit 2
}

phase_begin() {
    PHASE_T0=$(date +%s)
}

phase_record() {
    local name="$1" status="$2" detail="$3"
    local now dur=0
    now=$(date +%s)
    if [ -n "${PHASE_T0:-}" ]; then
        dur=$((now - PHASE_T0))
    fi
    printf '%s\t%s\t%s\t%s\n' "$name" "$status" "$dur" "$detail" >> "$PHASE_FILE"
    if [ "$status" = "fail" ]; then
        FAILED=1
        warn "${name}: ${detail}"
    elif [ "$status" = "warn" ]; then
        warn "${name}: ${detail}"
    fi
}

threads_for() {
    local key="$1" val
    eval "val=\${RECON_THREADS_${key}:-}"
    if [ -n "$val" ]; then
        printf '%s' "$val"
    else
        printf '%s' "$THREADS"
    fi
}

REACHED=0
should_run() {
    local phase="$1"
    if [ -z "$FROM" ]; then
        return 0
    fi
    if [ "$REACHED" -eq 1 ]; then
        return 0
    fi
    if [ "$FROM" = "$phase" ]; then
        REACHED=1
        return 0
    fi
    return 1
}

trim_phases_from() {
    local from="$1" line name
    if [ ! -f "$PHASE_FILE" ]; then
        : > "$PHASE_FILE"
        return 0
    fi
    : > "${PHASE_FILE}.new"
    while IFS= read -r line || [ -n "$line" ]; do
        name=$(printf '%s' "$line" | cut -f1)
        if [ "$name" = "$from" ]; then
            break
        fi
        printf '%s\n' "$line" >> "${PHASE_FILE}.new"
    done < "$PHASE_FILE"
    mv "${PHASE_FILE}.new" "$PHASE_FILE"
}

count_lines() {
    local file="$1"
    if [ -s "$file" ]; then
        wc -l < "$file" | tr -d ' '
    else
        echo 0
    fi
}

FROM=""
OUTPUT_SET=""
while [ $# -gt 0 ]; do
    case "$1" in
        --from)
            FROM="${2:-}"
            shift 2
            ;;
        --output)
            OUTPUT_SET="${2:-}"
            shift 2
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "[!] Opção desconhecida: $1" >&2
            usage
            ;;
        *)
            break
            ;;
    esac
done

if [ -z "${1:-}" ]; then
    usage
fi

DOMAIN="$1"
THREADS="${2:-50}"
SCOPE_FILE="${SCOPE_FILE:-/scope/scopes.txt}"
NUCLEI_TEMPLATES_DIR="${NUCLEI_TEMPLATES_DIR:-/opt/nuclei-templates}"
DATE=$(date +%Y%m%d_%H%M%S)
case "$FROM" in
    ""|subdomains|dns|http|urls|js|nuclei|report) ;;
    *)
        echo "[!] Fase inválida em --from: ${FROM}" >&2
        exit 2
        ;;
esac
if [ -n "$FROM" ] && [ -z "$OUTPUT_SET" ]; then
    echo "[!] --from exige --output." >&2
    exit 2
fi

if ! is_valid_domain "$DOMAIN"; then
    echo "[!] Domínio inválido. Use um hostname como example.com, sem barra, espaço ou '..'." >&2
    exit 2
fi
if ! is_valid_threads "$THREADS"; then
    echo "[!] Threads inválidas. Use um inteiro de 1 a 200." >&2
    exit 2
fi

scope_rc=0
domain_in_scope "$DOMAIN" "$SCOPE_FILE" || scope_rc=$?
if [ "$scope_rc" -eq 2 ]; then
    echo "[!] Arquivo de escopo ausente: ${SCOPE_FILE}" >&2
    exit 3
fi
if [ "$scope_rc" -ne 0 ]; then
    echo "[!] Domínio fora do escopo: ${DOMAIN}" >&2
    exit 3
fi

if [ -n "$OUTPUT_SET" ]; then
    OUTPUT_DIR="$OUTPUT_SET"
else
    OUTPUT_DIR="recon_${DOMAIN}_${DATE}"
fi
LOG_DIR="${OUTPUT_DIR}/logs"
mkdir -p "$OUTPUT_DIR"/{subdomains,dns,live,urls,js,nuclei,amass,logs}
PHASE_FILE="${OUTPUT_DIR}/phases.tsv"
if [ -n "$FROM" ]; then
    trim_phases_from "$FROM"
else
    : > "$PHASE_FILE"
fi

check_deps() {
    local required="subfinder amass assetfinder dnsx httpx katana gau waybackurls nuclei jq curl md5sum"
    local cmd missing=""
    for cmd in $required; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing="${missing} ${cmd}"
        fi
    done
    if [ -n "$missing" ]; then
        phase_record deps fail "binários ausentes:${missing}"
        exit 1
    fi
}

check_deps

log "Iniciando recon em: ${DOMAIN}"
log "Threads: ${THREADS}"
log "Resultados em: ${OUTPUT_DIR}"

# --------------------------------------------
# 1. Subdomínios
# --------------------------------------------
if should_run subdomains; then
phase_begin
step "1/7 - Enumerando subdomínios"
source_fail=0

log "Rodando subfinder..."
if ! subfinder -d "$DOMAIN" -silent -o "${OUTPUT_DIR}/subdomains/subfinder.txt" 2>"${LOG_DIR}/subfinder.err"; then
    warn "subfinder falhou. Ver logs/subfinder.err"
    source_fail=$((source_fail + 1))
    : > "${OUTPUT_DIR}/subdomains/subfinder.txt"
fi
if [ ! -s "${OUTPUT_DIR}/subdomains/subfinder.txt" ]; then
    log "Subfinder vazio, tentando com -all..."
    if ! subfinder -d "$DOMAIN" -silent -all -o "${OUTPUT_DIR}/subdomains/subfinder.txt" 2>>"${LOG_DIR}/subfinder.err"; then
        warn "subfinder -all falhou."
        source_fail=$((source_fail + 1))
        : > "${OUTPUT_DIR}/subdomains/subfinder.txt"
    fi
fi

AMASS_TIMEOUT="${RECON_AMASS_TIMEOUT:-5}"
log "Rodando amass (passive, limite ${AMASS_TIMEOUT} min). Progresso em logs/amass.err"
if ! amass enum -passive -nocolor -timeout "$AMASS_TIMEOUT" \
    -tr 1.1.1.1,8.8.8.8 \
    -d "$DOMAIN" -dir "${OUTPUT_DIR}/amass" \
    >"${OUTPUT_DIR}/subdomains/amass.raw" 2>"${LOG_DIR}/amass.err"; then
    warn "amass falhou. Ver logs/amass.err"
    source_fail=$((source_fail + 1))
    : > "${OUTPUT_DIR}/subdomains/amass.raw"
fi
# Conserva o apex e qualquer rótulo abaixo dele. Descarta o que só contém a string.
tr '[:upper:]' '[:lower:]' < "${OUTPUT_DIR}/subdomains/amass.raw" | strip_ansi | \
    keep_names "$DOMAIN" | sort -u > "${OUTPUT_DIR}/subdomains/amass.txt" || true

log "Rodando assetfinder (limite 3 min)..."
if command -v timeout >/dev/null 2>&1; then
    timeout 180 assetfinder --subs-only "$DOMAIN" > "${OUTPUT_DIR}/subdomains/assetfinder.txt" 2>"${LOG_DIR}/assetfinder.err" || {
        warn "assetfinder falhou. Ver logs/assetfinder.err"
        source_fail=$((source_fail + 1))
        : > "${OUTPUT_DIR}/subdomains/assetfinder.txt"
    }
else
    assetfinder --subs-only "$DOMAIN" > "${OUTPUT_DIR}/subdomains/assetfinder.txt" 2>"${LOG_DIR}/assetfinder.err" || {
        warn "assetfinder falhou. Ver logs/assetfinder.err"
        source_fail=$((source_fail + 1))
        : > "${OUTPUT_DIR}/subdomains/assetfinder.txt"
    }
fi

log "Consultando crt.sh..."
CRT_TMP=$(mktemp)
if curl -sS --max-time 120 -A "Mozilla/5.0" "https://crt.sh/?q=%25.${DOMAIN}&output=json" -o "$CRT_TMP" 2>"${LOG_DIR}/crtsh.err" \
    && [ -s "$CRT_TMP" ] && head -c 1 "$CRT_TMP" | grep -q '\['; then
    jq -r '.[].name_value // empty' "$CRT_TMP" 2>/dev/null | \
        tr '[:upper:]' '[:lower:]' | \
        sed 's/^\*\.//' | \
        keep_names "$DOMAIN" | \
        sort -u > "${OUTPUT_DIR}/subdomains/crtsh.txt" || true
else
    warn "crt.sh não devolveu JSON. A fonte foi pulada."
    : > "${OUTPUT_DIR}/subdomains/crtsh.txt"
    source_fail=$((source_fail + 1))
fi
rm -f "$CRT_TMP"

cat "${OUTPUT_DIR}/subdomains/subfinder.txt" \
    "${OUTPUT_DIR}/subdomains/amass.txt" \
    "${OUTPUT_DIR}/subdomains/assetfinder.txt" \
    "${OUTPUT_DIR}/subdomains/crtsh.txt" 2>/dev/null | \
    tr '[:upper:]' '[:lower:]' | \
    sed 's/^\*\.//' | \
    sed 's/\.$//' | \
    keep_names "$DOMAIN" | \
    sort -u > "${OUTPUT_DIR}/subdomains/all_subs.txt" || true

TOTAL_SUBS=$(count_lines "${OUTPUT_DIR}/subdomains/all_subs.txt")
if [ "$TOTAL_SUBS" -eq 0 ]; then
    phase_record subdomains fail "nenhum subdomínio. Fontes com falha: ${source_fail}"
    {
        echo "RECON ${DOMAIN}"
        echo "Subdomínios: 0"
        echo "Status: falha"
    } > "${OUTPUT_DIR}/resumo.txt"
    exit 1
fi
if [ "$source_fail" -gt 0 ]; then
    phase_record subdomains warn "${TOTAL_SUBS} nomes; ${source_fail} fonte(s) com falha"
else
    phase_record subdomains ok "${TOTAL_SUBS} nomes"
fi
ok "Subdomínios únicos: ${TOTAL_SUBS}"
else
    if [ ! -s "${OUTPUT_DIR}/subdomains/all_subs.txt" ]; then
        phase_begin
        phase_record subdomains fail "retomada sem lista de subdomínios"
        exit 1
    fi
    TOTAL_SUBS=$(count_lines "${OUTPUT_DIR}/subdomains/all_subs.txt")
fi

# --------------------------------------------
# 2. DNS e wildcard
# --------------------------------------------
if should_run dns; then
phase_begin
step "2/7 - Resolvendo DNS e filtrando wildcards"
if ! dnsx -l "${OUTPUT_DIR}/subdomains/all_subs.txt" \
    -silent -a -resp -threads "$(threads_for DNSX)" \
    -o "${OUTPUT_DIR}/dns/resolved.txt" 2>"${LOG_DIR}/dnsx.err"; then
    phase_record dns fail "dnsx terminou com erro. Ver logs/dnsx.err"
    exit 1
fi

strip_ansi < "${OUTPUT_DIR}/dns/resolved.txt" > "${OUTPUT_DIR}/dns/resolved.clean"
WILDCARD_TOKEN=$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
WILDCARD_NAME="${WILDCARD_TOKEN}.${DOMAIN}"
wildcard_note="sem wildcard"
if printf '%s\n' "$WILDCARD_NAME" | dnsx -silent -a -resp -threads "$(threads_for DNSX)" \
    > "${OUTPUT_DIR}/dns/wildcard_probe.txt" 2>"${LOG_DIR}/wildcard.err"; then
    strip_ansi < "${OUTPUT_DIR}/dns/wildcard_probe.txt" | \
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u > "${OUTPUT_DIR}/dns/wildcard_ips.txt" || true
    if [ -s "${OUTPUT_DIR}/dns/wildcard_ips.txt" ]; then
        awk '
            NR == FNR { wild[$0] = 1; next }
            {
                host = $1
                ip = ""
                if (match($0, /([0-9]+\.){3}[0-9]+/)) {
                    ip = substr($0, RSTART, RLENGTH)
                }
                if (ip != "") {
                    ips[host] = ips[host] " " ip
                    seen[host] = 1
                }
            }
            END {
                for (host in seen) {
                    n = split(ips[host], arr, " ")
                    keep = 0
                    for (i = 1; i <= n; i++) {
                        if (arr[i] != "" && !(arr[i] in wild)) keep = 1
                    }
                    if (keep) print host
                }
            }
        ' "${OUTPUT_DIR}/dns/wildcard_ips.txt" "${OUTPUT_DIR}/dns/resolved.clean" | sort -u \
            > "${OUTPUT_DIR}/dns/resolved_hosts.txt"
        raw_hosts=$(cut -d ' ' -f1 "${OUTPUT_DIR}/dns/resolved.clean" | sort -u | wc -l | tr -d ' ')
        kept_hosts=$(count_lines "${OUTPUT_DIR}/dns/resolved_hosts.txt")
        dropped=$((raw_hosts - kept_hosts))
        wildcard_note="${dropped} hosts só com IP de wildcard removidos"
    else
        cut -d ' ' -f1 "${OUTPUT_DIR}/dns/resolved.clean" | sort -u > "${OUTPUT_DIR}/dns/resolved_hosts.txt"
        : > "${OUTPUT_DIR}/dns/wildcard_ips.txt"
    fi
else
    cut -d ' ' -f1 "${OUTPUT_DIR}/dns/resolved.clean" | sort -u > "${OUTPUT_DIR}/dns/resolved_hosts.txt"
    wildcard_note="sonda de wildcard falhou; lista resolvida não foi filtrada"
fi

RESOLVED_COUNT=$(count_lines "${OUTPUT_DIR}/dns/resolved_hosts.txt")
if printf '%s\n' "$wildcard_note" | grep -q 'sonda de wildcard falhou'; then
    phase_record dns warn "${RESOLVED_COUNT} hosts. ${wildcard_note}"
else
    phase_record dns ok "${RESOLVED_COUNT} hosts. ${wildcard_note}"
fi
ok "Hosts resolvidos: ${RESOLVED_COUNT}. ${wildcard_note}"
else
    if [ ! -s "${OUTPUT_DIR}/dns/resolved_hosts.txt" ] && [ ! -f "${OUTPUT_DIR}/dns/resolved_hosts.txt" ]; then
        phase_begin
        phase_record dns fail "retomada sem hosts resolvidos"
        exit 1
    fi
    RESOLVED_COUNT=$(count_lines "${OUTPUT_DIR}/dns/resolved_hosts.txt")
fi

# --------------------------------------------
# 3. Hosts vivos
# --------------------------------------------
if should_run http; then
phase_begin
step "3/7 - Filtrando hosts vivos"
if [ "$RESOLVED_COUNT" -eq 0 ]; then
    : > "${OUTPUT_DIR}/live/httpx.json"
    : > "${OUTPUT_DIR}/live/live_hosts.txt"
    : > "${OUTPUT_DIR}/live/httpx_full.txt"
    phase_record http warn "nenhum host resolvido; httpx não foi chamado"
    LIVE_COUNT=0
else
    if ! httpx -l "${OUTPUT_DIR}/dns/resolved_hosts.txt" \
        -silent \
        -threads "$(threads_for HTTPX)" \
        -status-code \
        -title \
        -tech-detect \
        -follow-redirects \
        -timeout 10 \
        -retries 2 \
        -json \
        -o "${OUTPUT_DIR}/live/httpx.json" 2>"${LOG_DIR}/httpx.err"; then
        phase_record http fail "httpx terminou com erro. Ver logs/httpx.err"
        exit 1
    fi
    if ! jq -r 'select((.status_code // .["status-code"] // 0) >= 200 and (.status_code // .["status-code"] // 0) < 400) | .url' \
        "${OUTPUT_DIR}/live/httpx.json" 2>"${LOG_DIR}/httpx_jq.err" | sort -u > "${OUTPUT_DIR}/live/live_hosts.txt"; then
        phase_record http fail "httpx.json não pôde ser lido"
        exit 1
    fi
    jq -r '"\(.url) [\(.status_code // .["status-code"] // "")] \(.title // "") \(.tech // [])"' \
        "${OUTPUT_DIR}/live/httpx.json" > "${OUTPUT_DIR}/live/httpx_full.txt" || true
    LIVE_COUNT=$(count_lines "${OUTPUT_DIR}/live/live_hosts.txt")
    phase_record http ok "${LIVE_COUNT} urls com status 2xx ou 3xx"
fi
ok "Hosts vivos: ${LIVE_COUNT}"
else
    LIVE_COUNT=$(count_lines "${OUTPUT_DIR}/live/live_hosts.txt")
fi

# --------------------------------------------
# 4. URLs
# --------------------------------------------
if should_run urls; then
phase_begin
step "4/7 - Coletando URLs"
url_warn=0
if [ "$LIVE_COUNT" -gt 0 ]; then
    log "Rodando katana..."
    if ! katana -list "${OUTPUT_DIR}/live/live_hosts.txt" \
        -d 3 -silent -jc -timeout 10 \
        -o "${OUTPUT_DIR}/urls/katana.txt" \
        >"${LOG_DIR}/katana.out" 2>"${LOG_DIR}/katana.err"; then
        warn "katana falhou. Ver logs/katana.err"
        url_warn=$((url_warn + 1))
        : > "${OUTPUT_DIR}/urls/katana.txt"
    fi
else
    : > "${OUTPUT_DIR}/urls/katana.txt"
fi

log "Rodando gau..."
if ! gau "$DOMAIN" --subs --threads "$(threads_for GAU)" >"${OUTPUT_DIR}/urls/gau.raw" 2>"${LOG_DIR}/gau.err"; then
    warn "gau falhou. Ver logs/gau.err"
    url_warn=$((url_warn + 1))
    : > "${OUTPUT_DIR}/urls/gau.raw"
fi
keep_urls "$DOMAIN" < "${OUTPUT_DIR}/urls/gau.raw" | sort -u > "${OUTPUT_DIR}/urls/gau.txt" || true

log "Rodando waybackurls..."
if ! waybackurls "$DOMAIN" >"${OUTPUT_DIR}/urls/wayback.raw" 2>"${LOG_DIR}/wayback.err"; then
    warn "waybackurls falhou. Ver logs/wayback.err"
    url_warn=$((url_warn + 1))
    : > "${OUTPUT_DIR}/urls/wayback.raw"
fi
keep_urls "$DOMAIN" < "${OUTPUT_DIR}/urls/wayback.raw" | sort -u > "${OUTPUT_DIR}/urls/wayback.txt" || true

cat "${OUTPUT_DIR}/urls/katana.txt" "${OUTPUT_DIR}/urls/gau.txt" "${OUTPUT_DIR}/urls/wayback.txt" 2>/dev/null | \
    keep_urls "$DOMAIN" | \
    sort -u > "${OUTPUT_DIR}/urls/all_urls.txt" || true
URL_COUNT=$(count_lines "${OUTPUT_DIR}/urls/all_urls.txt")
if [ "$url_warn" -gt 0 ]; then
    phase_record urls warn "${URL_COUNT} urls; ${url_warn} fonte(s) com falha"
else
    phase_record urls ok "${URL_COUNT} urls"
fi
ok "URLs coletadas: ${URL_COUNT}"
else
    URL_COUNT=$(count_lines "${OUTPUT_DIR}/urls/all_urls.txt")
fi

# --------------------------------------------
# 5. JavaScript
# --------------------------------------------
if should_run js; then
phase_begin
step "5/7 - Extraindo arquivos JS"
grep -iE '\.js($|\?|#)' "${OUTPUT_DIR}/urls/all_urls.txt" 2>/dev/null | \
    sort -u > "${OUTPUT_DIR}/js/js_urls.txt" || true
JS_COUNT=$(count_lines "${OUTPUT_DIR}/js/js_urls.txt")
ENDPOINT_COUNT=0
SECRET_COUNT=0

if [ "$JS_COUNT" -gt 0 ]; then
    log "Baixando JS vivos (máx. 200)..."
    if ! head -n 200 "${OUTPUT_DIR}/js/js_urls.txt" | \
        httpx -silent -mc 200 -threads "$(threads_for HTTPX)" -timeout 8 \
        -o "${OUTPUT_DIR}/js/js_live.txt" \
        >"${LOG_DIR}/js_httpx.out" 2>"${LOG_DIR}/js_httpx.err"; then
        phase_record js warn "httpx dos JS falhou. Ver logs/js_httpx.err"
        : > "${OUTPUT_DIR}/js/js_live.txt"
    fi
    mkdir -p "${OUTPUT_DIR}/js/content"
    js_fail=0
    : > "${LOG_DIR}/js_curl.err"
    if [ -s "${OUTPUT_DIR}/js/js_live.txt" ]; then
        while IFS= read -r jsurl; do
            [ -z "$jsurl" ] && continue
            fname=$(printf '%s' "$jsurl" | md5sum | cut -d ' ' -f1)
            if ! curl -fsSL --http1.1 --max-time 15 -A "Mozilla/5.0" \
                "$jsurl" -o "${OUTPUT_DIR}/js/content/${fname}.js" 2>>"${LOG_DIR}/js_curl.err"; then
                js_fail=$((js_fail + 1))
                printf '%s\n' "$jsurl" >> "${LOG_DIR}/js_curl.err"
            fi
        done < "${OUTPUT_DIR}/js/js_live.txt"
    fi
    grep -rhoE '(/api/[a-zA-Z0-9_/-]+|/v[0-9]+/[a-zA-Z0-9_/-]+)' \
        "${OUTPUT_DIR}/js/content/" 2>/dev/null | sort -u > "${OUTPUT_DIR}/js/endpoints.txt" || true
    grep -rhoEi '(api[_-]?key|access[_-]?token|secret[_-]?key|authorization|bearer[[:space:]]+[a-zA-Z0-9._-]+|AKIA[0-9A-Z]{16})' \
        "${OUTPUT_DIR}/js/content/" 2>/dev/null | sort -u > "${OUTPUT_DIR}/js/possible_secrets.txt" || true
    ENDPOINT_COUNT=$(count_lines "${OUTPUT_DIR}/js/endpoints.txt")
    SECRET_COUNT=$(count_lines "${OUTPUT_DIR}/js/possible_secrets.txt")
    if [ "$js_fail" -gt 0 ]; then
        phase_record js warn "${JS_COUNT} urls, ${js_fail} downloads falhos, ${ENDPOINT_COUNT} endpoints. Ver logs/js_curl.err"
    else
        phase_record js ok "${JS_COUNT} urls, ${ENDPOINT_COUNT} endpoints, ${SECRET_COUNT} padrões"
    fi
else
    : > "${OUTPUT_DIR}/js/endpoints.txt"
    : > "${OUTPUT_DIR}/js/possible_secrets.txt"
    phase_record js ok "nenhum JS na lista de URLs"
fi
ok "Arquivos JS: ${JS_COUNT}"
else
    JS_COUNT=$(count_lines "${OUTPUT_DIR}/js/js_urls.txt")
    ENDPOINT_COUNT=$(count_lines "${OUTPUT_DIR}/js/endpoints.txt")
    SECRET_COUNT=$(count_lines "${OUTPUT_DIR}/js/possible_secrets.txt")
fi

# --------------------------------------------
# 6. Nuclei
# --------------------------------------------
if should_run nuclei; then
phase_begin
step "6/7 - Rodando Nuclei"
NUCLEI_COUNT=0
if [ "$LIVE_COUNT" -eq 0 ]; then
    : > "${OUTPUT_DIR}/nuclei/results.txt"
    : > "${OUTPUT_DIR}/nuclei/results.jsonl"
    phase_record nuclei skip "nenhum host vivo"
elif [ ! -d "$NUCLEI_TEMPLATES_DIR" ]; then
    phase_record nuclei fail "diretório de templates ausente: ${NUCLEI_TEMPLATES_DIR}"
    exit 1
else
    if ! nuclei -l "${OUTPUT_DIR}/live/live_hosts.txt" \
        -t "${NUCLEI_TEMPLATES_DIR}/http/" \
        -t "${NUCLEI_TEMPLATES_DIR}/dns/" \
        -t "${NUCLEI_TEMPLATES_DIR}/ssl/" \
        -severity critical,high,medium \
        -tags cve,exposure,misconfiguration,takeover,tech,config,default-login \
        -c "$(threads_for NUCLEI)" \
        -rate-limit "${RECON_RATE_NUCLEI:-150}" \
        -timeout 10 \
        -retries 1 \
        -silent \
        -duc \
        -or \
        -o "${OUTPUT_DIR}/nuclei/results.txt" \
        -jle "${OUTPUT_DIR}/nuclei/results.jsonl" \
        2>"${LOG_DIR}/nuclei.err"; then
        phase_record nuclei fail "nuclei terminou com erro. Ver logs/nuclei.err"
        exit 1
    fi
    [ -f "${OUTPUT_DIR}/nuclei/results.jsonl" ] || : > "${OUTPUT_DIR}/nuclei/results.jsonl"
    NUCLEI_COUNT=$(count_lines "${OUTPUT_DIR}/nuclei/results.jsonl")
    phase_record nuclei ok "${NUCLEI_COUNT} findings no JSONL"
fi
ok "Findings do Nuclei: ${NUCLEI_COUNT}"
else
    NUCLEI_COUNT=$(count_lines "${OUTPUT_DIR}/nuclei/results.jsonl")
fi

# --------------------------------------------
# 7. Resumo
# --------------------------------------------
if should_run report; then
phase_begin
step "7/7 - Gerando resumo"
{
    echo "=============================================="
    echo "  RECON REPORT - ${DOMAIN}"
    echo "  Data: $(date)"
    echo "=============================================="
    echo ""
    echo "Subdomínios encontrados : ${TOTAL_SUBS}"
    echo "Hosts resolvidos        : ${RESOLVED_COUNT}"
    echo "Hosts vivos             : ${LIVE_COUNT}"
    echo "URLs coletadas          : ${URL_COUNT}"
    echo "Arquivos JS             : ${JS_COUNT}"
    echo "Endpoints (JS)          : ${ENDPOINT_COUNT}"
    echo "Possíveis secrets (JS)  : ${SECRET_COUNT}"
    echo "Findings Nuclei         : ${NUCLEI_COUNT}"
    echo ""
    echo "Fases:"
    sed 's/^/  /' "$PHASE_FILE"
    echo ""
    echo "Diretório de saída      : ${OUTPUT_DIR}"
    if [ "$FAILED" -ne 0 ]; then
        echo "Status                  : falha"
    else
        echo "Status                  : ok"
    fi
    echo "=============================================="
} | tee "${OUTPUT_DIR}/resumo.txt"

echo ""
if [ "$NUCLEI_COUNT" -gt 0 ]; then
    echo -e "${CYAN}=== Top findings do Nuclei (critical/high) ===${NC}"
    grep -iE '\[critical\]|\[high\]' "${OUTPUT_DIR}/nuclei/results.txt" 2>/dev/null | head -n 15 || true
    echo ""
fi

if [ "$FAILED" -ne 0 ]; then
    echo -e "${RED}[!] Recon terminou com falha em fase crítica. Veja phases.tsv.${NC}" >&2
    exit 1
fi

ok "Recon finalizado."
echo -e "Resultados completos em: ${GREEN}${OUTPUT_DIR}${NC}"
echo -e "Resumo salvo em: ${GREEN}${OUTPUT_DIR}/resumo.txt${NC}"
phase_record report ok "resumo.txt"
fi
