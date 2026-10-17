#!/bin/bash
set -euo pipefail

source /usr/local/lib/recon/common.sh
# shellcheck disable=SC1091
source /opt/recon/versions.lock

die() {
    local code="$1"
    shift
    echo "[!]" "$*" >&2
    exit "$code"
}

check_cli() {
    local bin="$1"
    local expect="$2"
    local out

    out=$("$bin" -version 2>&1 || true)
    if ! printf '%s\n' "$out" | strip_ansi | grep -F -q "$expect"; then
        out=$("$bin" --version 2>&1 || true)
    fi
    if ! printf '%s\n' "$out" | strip_ansi | grep -F -q "$expect"; then
        printf '%s\n' "$out" | strip_ansi >&2
        die 4 "Versão divergente em ${bin}: esperada ${expect}."
    fi
}

verify_image() {
    sha256sum -c /opt/recon/bin-sha256.txt >/dev/null
    check_cli subfinder "$SUBFINDER_VERSION"
    check_cli amass "$AMASS_VERSION"
    check_cli dnsx "$DNSX_VERSION"
    check_cli httpx "$HTTPX_VERSION"
    check_cli katana "$KATANA_VERSION"
    check_cli nuclei "$NUCLEI_VERSION"
    check_cli gau "$GAU_VERSION"

    local templates_commit
    templates_commit=$(cat /opt/nuclei-templates/.commit)
    if [ "$templates_commit" != "$NUCLEI_TEMPLATES_COMMIT" ]; then
        die 4 "Templates do Nuclei divergentes: ${templates_commit}."
    fi

    command -v assetfinder >/dev/null 2>&1 || die 4 "assetfinder ausente."
    command -v waybackurls >/dev/null 2>&1 || die 4 "waybackurls ausente."
    command -v go-dork >/dev/null 2>&1 || die 4 "go-dork ausente."
    command -v jq >/dev/null 2>&1 || die 4 "jq ausente."
    command -v md5sum >/dev/null 2>&1 || die 4 "md5sum ausente."
}

link_config() {
    local name="$1"
    if [ -d "/config/${name}" ]; then
        ln -sfn "/config/${name}" "${HOME}/.config/${name}"
    fi
}

ensure_pd_config() {
    local name="$1"
    local dir="${HOME}/.config/${name}"
    if [ -L "$dir" ]; then
        return 0
    fi
    mkdir -p "$dir"
    if [ ! -e "${dir}/config.yaml" ]; then
        printf '%s\n' '{}' > "${dir}/config.yaml"
    fi
}

prepare_home() {
    export HOME=/tmp/recon-home
    export XDG_CONFIG_HOME="${HOME}/.config"
    mkdir -p "${HOME}/.config"
    link_config subfinder
    link_config amass
    if [ -f /config/gau.toml ]; then
        ln -sfn /config/gau.toml "${HOME}/.gau.toml"
    fi
    ensure_pd_config subfinder
    ensure_pd_config dnsx
    ensure_pd_config httpx
    ensure_pd_config katana
    ensure_pd_config nuclei
    export NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates
    export SCOPE_FILE=/scope/scopes.txt
}

prepare_home
verify_image

if [ "${1:-}" = "--check" ]; then
    echo "Imagem íntegra. Versões do lockfile de 2026-10-03 conferidas."
    exit 0
fi

if [ -z "${1:-}" ]; then
    die 2 "Uso: docker compose run --rm recon <dominio> [threads]"
fi

DOMAIN="$1"
THREADS="${2:-50}"

if ! is_valid_domain "$DOMAIN"; then
    die 2 "Domínio inválido. Use um hostname como example.com, sem barra, espaço ou '..'."
fi
if ! is_valid_threads "$THREADS"; then
    die 2 "Threads inválidas. Use um inteiro de 1 a 200."
fi

scope_rc=0
domain_in_scope "$DOMAIN" "$SCOPE_FILE" || scope_rc=$?
if [ "$scope_rc" -eq 2 ]; then
    die 3 "Arquivo de escopo ausente em /scope/scopes.txt. Copie scope/scopes.txt.example e liste o domínio autorizado."
fi
if [ "$scope_rc" -ne 0 ]; then
    die 3 "Domínio fora do escopo: ${DOMAIN}. Inclua essa linha em scope/scopes.txt."
fi

exec /usr/local/bin/recon-claude-grok.sh "$DOMAIN" "$THREADS"
