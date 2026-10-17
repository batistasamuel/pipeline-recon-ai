#!/bin/bash
# Confere checksums e versões pinadas. O chamador precisa ter deixado HOME gravável.
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

sha256sum -c /opt/recon/bin-sha256.txt >/dev/null
check_cli subfinder "$SUBFINDER_VERSION"
check_cli amass "$AMASS_VERSION"
check_cli dnsx "$DNSX_VERSION"
check_cli httpx "$HTTPX_VERSION"
check_cli katana "$KATANA_VERSION"
check_cli nuclei "$NUCLEI_VERSION"
check_cli gau "$GAU_VERSION"

templates_commit=$(cat /opt/nuclei-templates/.commit)
if [ "$templates_commit" != "$NUCLEI_TEMPLATES_COMMIT" ]; then
    die 4 "Templates do Nuclei divergentes: ${templates_commit}."
fi

command -v assetfinder >/dev/null 2>&1 || die 4 "assetfinder ausente."
command -v waybackurls >/dev/null 2>&1 || die 4 "waybackurls ausente."
command -v go-dork >/dev/null 2>&1 || die 4 "go-dork ausente."
command -v jq >/dev/null 2>&1 || die 4 "jq ausente."
command -v md5sum >/dev/null 2>&1 || die 4 "md5sum ausente."
echo "Imagem íntegra. Versões do lockfile de 2026-10-03 conferidas."
