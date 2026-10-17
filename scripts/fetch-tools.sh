#!/bin/bash
# Baixa os binários de release, confere o checksum publicado e a versão.
set -euo pipefail

arch="${TARGETARCH:?TARGETARCH ausente}"
case "$arch" in
    amd64|arm64) ;;
    *)
        echo "Arquitetura não suportada: ${arch}" >&2
        exit 1
        ;;
esac

# shellcheck disable=SC1091
source /tmp/versions.lock
mkdir -p /out/bin

download_release() {
    local repo="$1"
    local version="$2"
    local asset="$3"
    local sums="$4"
    local binname="$5"
    local work url sums_url found

    work=$(mktemp -d)
    url="https://github.com/${repo}/releases/download/v${version}/${asset}"
    sums_url="https://github.com/${repo}/releases/download/v${version}/${sums}"
    curl -fsSL "$url" -o "${work}/${asset}"
    curl -fsSL "$sums_url" -o "${work}/checksums.txt"
    sums=$(awk -v asset="$asset" '$NF == asset { print }' "${work}/checksums.txt")
    if [ -z "$sums" ]; then
        echo "Checksum ausente para ${asset}" >&2
        exit 1
    fi
    printf '%s\n' "$sums" | (cd "$work" && sha256sum -c -)

    mkdir -p "${work}/unpack"
    case "$asset" in
        *.zip) unzip -q "${work}/${asset}" -d "${work}/unpack" ;;
        *.tar.gz) tar -xzf "${work}/${asset}" -C "${work}/unpack" ;;
        *)
            echo "Arquivo não suportado: ${asset}" >&2
            exit 1
            ;;
    esac

    found=$(find "${work}/unpack" -type f -name "$binname" | head -n 1)
    if [ -z "$found" ]; then
        echo "Binário ${binname} não encontrado em ${asset}" >&2
        exit 1
    fi
    install -m 0755 "$found" "/out/bin/${binname}"
    rm -rf "$work"
}

version_matches() {
    local bin="$1"
    local expect="$2"
    local out
    out=$("$bin" -version 2>&1 || true)
    if ! printf '%s\n' "$out" | sed -E 's/\x1b\[[0-9;]*[mK]//g' | grep -F -q "$expect"; then
        out=$("$bin" --version 2>&1 || true)
    fi
    if ! printf '%s\n' "$out" | sed -E 's/\x1b\[[0-9;]*[mK]//g' | grep -F -q "$expect"; then
        echo "Versão inesperada em ${bin}. Esperada: ${expect}" >&2
        printf '%s\n' "$out" >&2
        exit 1
    fi
}

download_release projectdiscovery/subfinder "$SUBFINDER_VERSION" \
    "subfinder_${SUBFINDER_VERSION}_linux_${arch}.zip" \
    "subfinder_${SUBFINDER_VERSION}_checksums.txt" subfinder
download_release projectdiscovery/dnsx "$DNSX_VERSION" \
    "dnsx_${DNSX_VERSION}_linux_${arch}.zip" \
    "dnsx_${DNSX_VERSION}_checksums.txt" dnsx
download_release projectdiscovery/httpx "$HTTPX_VERSION" \
    "httpx_${HTTPX_VERSION}_linux_${arch}.zip" \
    "httpx_${HTTPX_VERSION}_checksums.txt" httpx
download_release projectdiscovery/katana "$KATANA_VERSION" \
    "katana_${KATANA_VERSION}_linux_${arch}.zip" \
    "katana-${KATANA_VERSION}-checksums.txt" katana
download_release projectdiscovery/nuclei "$NUCLEI_VERSION" \
    "nuclei_${NUCLEI_VERSION}_linux_${arch}.zip" \
    "nuclei_${NUCLEI_VERSION}_checksums.txt" nuclei
download_release lc/gau "$GAU_VERSION" \
    "gau_${GAU_VERSION}_linux_${arch}.tar.gz" \
    "gau_${GAU_VERSION}_checksums.txt" gau
download_release owasp-amass/amass "$AMASS_VERSION" \
    "amass_Linux_${arch}.zip" \
    "amass_checksums.txt" amass

download_plain() {
    local repo="$1"
    local version="$2"
    local asset="$3"
    local sums="$4"
    local binname="$5"
    local work url sums_url found

    work=$(mktemp -d)
    url="https://github.com/${repo}/releases/download/v${version}/${asset}"
    sums_url="https://github.com/${repo}/releases/download/v${version}/${sums}"
    curl -fsSL "$url" -o "${work}/${asset}"
    curl -fsSL "$sums_url" -o "${work}/checksums.txt"
    found=$(awk -v asset="$asset" '$NF == asset { print }' "${work}/checksums.txt")
    if [ -z "$found" ]; then
        echo "Checksum ausente para ${asset}" >&2
        exit 1
    fi
    printf '%s\n' "$found" | (cd "$work" && sha256sum -c -)
    install -m 0755 "${work}/${asset}" "/out/bin/${binname}"
    rm -rf "$work"
}

download_plain dwisiswant0/go-dork "$GODORK_VERSION" \
    "go-dork_${GODORK_VERSION}_linux_${arch}" \
    "go-dork_${GODORK_VERSION}_checksums.txt" go-dork

version_matches /out/bin/subfinder "$SUBFINDER_VERSION"
version_matches /out/bin/dnsx "$DNSX_VERSION"
version_matches /out/bin/httpx "$HTTPX_VERSION"
version_matches /out/bin/katana "$KATANA_VERSION"
version_matches /out/bin/nuclei "$NUCLEI_VERSION"
version_matches /out/bin/gau "$GAU_VERSION"
version_matches /out/bin/amass "$AMASS_VERSION"

echo "Releases ${arch} conferidos."
