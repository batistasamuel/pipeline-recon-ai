# ADR-004 — Ferramentas pinadas e `--check`

Status: Accepted  
Evidência: `versions.lock`, `scripts/verify-image.sh`, `scripts/fetch-tools.sh`

## Decisão

Subfinder 2.16.0, Dnsx 1.3.1, Httpx 1.12.0, Katana 1.7.0, Nuclei 3.11.1, Gau 2.2.4, Amass **4.2.0** (não 5.1.1: o 5 só enumera via engine 127.0.0.1:4000). assetfinder commit `4e95d870`. waybackurls 0.1.0 via `go install`. templates Nuclei commit `893122ff`.

`--check` compara versão anunciada e checksums. Exit 4 se divergir.

## Motivo

Amass 5.1.1 quebrava a fase de nomes (comentário no lockfile).
