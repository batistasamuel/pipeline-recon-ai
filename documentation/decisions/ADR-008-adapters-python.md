# ADR-008 — Adapters Python em vez do Bash como default

Status: Accepted  
Evidência: `RECON_ENGINE`, `pipeline.py`, `job.TOOL_CATALOG` (13 ferramentas, inclui `dorks`)

## Decisão

O default chama binários pelo Pipeline. O Bash fica na imagem para `RECON_ENGINE=bash`.

## Nota

O guia falava em “sete adapters”. O catálogo tem treze nomes (inclui crtsh, waybackurls, js_httpx, js_curl, `dorks`). Não são classes Adapter; são ramos do Pipeline.
