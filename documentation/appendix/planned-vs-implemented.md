# Planejado versus implementado

| Item | Fonte | Planejado | Actual | Diferença | Motivo / evidência | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Docker como contrato | Estratégico / guia | `compose run` único | `compose run recon` + profile `ui` | UI extra | ADR-001, ADR-014 | Implementado |
| Debian/base pinada | WP1 | digest | debian:13-slim@sha256:a99cfc51… | — | `versions.lock` | Implementado |
| amd64 + arm64 | WP1 | mesma imagem | Dockerfile `TARGETARCH` | job CI ainda é placeholder | README; `.github/workflows/ci.yml` | Parcial |
| Ferramentas pinadas | guia 0 @latest | lockfile | lockfile + `--check` | Amass 4.2.0 não 5.x | ADR-004 | Implementado |
| Exit code | WP0 | fail ⇒ ≠0 | 0–4 documentados | URL source fail não falha a fase | `pipeline.py` urls | Parcial |
| Escopo obrigatório | guia | sem arquivo impede | exit 3 + in_scope | — | `refuse_scope` | Implementado |
| JSONL estruturado | estratégico | adapters JSONL | Nuclei JSONL; resto txt + SQLite | não é tudo JSONL | `ingest.py` | Parcial |
| CLI Typer | estratégico | Typer (+ Rich) | Typer só | sem Rich | `requirements.txt` | Implementado |
| SQLite | WP2 | run/phase/asset/url/finding | + spec, control, delta, ai_result | mais tabelas | `db.py` | Implementado |
| Adapters | WP3 | sete módulos | 13 ferramentas no Pipeline (inclui `dorks`) | sem package adapters | `job.py` | Alterado |
| Aposentadoria Bash | WP3 | fora do default | default Python; `RECON_ENGINE=bash` | legado presente | `runner.py` | Implementado |
| Ollama / profile ai | WP4 / lockfile | perfil `ai`, comando separado | sem profile; IA no scan | ADR-010 | `compose.yaml` | Alterado |
| Schema IA | WP4 | JSON válido | validate_* | — | `ai.py` | Implementado |
| Cloud opt-in | estratégico | Gemini/Groq | `--cloud`: Groq e NVIDIA ativos; Gemini/DeepSeek desligados; prompt mascarado | ADR-012 | `cloud.py` | Implementado |
| Hardware 16 GB | estratégia | 7B local, IA separada | 7B + serviços separados; scan puxa ollama | cache RAM=0 | Compose | Parcial |
| Diff | WP5 | delta | `diff.py` | — | `test_phase5` | Implementado |
| Webhook | WP5 / PDF | Telegram/Discord | recusado | ADR-016 | `cli.py` | Não implementado |
| Coletores extras | PDF Fase 3 | nmap/ffuf/gowitness | ausentes | ADR-015 | catálogo | Não implementado |
| Celery/Redis | PDF | orquestração async | um processo | ADR-013 | Compose | Não implementado |
| UI | PDF / guia adiada | dashboard opcional, depois adiada | HTTP stdlib inicia scan, HAR, Consultar a IA, Candidatos, Rascunhos, DELETE do run | ADR-014 | `ui.py` / `ui_page.html` | Alterado |
| HAR | pedido de operação | captura de browser no mesmo run | fase `har` opcional, ≤ 32 MB, entries em streaming, nuclei em lotes | `har.py` | Implementado |
| Catálogo / rascunhos | operação bounty | caderno ≠ envio | `reportable`/`note`/`coverage`, `drafts/`, `--verify` | ADR-018 | Implementado |
| Correlate | plano BB joins | joins A∧B sem exploit | `corr/…` + checklist | ADR-017 | Implementado |
| Dorks executados | plano BB joins | motor pinado + httpx no URL | `go-dork` 1.0.3, Bing, `--disable` | ADR-017 | Implementado |
