# Histórico e evolução

## Fontes

| Documento | Caminho | Papel |
| --- | --- | --- |
| Estratégia de automação | `Estrategia_Automação_Recon_e_IA.md.pdf` | Contexto de bug bounty, ferramentas de mercado, IA local em 16 GB, Qwen 2.5 7B |
| Plano estratégico AS IS → TO BE | `Plano Estratégico de Evolução_ Recon AI Automation (AS IS para TO BE).pdf` | Evoluir o Bash, CLI first, Docker, SQLite, IA agnóstica, roadmap em 4 fases |
| Documentação do script | `Documentacao_Recon_Script_Full.docx` | AS IS: sete fases, `@latest` na instalação, sem escopo obrigatório |
| Guia de documentação v2 | fornecido fora do repo | WP0–WP5, critérios de corte, árvore documental |
| Código atual | `recon_ai/`, `compose.yaml`, `versions.lock` | Comportamento vigente |

O git do projeto existe (`batistasamuel/pipeline-recon-ai`). ADRs iniciais foram reconstruídos a partir dos PDFs e dos testes; a partir da UI e dos joins `corr/` há commits Conventional Commits em `dev`.

## AS IS (script)

`recon-claude-grok.sh` encadeava subfinder, amass, assetfinder, crt.sh, dnsx, httpx, katana, gau, waybackurls, nuclei. Instalação documentada com `go install …@latest`. Ambiente de referência: Kali arm64 em VM. Sem allowlist, sem SQLite, sem IA, com pasta `screenshots` e grep de “secrets” em JS.

## Intenção TO BE (plano estratégico)

Evolução gradual, não greenfield. CLI Typer como caminho primário. Docker multi-stage. Persistência relacional para recon diferencial. Camada de IA agnóstica (Gemini/Groq **ou** Ollama). Web dashboard opcional (FastAPI + Streamlit/React). Mais tarde: Naabu/Nmap, Gowitness, FFuF, webhooks.

O guia v2 apertou essa visão: 1 comando Compose, 0 `@latest`, falha crítica ⇒ exit ≠ 0, escopo obrigatório, artefatos estruturados, IA pós-processamento **opcional**, dados do alvo não saem da máquina sem opt-in, sem Celery/Redis/UI no núcleo.

## O que o código fez (fases de implementação)

A implementação no repo está organizada por testes `test_phase2` … `test_phase7`, não pelas “Fases 1–4 / semanas 1–8” do PDF estratégico.

| Bloco no código | Entrega | Relação com o plano |
| --- | --- | --- |
| Imagem + lockfile + `--check` | Debian 13, binários pinados, amd64/arm64 no Dockerfile | WP1 / Fase 1 do PDF |
| CLI Typer + escopo + SQLite | `recon run/resume/stop` | WP2; CLI first do PDF |
| Pipeline Python | adapters por ferramenta, fixtures | WP3; Bash deixa de ser default |
| IA Ollama + schema | `qwen2.5:7b`, manifest; Gemini só com `--cloud` | WP4; Groq ausente |
| Diff | comparado ao último `ok` | WP5; webhook recusado |
| UI stdlib | perfil `ui`, também **inicia** scan | PDF Fase 4 / guia: UI adiada — **alterado** |
| Alvo IPv4:porta + loopback | DVWA no host | não estava no plano; evidência: `scope.py`, `test_phase2` |
| Fase `ai` no scan completo | `analyze_run` depois do ingest | guia: IA opcional e perfil `ai` — **alterado** |
| HAR opcional | `--har` / upload; fase `har` | evidência: `har.py`, `test_har.py`, PR #6 |
| Derive + correlate | fingerprints, provenance, buckets, `corr/…` | evidência: `derive.py`, `correlate.py`, PR #7 |
| Dorks executados | `go-dork` 1.0.3, Bing, hits → httpx | evidência: `dorks.py`, `versions.lock`, PR #7 |
| Cloud opt-in | `--cloud`, Gemini + retry 429/503, sem fallback Ollama | ADR-012; `gemini.py`, `test_pseudonym.py` |
| Catálogo + rascunhos | `reportable`/`note`/`coverage`, `drafts/`, `--verify` | ADR-018; `catalog.py`, `drafts.py` |
| HAR em streaming | `iter_har_entries`; nuclei HAR em lotes de 10 | `har.py`, `test_har.py` |

## Divergências que importam

1. **IA no scan padrão.** O guia e o lockfile descrevem Ollama só com perfil `ai` e análise como comando separado. `compose.yaml` atual sobe `ollama` sem profile e `recon`/`ui` fazem `depends_on`. `run_job` chama `analyze_run` após ingest. Motivo no código: o operador pediu scan completo com contribuição da IA visível. Evidência: `recon_ai/control.py`, `recon_ai/runner.py`, `compose.yaml`.
2. **UI inicia scan.** O guia adiava UI; a fase 6 era só leitura. A fase 7 adicionou POST `/api/runs`. Evidência: `recon_ai/ui.py`, `tests/test_phase7.py`.
3. **Webhook, coletores extras, Celery.** Planejados no PDF; recusados ou ausentes. Cloud saiu de “recusado” para **opt-in** (ADR-012): Groq e NVIDIA ativos; Gemini e DeepSeek desligados por enquanto. Evidência: `cli.py` (`--cloud`, `--webhook`), `cloud.py`, ausência de Naabu/Nmap no `TOOL_CATALOG`.
4. **Bash não foi apagado.** `RECON_ENGINE=bash` ainda chama o script. Evidência: `runner.py`, `README.md`.
5. **CI da segunda arquitetura.** Existem workflows em `.github/workflows/` (CI, Promotion Guard, deploy placeholder, release). O job `CI` ainda é TODO de lint/test — não prova amd64 e arm64. Status: workflows existem; a suíte local é `unittest` no host.

## Linha WP0–WP5 (guia) × código

| Fase | Objetivo original | Status atual |
| --- | --- | --- |
| WP0 | Honestidade do script | **Implementado** no Python (exit ≠ 0, Nuclei conta JSONL). Bash legado ainda pode imprimir sucesso — ver limitações. |
| WP1 | Docker + isolamento + duas arch | **Parcial**. Imagem pinada; segunda arch sem CI. |
| WP2 | CLI + escopo + SQLite + resume | **Implementado**, com spec, stop e cancel. |
| WP3 | Adapters + fixtures + Bash fora do default | **Implementado** (13 ferramentas no catálogo, incluindo `dorks`; não “sete adapters” como módulos isolados). |
| WP4 | IA local + schema + perfil separado | **Alterado**: schema e Ollama existem; perfil `ai` foi removido; scan completo chama a IA; Gemini só com `--cloud`. |
| WP5 | Diff + webhook opcional | **Parcial**: diff sim; webhook não. |
