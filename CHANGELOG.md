# Changelog

Todas as mudanças relevantes deste projeto são documentadas neste arquivo.

O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/),
e este projeto adota [Versionamento Semântico](https://semver.org/lang/pt-BR/).

Tags `vMAJOR.MINOR.PATCH` são criadas **somente em `main`**.

## [Unreleased]

### Added

- README: print da UI (`documentation/images/ui.png`) no início do arquivo.
- `--cloud`: Groq e NVIDIA ativos; Gemini e DeepSeek desligados por enquanto (cota/saldo). `--cloud-mode sequential` (padrão) ou `parallel`. `--ai-delay-ms` (padrão 2000, de 10 ms a 10 min) espera entre uma resposta e o próximo prompt, em Ollama e na nuvem.
- Ingest: `finding` ganha `kind`, `class`, `cluster_key` e `evidence` (CWE, curl, fingerprint; sem segredo em claro). Catálogo `reportable` | `note` | `coverage`.
- IA classifica só clusters reportáveis; `clusters.json` agrupa note/coverage. Rascunhos de bounty em `drafts/*.md` (8 seções) e `recon export --draft`.
- UI: bloco Rascunhos, GET/POST `/api/runs/{id}/drafts/{key}` (`draft` | `ready` | `rejected`).
- `--verify`: checagens passivas opt-in (CNAME, HEAD sem sessão, fingerprint no disco); default `skip`.
- ADR-018: reportável versus nota; caderno do run e rascunho são artefatos distintos.
- Pipeline de recon em container, CLI, SQLite, IA local e UI.
- Fluxo Git (`dev` / `hml` / `main`), hooks locais, workflows de CI, Promotion Guard, deploy e release.
- README: setup desde o clone até feature, correção, homologação (HML) e PRD.
- UI: Consultar a IA (prompt livre), bloqueio com scan `running` e orçamento de entrada ~12k.
- IA: recorte em torno de paths literais e divisão se o JSON de rotas truncar; `num_predict` alinhado à reserva de 2500.
- Scan: HAR opcional (`--har` / upload na UI). Sem arquivo a fase `har` é `skip`. Com arquivo, URLs/JS no escopo e findings graves entram no mesmo run antes de uma única IA.
- Pipeline: fingerprints HTTP, provenance de URL, buckets de parâmetros e fase `correlate` (`corr/…`) antes da IA. Dorks pinados (`go-dork` 1.0.3, Bing por padrão); hits in-scope passam por httpx no URL concreto.
- Coleta: CNAME (`dnsx -cname`), probe de URLs de arquivo (gau/wayback), salto JS extra, source maps no mesmo host, passagem nuclei takeover (cap 30) e nuclei em URLs HAR sem sessão (cap 50).
- Correlação: `corr/js-not-crawled`, `corr/crtsh-only`, `corr/dangling-cname`, candidatos graphql/debug/upload, dorks 401/403 no mesmo gated.
- i18n: catálogos `en-US`, `pt-BR` (padrão) e `es-ES` na UI, CLI (`--lang` / `RECON_LANG`), checklist, fases, export e prompts da IA. Runs antigos não são regravados.
- `--cloud`: Google AI Studio (`gemini-flash-latest`) com prompt pseudonimizado; chave só em `GEMINI_API_KEY`; task `tech` a partir de fingerprints sem host.

### Changed

- Exemplos e documentação de desempenho usam hosts fictícios (`example.com`); HAR de exemplo em `scope/` deixa de ser versionável.
- Cloud: Gemini (desligado por enquanto) ainda distingue 429 de cota vs ritmo; Groq e NVIDIA ativos com retry de TPM. Sem fallback para Ollama.
- HAR: `log.entries` lidas uma a uma (sem `json.loads` da captura inteira). Nuclei das URLs HAR corre em lotes de 10 com `-max-host-error 3` e progresso na fase. A UI colhe runs `running` órfãos na subida e antes de aceitar um scan novo.
- IA: classificação de findings em lotes que cabem em `num_predict`; JSON truncado divide o lote. O run com 144 `corr/…` não cabe numa única chamada ao Ollama.
- UI: lista de Runs usa `row` para não sombrear `tr()` i18n; HTML relido a cada GET. Restyle visual em `ui_page.html` (tema escuro); IDs e `fetch` iguais ao contrato anterior.
- README e `documentation/`: alinhados ao catálogo reportable/note/coverage, rascunhos, `--verify`, HAR em streaming, retry Gemini 429/503, `recon ai` vs `--cloud`, UI (apagar run, Iniciar bloqueado, Rascunhos) e ADR-018.
