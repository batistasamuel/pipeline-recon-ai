# Referência de configuração

Origens, por ordem de uso no código: flags CLI / spec JSON → `config/recon.yaml` (via `config.py`) → defaults do `TOOL_CATALOG` (`job.py`) → ambiente.

## Ambiente

| Nome | Default no código | Consumidor | Efeito |
| --- | --- | --- | --- |
| `RECON_ENGINE` | `python` (Compose) | `runner.execute` | `bash` chama o script legado |
| `RECON_OLLAMA_URL` | `http://ollama:11434` | `ai.OllamaClient`, `analyze_run` | Endpoint do modelo |
| `RECON_LOOPBACK_HOST` | `host.docker.internal` (Compose) | `scope.probe_address`, `parse` | Alias de 127.0.0.1 no container |
| `RECON_SCOPE` | `/scope/scopes.txt` | `control.scope_file` | Allowlist |
| `RECON_RESULTS` | `/results` ou cwd | `control.results_root` | Artefatos + DB |
| `RECON_DB` | `<results>/recon.db` | store e UI | SQLite |
| `RECON_CONFIG` | `/config` | `config_dir` | YAML + chaves |
| `RECON_STATE_HOME` | `<results>/state/home` | `runtime.prepare_state` | HOME gravável |
| `RECON_VERIFY` | `/usr/local/lib/recon/verify-image.sh` | `--check` | Exit 4 se lockfile divergir |
| `RECON_UI_HOST` | `127.0.0.1` | `ui.main` | Bind; Compose usa `0.0.0.0` |
| `RECON_UI_PORT` | `8765` | `ui.main` | Porta |
| `NUCLEI_TEMPLATES_DIR` | `/opt/nuclei-templates` | `phase_nuclei` | Templates pinados |
| `PUID` / `PGID` | `1000` | Compose | Dono dos arquivos |
| `LLAMA_ARG_CACHE_RAM` | `0` | serviço ollama | Desliga cache llama.cpp de 8 GB |
| `HOME` / `XDG_CONFIG_HOME` | definidos em `prepare_state` | binários | Evita escrever em `/config` ro |
| `RECON_SCRIPT` | script na imagem | engine bash | Override de testes |
| `SHODAN_API_KEY` | — | `dorks.shodan_key` | Obrigatório se `engine=shodan` |
| `GEMINI_API_KEY` | — | `GeminiClient` | `--cloud`; alias `GOOGLE_API_KEY`; Compose `${GEMINI_API_KEY:-}` |
| `RECON_GEMINI_MODEL` | `gemini-flash-latest` | `GeminiClient` | override do modelo |
| `GROQ_API_KEY` | — | `GroqClient` | `--cloud`; Compose `${GROQ_API_KEY:-}` |
| `RECON_GROQ_MODEL` | `openai/gpt-oss-120b` | `GroqClient` | override do modelo Groq |
| `DEEPSEEK_API_KEY` | — | `DeepSeekClient` | `--cloud`; Compose `${DEEPSEEK_API_KEY:-}` |
| `RECON_DEEPSEEK_MODEL` | `deepseek-chat` | `DeepSeekClient` | override do modelo |
| `NVIDIA_API_KEY` | — | `NvidiaClient` | `--cloud`; Compose `${NVIDIA_API_KEY:-}` |
| `RECON_NVIDIA_MODEL` | `openai/gpt-oss-20b` | `NvidiaClient` | override do modelo |

## CLI

| Flag | Tipo | Default | Validação |
| --- | --- | --- | --- |
| `domain` / target | string | obrigatório | `valid_target` |
| `--threads` | int | 50 | 1–200 (`config._threads`) |
| `--dry-run` | bool | false | não consulta rede |
| `--config` | path | `/config/recon.yaml` se existir | YAML mapa |
| `--scope` | lista | `[target]` no spec | tem que cobrir o alvo |
| `--exclude` | lista | `[]` | hosts removidos |
| `--disable` | lista | `[]` | nomes do catálogo |
| `--job` | path JSON | — | mapa; ferramentas desconhecidas: erro |
| `--cloud` | bool | false | opt-in nuvem; Groq/NVIDIA agora; Gemini/DeepSeek desligados; prompt pseudonimizado. No subcomando `ai`, a flag **substitui** o spec (sem flag = Ollama) |
| `--cloud-mode` | `sequential`/`parallel` | `sequential` | sequencial = fallback; paralelo = balanceamento |
| `--ai-delay-ms` | int | 2000 | 10–600000; espera entre uma resposta e o próximo prompt |
| `--verify` | bool | false | checagens passivas na fase `ai`; default do spec é `skip` |
| `--webhook` | bool | false | sempre exit 2 |
| `--format` (export) | `pdf`/`docx` | `pdf` | outro: erro |
| `--draft` (export) | `cluster_key` | — | exporta um rascunho de `drafts/` em vez do caderno |
| `--har` | path no container | — | arquivo ≤ 32 MB; `iter_har_entries`; hosts filtrados por `url_allowed` |
| `--har-b` | path no container | — | segundo HAR (mesmo filtro) |

`nuclei` e `dorks` exigem `httpx` ligado (`JobError`).

## `config/recon.yaml`

Lido por `recon_ai/config.py`. Só aplica `threads` globais, `tools.{dnsx,httpx,katana,gau,nuclei}.threads`, `tools.nuclei.rate_limit`, `tools.amass.timeout_minutes`. Os outros parâmetros do catálogo (depth, timeout httpx, tags Nuclei, …) vêm do spec / defaults de `job.py`, não deste YAML.

`recon_ai/settings.py` é uma cópia mais antiga (sem amass timeout) e **não** é importada por `control.py`.
