# Troubleshooting

| Sintoma | Causa confirmada no código / operação | O que fazer |
| --- | --- | --- |
| `no such service: recon` | Compose noutro diretório | `cd` para a raiz do RECON-AI |
| `Alvo inválido` exit 2 | `valid_target` recusou | domínio com ponto, ou IPv4[:porta] |
| `fora do escopo` exit 3 | falta `scopes.txt` ou linha ≠ alvo | acrescentar o alvo exato (inclui `:8080`) |
| `Imagem divergente` exit 4 | `--check` / `verify-image.sh` | rebuild; não actualizar nuclei no container |
| fase `subdomains` fail | zero nomes | DNS, fontes, ou alvo literal mal escrito |
| `warn` em subdomains | uma fonte falhou (amass/crtsh/…) | ver `logs/*.err`; nomes das outras fontes entram |
| `Ollama não está acessível` | serviço em baixo ou URL | `docker compose up -d ollama` |
| `Modelo divergente` | tag ≠ `qwen2.5:7b*` | `ollama pull qwen2.5:7b` |
| IA `fail` schema | JSON fora do contrato | manifest tem `validation_error`; `ai_result` antigo permanece |
| IA `fail` transporte Gemini HTTP 503 | pico de demanda no Google AI Studio | o cliente retenta 429/503 (4×); se persistir, a fase falha sem cair no Ollama. `recon ai RUN_ID --cloud` insiste na nuvem; `recon ai RUN_ID` (sem flag) classifica no Ollama local |
| UI `Já existe um scan` 409 | `SCAN_LOCK` ou run `running` | stop ou esperar; a UI colhe órfãos na subida; próximo comando reap `running` como `failed` |
| Lista de Runs vazia na UI | bug antigo: `const tr` sombreava `tr()` i18n após a lixeira | `loadRuns` usa `row`; recarregue a página (HTML relido a cada GET) |
| `DELETE` 409 | tentou apagar run `running` | `stop` primeiro, ou esperar o reap |
| 127.0.0.1 no container ≠ DVWA | loopback do container | `RECON_LOOPBACK_HOST=host.docker.internal` (já no Compose) |
| gau com milhares de URLs irrelevantes | arquivo histórico, não o host actual | `--disable gau` e/ou `waybackurls` |
| `settings.py` vs `config.py` | dois loaders | o runtime usa `config.py` |
| fase `dorks` fail / `go-dork` ausente | imagem antiga ou `--check` falhou | rebuild `recon-ai:local`; `--check`; o banner do binário pode dizer v1.0.1 embora o asset pinado seja 1.0.3 |
| HAR `0 urls; 0 js` | hosts do HAR ≠ `in_scope` do run | incluir o host no spec (não basta estar em `scopes.txt`); ver `har/` e o resumo da fase |
| fase `har` `running` por muito tempo | nuclei sem sessão nas URLs do HAR (cap 50); no run `56ea92d1` foram ~38 min no mesmo host 403 | a fase atualiza `{done}/{total}`; `-max-host-error 3` abandona o host após 3 erros |
| fase `har` `running` com UI recém-reiniciada | o processo do scan morreu e o SQLite ficou `running` | a UI colhe o órfão na subida; o botão Iniciar scan volta a habilitar |
| dorks `0 hits` | motor sem resultados in-scope, delay, ou queries fracas | ver `dorks/queries.txt` e `dorks/hits.txt`; não é falha se `go-dork` saiu 0 |
| `engine=shodan` fail | chave em falta | `SHODAN_API_KEY` ou `tools.dorks.shodan_key`; sem chave a fase falha (sem fallback) |
| rotas `provider=none` com milhares de URLs JS | `js/content` vazio (download falhou ou cap 200) | a IA não inventa rotas sem arquivo no disco; ver `js/` e `logs/` |
| `--cloud` `Provedor em nuvem sem chave` | nenhuma chave de provedor ativo | definir `GROQ_API_KEY` e/ou `NVIDIA_API_KEY` no `.env` / Compose |
| Groq HTTP 403 `error code: 1010` | Cloudflare recusou o User-Agent do urllib | o cliente envia `User-Agent: recon-ai` |
| Groq `model_not_found` | a chave não tem o modelo pedido | override em `RECON_GROQ_MODEL` |
| Groq HTTP 429 TPM | ritmo da faixa on_demand | o cliente espera o `try again in Xs` e repete; não aborta a fase |

## Honestidade (falha crítica ≠ sucesso)

O Pipeline marca `fail` em: zero subdomínios; dnsx/httpx/nuclei/go-dork (ou httpx dos hits) com exit ≠ 0. `run_status` trata qualquer `fail` como run failed. `analyze_run` failed também fecha `failed`. Shodan sem chave falha `dorks` — não há motor alternativo.

Possível gap: fonte de URL (katana/gau) que falha **não** falha a fase `urls` — a fase fica `ok` com o que houver. `warn` em subdomains **não** é fail. Engine Bash legado não foi reauditado linha a linha neste documento; o README da raiz descreve correcções em relação ao script antigo.
