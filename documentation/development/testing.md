# Testes

| Arquivo | O que cobre |
| --- | --- |
| `check-gates.sh` | domínio, threads, escopo, keep_names (helpers Bash) |
| `test_phase2.py` | alvo, escopo, resume, reap (run e fase `running`), `--from` no script fake, `first_incomplete` inclui `ai`, `delete_run` |
| `test_phase3.py` | parsers, pipeline com fixtures, host literal, nuclei HAR em lotes |
| `test_catalog.py` | evidence Nuclei/HAR, `class`, `cluster_key` por host em cobertura |
| `test_drafts.py` | 8 seções do markdown, status, export `--draft`, verify skip/yes/no |
| `test_phase4.py` | schema IA, chunking, grounding, manifest, `CloudNotAvailable` sem chave, classify só reportable |
| `test_pseudonym.py` | máscara de hosts, Gemini, retry HTTP 503 depois sucesso, 400 sem retry |
| `test_cloud.py` | Groq/NVIDIA; cadeia sequencial vs paralelo; sem chave |
| `test_pace.py` | `--ai-delay-ms` 10–600000; `cloud_mode`; espera após a primeira resposta |
| `test_i18n.py` | catálogos `pt-BR` / `en-US` / `es-ES` |
| `test_phase5.py` | delta |
| `test_phase6.py` | view, UI GET, classificação na página, drafts na API; `loadRuns` usa `row` (não sombreia `tr()`) |
| `test_phase7.py` | spec, disable, live phases, stop, export, `run_job` + IA stub, export `--draft`, DELETE do run |
| `test_har.py` | HAR opcional, filtro de escopo, `iter_har_entries`, fase `skip` sem arquivo |
| `test_derive.py` | fingerprints httpx, provenance, buckets, JS secrets redactados |
| `test_correlate.py` | joins `corr/…`, zero matches `ok`, `from_phase=ai` não recalcula |
| `test_dorks.py` | queries `site:`, escopo, httpx no URL, `--disable dorks`, Shodan sem chave; `go-dork` injectado (sem rede de busca) |

## Fixtures (`tests/fixtures/`)

| Arquivo | Ferramenta |
| --- | --- |
| `subfinder.txt` | subfinder |
| `amass.txt` | amass |
| `crtsh.json` | curl crt.sh |
| `dns.txt` | dnsx |
| `http.jsonl` | httpx JSON |
| `urls.txt` | katana |
| `app.js` | curl de JS (`/api/v1/users`, `/v2/health`) |
| `nuclei.jsonl` | nuclei |

Não há fixture de gau/waybackurls: o runner de teste devolve string vazia nesses binários.
