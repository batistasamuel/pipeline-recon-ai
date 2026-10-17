# Uso

Todos os exemplos assumem o diretório do repositório e `PUID="$(id -u)" PGID="$(id -g)"`.

```bash
docker compose run --rm recon example.com
docker compose run --rm recon example.com --har /scope/captura.har
docker compose run --rm recon example.com --threads 40
docker compose run --rm recon example.com --scope example.com --exclude dev.example.com
docker compose run --rm recon example.com --disable waybackurls --disable gau
docker compose run --rm recon example.com --disable dorks
docker compose run --rm recon resume RUN_ID
docker compose run --rm recon stop RUN_ID
docker compose run --rm recon example.com --cloud --verify
docker compose run --rm recon example.com --cloud --cloud-mode parallel --ai-delay-ms 2000
docker compose run --rm recon ai RUN_ID
docker compose run --rm recon ai RUN_ID --cloud --cloud-mode sequential
docker compose run --rm recon export RUN_ID --format pdf
docker compose run --rm recon export RUN_ID --format docx
docker compose run --rm recon export RUN_ID --draft CLUSTER_KEY --format pdf
```

Alvo IPv4 no host (DVWA):

```bash
# scopes.txt contém 127.0.0.1:8080
docker compose run --rm recon 127.0.0.1:8080
```

Engine legado:

```bash
RECON_ENGINE=bash docker compose run --rm recon example.com
```

## Códigos de saída

| Código | Motivo (`README.md` / `ControlError`) |
| --- | --- |
| 0 | Run `ok` (coleta crítica + IA ok, ou dry-run / check ok) |
| 1 | Fase crítica, ingest inválido, ou IA falhou |
| 2 | Alvo/threads/job inválidos; `--cloud`; `--webhook`; comando sem subcomando |
| 3 | Fora do `scopes.txt` ou fora do `in_scope` |
| 4 | Imagem ≠ lockfile |

## UI

`POST /api/runs` 202 + thread. JSON sem arquivo = scan como o CLI (inclui `cloud` e `verify` no spec). `multipart/form-data` com `spec` (JSON) e `har` (arquivo, máx. 32 MB) acrescenta a fase `har` no mesmo run. Um scan de cada vez (`SCAN_LOCK` + `running` no SQLite); o botão Iniciar fica desabilitado enquanto houver scan `running`. `GET /api/runs/{id}` devolve fases, delta, classificação, rotas e `drafts`. `POST …/stop`. `DELETE /api/runs/{id}` apaga run parado (409 se `running`) e a pasta de artefatos. `GET …/export?format=pdf|docx`. `GET/POST /api/runs/{id}/drafts/{key}` marca `draft` | `ready` | `rejected`.

Na subida e antes de aceitar um POST, a UI chama `reap_stale_runs` (run `running` órfão → `failed`; fase `running` → `fail` com `phase.interrupted`).

O HAR tem que caber no `in_scope` **deste** run (o mesmo `url_allowed` das outras fases). Um host autorizado em `scopes.txt` mas ausente do spec conta como fora do escopo: a fase pode ficar `ok` com 0 URLs e 0 JS. Coloque o arquivo em `./scope` e passe `--har /scope/captura.har`. Tamanho máximo 32 MB. A ingestão percorre `log.entries` uma a uma.

Dorks: motor Bing por padrão, delay 12 s, no máximo 24 queries. Hits só entram se o host estiver no escopo; httpx confirma o URL. `--disable dorks` omite a fase. `engine=shodan` exige `SHODAN_API_KEY` ou `tools.dorks.shodan_key`.

A UI mostra **Candidatos** (`corr/…`) separados dos findings Nuclei, **Rascunhos** e uma checklist gerada do run. Consultar a IA (prompt livre) continua no Ollama, mesmo com o checkbox de nuvem marcado.
