# Retomada e recuperação

## Resume

```bash
docker compose run --rm recon resume RUN_ID
```

`first_incomplete` escolhe a primeira fase de `PHASES` que não está `ok` ou `skip`. Reusa `output_dir` e o spec gravado. Se a coleta está `ok`, `har` e `correlate` são `skip`/`ok` e `ai` falta ou falhou, só a análise corre (`from_phase=ai` não reexecuta `SCAN_PHASES`, HAR nem correlate).

Para **só** a fase `ai` (mesmo depois de `fail` ou `ok`):

```bash
docker compose run --rm recon ai RUN_ID          # Ollama local
docker compose run --rm recon ai RUN_ID --cloud  # Gemini; exige GEMINI_API_KEY
```

A flag `--cloud` do subcomando `ai` **não** herda o spec do scan: omiti-la usa Ollama.

## Stop

```bash
docker compose run --rm recon stop RUN_ID
```

`run_control.cancel=1`. O Pipeline envia SIGTERM ao process group. Status `cancelled`. Delta é limpo.

## Reap

Qualquer invocação da CLI chama `reap_stale_runs`: linhas `running` passam a `failed` e fases `running` passam a `fail` (`phase.interrupted`). A UI faz o mesmo na subida do processo e ao aceitar um `POST /api/runs` (depois do `SCAN_LOCK`). Um container morto não fica `running` para sempre.

## Apagar

`DELETE /api/runs/{id}` (lixeira na UI) chama `delete_run`: recusa `running` (409), remove linhas do SQLite e a pasta `output_dir`. Irreversível.

## Store

| Entidade | Papel |
| --- | --- |
| `run` | id, target, status, output_dir, threads, timestamps |
| `run_spec` | JSON do job |
| `run_control` | flag de cancel |
| `phase` | nome, status, exit_code, duration_s, detail |
| `asset` | kind = subdomain/host/live/unauthorized/forbidden |
| `url` | URLs da fase urls |
| `finding` | Nuclei, `har/*` e `corr/*` (`kind`, `class`, `cluster_key`, `evidence`) |
| `ai_result` | classification + routes + tech + draft |
| `delta_run` / `delta_item` | baseline e mudanças |

`previous_ok_run` = último `ok` do mesmo `target` (casefold), excluindo o run actual. Sem baseline, o delta lista tudo como `entered`.
