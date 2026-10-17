# Logging

- stdout do orquestrador: `[+] fase: detalhe`, `rotas: i/n arquivo parte p`, progresso nuclei HAR `{done}/{total}`.
- `logs/<binário>.err`: stderr de cada ferramenta.
- `phases.tsv`: nome, status, segundos, detalhe.
- `resumo.txt`: contagens + bloco `--- delta ---`.
- SQLite `phase.detail` e `phase.stderr_path` (directório `logs/`).
- `ai_manifest.jsonl`: uma linha por parte / lote de classificação.

Não há agregador, métricas Prometheus nem níveis debug configuráveis.
