# Manifest da IA

Arquivo: `<output>/ai_manifest.jsonl`. Campos escritos por `ai.py`:

`task`, `chunk`, `parts` (rotas: file, part, chars; classificação: count, ids), `prompt_sha256`, `prompt_eval_count`, `eval_count`, `done_reason`, `input_budget`, `over_budget`, `valid`, `response`, `validation_error`, `error`, `model_called`.

`_reset_manifest` zera o arquivo no início de cada `analyze`. Linhas anteriores daquele run perdem-se no reprocessamento; `ai_result` só é substituído se o novo lote publicar. Tasks no manifest: `classification` (um `chunk` por lote), `routes`, `tech`, `draft`.
