# Validação da IA

## Classificação (`validate_classification`)

- Objeto só com chave `items`.
- Cada item: exatamente `finding_id`, `decision`, `reason`.
- `decision` ∈ {`keep`, `review`, `false_positive`}.
- `reason` string não vazia.
- Todos os ids **reportáveis** do lote, sem extras nem repetidos. Note e coverage não entram no schema. Cada lote valida o seu subconjunto; o merge final exige o conjunto reportável enviado.

## Rascunho (`validate_draft`)

- Objeto só com `title`, `summary`, `impact`, `steps`, `evidence_notes`.
- Strings não vazias; `steps` lista de strings não vazias.
- Transporte ou schema inválido na task `draft` falha a fase `ai` (mesmo critério da ADR-011). Sem cluster reportável a pasta fica vazia e a fase segue `ok`.

## Rotas (`validate_routes`)

- Objeto só com chave `routes`.
- Cada item tem `path`; extra permitido só `method`.
- `path` string começando por `/`.
- `method` se existir ∈ GET POST PUT PATCH DELETE HEAD OPTIONS.

Antes da validação estrita, `routes_keeping_slash_paths` tenta ficar só com paths `/…`. Depois `grounded_routes` exige que o path esteja no excerpt.

## Efeito no run

`analyze_run` mapeia `AiError` → fase `ai` `fail` → run `failed`. Schema inválido no meio das rotas incrementa `schema_errors` e segue; se no fim `had_error`, não publica. Classificação inválida também não publica.

`--cloud` exige chave de um provedor ativo (hoje Groq/NVIDIA) e prompt sem identidade residual. Sem chave ou com vazamento: `CloudNotAvailable` / `IdentityLeak` → fase `ai` `fail`. HTTP transitório: o cliente retenta; se esgotar, `AiError` e a fase falha (sem cair no Ollama). O SHA-256 do manifest é do prompt já mascarado.
