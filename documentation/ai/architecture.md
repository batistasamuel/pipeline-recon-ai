# Arquitetura da IA

A IA é pós-processamento sobre artefatos já estruturados. Não descobre hosts. Não substitui Nuclei.

## Fronteira

| A IA recebe | A IA não recebe |
| --- | --- |
| Findings ingeridos (`id`, severity, name, template, URL, `class`, `cluster_key`, `evidence`) — só `reportable` na classificação | Tráfego HTTP cru, findings `note`/`coverage`, segredo em claro |
| Partes de JS já baixado | Lista regex `endpoints.txt` (é paralela, não prompt) |
| | URLs do gau sem download |

## Provedor

| Campo | Valor | Evidência |
| --- | --- | --- |
| Runtime | Ollama `ollama/ollama@sha256:292ee7945dfc3d5840a181f3ab86fedb1e66703e02c8af98b50f4da56b7e278c` | `versions.lock`, Compose |
| Modelo | `qwen2.5:7b` (4,7 GB na listagem local observada) | `ai.MODEL`, `ollama list` |
| API | `POST /api/chat`, `format=json`, `stream=false` | `OllamaClient.complete_with_usage` |
| Cloud | `--cloud`: Groq e NVIDIA (Gemini e DeepSeek desligados). `sequential` ou `parallel`. Prompt pseudonimizado | `make_cloud_client`, `DISABLED_CLOUD_PROVIDERS` |
| Paralelismo | uma chamada de cada vez | loop em `analyze` |
| Retry | Gemini HTTP 429/503: até 4 tentativas (2s, 4s, 8s). Timeout e demais HTTP falham na hora. Ollama sem retry de transporte | raise `AiError` |
| JSON truncado | divide o trecho e chama o mesmo Ollama | não publica JSON incompleto |
| Timeout | 600 s | construtor do cliente |

## Saídas

1. `classification`: `{ "items": [ { "finding_id", "decision", "reason" } ] }` cobrindo os ids **reportáveis** do lote. Note e coverage ficam só em `clusters.json`. O prompt é fatiado em lotes que caibam em `CLASSIFY_OUTPUT_BUDGET` (2000 tokens de saída estimados); o resultado publicado é o merge validado.
2. `routes`: `{ "routes": [ { "path", "method"? } ] }`.
3. `tech` (se houver fingerprints): `{ "items": [ { "name", "version"?, "note"? } ] }`.
4. `draft` (se houver cluster reportável): `{ "items": [ { "cluster_key", "title" } ] }`. Título, CWE, passos e remediação são determinísticos; o modelo só preenche summary/impact/evidence_notes no Ollama. Google AI Studio usa o catálogo, sem host real no prompt.

Gravadas em `ai_result` só no fim bem-sucedido. Cada parte também vai ao manifest. Markdown em `drafts/<cluster_key>.md` + `drafts/index.json`.

## Quando o modelo não é chamado

- Sem findings reportáveis e sem JS → `provider=none` na classificação, payload vazio.
- Parte de JS sem `LITERAL_PATH` (`"/…"` com conteúdo além de barras) → `{"routes":[]}` sem HTTP.
- Run só com note/coverage → `drafts/` vazio, fase `ai` ok.

## Perfil

O desenho original isolava Ollama no profile `ai`. O scan completo atual depende de `ollama` no Compose default. O comando `recon ai RUN_ID` reprocessa a fase no **Ollama** (a flag `--cloud` do CLI defaulta a falso e **não** herda `spec.cloud`). `recon ai RUN_ID --cloud` insiste no Gemini. Sem fallback silencioso entre os dois.
