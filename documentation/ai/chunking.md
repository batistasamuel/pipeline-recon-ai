# Chunking

`js_chunks` em `ai.py`:

1. Lê `js/content/*.js` por ordem de nome.
2. Ignora vazio.
3. Dedup `sha256` do arquivo inteiro.
4. Parte em janelas de `JS_CHUNK_CHARS=20000` com `JS_CHUNK_OVERLAP=400`.
5. Se `overlap >= chunk_chars`, overlap cai para 0.
6. Antes do modelo, `route_excerpts` recorta ~2400 caracteres em torno de cada path literal (e parte se houver mais de 24 paths ou o recorte passar de 4000 chars).
7. Se o Ollama devolver JSON truncado (`done_reason=length` ou `eval_count` no teto), o trecho é dividido ao meio e as duas metades voltam ao mesmo cliente. JSON incompleto nunca é publicado.

Classificação (`classification_batches` em `ai.py`):

1. Estima a saída JSON com um `reason` pessimista (`CLASSIFY_REASON_BUDGET`).
2. Empacota findings até `CLASSIFY_OUTPUT_BUDGET` (2000 tokens, abaixo de `num_predict=2500`).
3. Cada lote vira uma linha no manifest (`chunk` 1..N).
4. JSON truncado num lote com mais de um finding divide o lote ao meio e chama de novo. Um finding sozinho que truncar falha a fase.
5. O payload publicado só existe depois do merge cobrir todos os ids.

Não há priorização por tamanho, host ou “parecer API”. Não há filtragem de minificados ou vendor (`jquery`). A única filtragem pré-modelo é `literal_paths`: aspas + `/` + pelo menos um carácter que não seja só barras.

## Trade-off

| Escolha | Ganho | Custo |
| --- | --- | --- |
| 20k chars | menos partes que um corte pequeno | risco de `over_budget` em JS denso |
| overlap 400 | path partido na fronteira pode aparecer nas duas metades | tokens duplicados |
| sem priorização | implementação simples | vendor bundles grandes (15 partes num único arquivo num run observado) consomem a fila |

Testes injetam `chunk_chars` menor (`test_phase4`). Em produção os valores são os da constante.
