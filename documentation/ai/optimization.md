# Otimização da IA (o que existe)

| Estratégia | Implementada? | Como | Trade-off |
| --- | --- | --- | --- |
| Deduplicação de JS | sim | SHA-256 do corpo | dois URLs com o mesmo bundle = uma leitura |
| Filtragem pré-modelo | sim | só chama se houver path literal | pode ignorar concatenação sem aspas |
| Normalização de path | sim | descarta path sem `/` inicial ou só barras | rotas relativas `api/x` saem |
| Grounding | sim | `path` tem que ocorrer no trecho | alucinação de path novo é cortada |
| Prompt compacto | sim | uma frase + JSON; sem system | menos contexto de domínio |
| Output estruturado | sim | `format=json` + schema | recusa prosa |
| Limite de saída | sim | `num_predict=2500` (reserva de saída) | lista enorme ainda pode truncar; nesse caso o trecho (rotas) ou o lote (classificação) é dividido e volta ao mesmo modelo |
| Recorte focado | sim | janela ~2400 chars em torno de cada `LITERAL_PATH` | o modelo não vê 20k de ruído minificado |
| Chunking + overlap | sim | 20k / 400, depois recorte focado | ver chunking.md |
| Não reprocessar vazio | sim | sem JS/findings ⇒ `provider=none` | |
| Cache de prompt llama.cpp | desligado | `LLAMA_ARG_CACHE_RAM=0` | menos RAM, sem reuse entre partes |
| Lote de classificação | sim | fatia findings pelo orçamento de saída | mais chamadas em série; 144 findings não cabem numa resposta |
| Batching / paralelo | não | loop série | tempo (~16 min de IA num run observado) |
| Priorização | não | ordem de arquivo | |
| Filtragem de vendor | não | jquery entra se tiver `"/…"` | tokens em bibliotecas |
| Retry de transporte | Ollama: não. Gemini: HTTP 429/503 até 4 vezes (2 s, 4 s, 8 s) | timeout e demais HTTP falham a fase | 503 persistente ainda falha; não troca de provedor |
| Divisão por JSON truncado | sim | o mesmo Ollama, trechos menores | não aceita JSON incompleto nem salta o pedaço |

Quantização: a tag `qwen2.5:7b` no Ollama é a distribuição padrão da tag; **não** há no repo um arquivo que fixe Q4 vs Q8. Não afirmar nível de quantização.
