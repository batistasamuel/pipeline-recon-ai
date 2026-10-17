# Janela de 16K

`num_ctx = 16384` é o **orçamento total** enviado ao Ollama, não o espaço livre para JavaScript.

Constantes em `recon_ai/ai.py`:

| Símbolo | Valor | Papel |
| --- | --- | --- |
| `NUM_CTX` | 16384 | `options.num_ctx` |
| `MAX_OUTPUT_TOKENS` | 2500 | reserva de saída no cálculo do budget |
| `SAFETY_MARGIN_TOKENS` | 1000 | margem |
| `MAX_PREDICT_TOKENS` | 2500 | `options.num_predict` (igual a `MAX_OUTPUT_TOKENS`) |
| `INPUT_TOKEN_BUDGET` | 12884 | `NUM_CTX - MAX_OUTPUT_TOKENS - SAFETY_MARGIN_TOKENS` |
| `CLASSIFY_OUTPUT_BUDGET` | 2000 | teto estimado por lote de classificação |

Não há system prompt separado. A mensagem é um único `role=user`.

```
Context Budget (16384)
  - Task prompt (classificação ou “Extraia rotas…”)
  - Metadata (ids dos findings ou o trecho JS)
  - Output reservation (2500 no cálculo e no `num_predict`)
  - Safety margin (1000)
= Effective input budget 12884
```

O código **não** estima tokens antes de enviar. Depois da resposta, `prompt_eval_count > 12884` marca `over_budget=true` no manifest. Não aborta só por isso.

O tamanho do recorte JS é em **caracteres** (20000), não em tokens. Um JS minificado denso pode gastar mais tokens que 20k / 4.
