# Orçamento de tokens

## Cálculo efetivo

```
INPUT_TOKEN_BUDGET = 16384 - 2500 - 1000 = 12884
```

`num_predict` é 2500, igual à reserva de saída do budget. A classificação entra em lotes (`CLASSIFY_OUTPUT_BUDGET=2000`) e só inclui findings **reportáveis**. 144 findings `corr/…` num run de alvo autorizado (2026-10-07) cabiam no input (~8k tokens) e estourou o timeout de 600 s numa única chamada; a estimativa de saída daquele lote único passava de 2500. A classificação de 12 findings noutro run usou 537 prompt / 418 eval (manifest). As 6 chamadas de rotas que de fato bateram no modelo (antes do recorte focado) usaram ~5,5k–11k prompt e 5–8 eval. Run observado (2026-10-08): 5 `corr/tech-panel` reportáveis; reprocessamento local (`recon ai` sem `--cloud`) concluiu com 5 classificações e 0 rotas (`js/content` vazio).

## O que conta como “desperdício”

- Overlap de 400 caracteres entre partes do mesmo arquivo.
- Partes sem path literal **não** gastam tokens (não chamam o modelo).
- Conteúdo JS repetido (mesmo SHA-256) não gera segunda leitura.
- Schema inválido: tokens daquela parte foram gastos; a parte seguinte ainda corre; o lote pode não publicar.

## Observado (não é benchmark formal)

Run observado (alvo autorizado, hash omitido): 66 linhas de manifest, 41153 prompt + 451 eval tokens somados no parser ad hoc da sessão. 60 partes sem modelo, 6 com modelo, 1 classificação. **INFERIDO** a partir do manifest daquele run, não de teste automatizado.
