# Gaps e classificação de afirmações

## Afirmações

| Afirmação | Classe | Nota |
| --- | --- | --- |
| Compose é o contrato de execução | CONFIRMADO | `compose.yaml`, README |
| Debian 13 digest a99cfc51… | CONFIRMADO | lockfile / Dockerfile |
| Ferramentas e versões da tabela de adapters | CONFIRMADO | `versions.lock` |
| `PHASES` inclui `ai` | CONFIRMADO | `phases.py` |
| Scan completo chama `analyze_run` | CONFIRMADO | `control.py` |
| Ollama sem profile | CONFIRMADO | `compose.yaml` 2026-10-04 |
| Input budget 12884 | CONFIRMADO | `ai.py` aritmética |
| `--webhook` recusado | CONFIRMADO | `cli.py` exit 2 |
| `--cloud` opt-in | CONFIRMADO | `cloud.py`; Groq e NVIDIA ativos |
| HAR `iter_har_entries` | CONFIRMADO | `har.py`, `test_har.py` |
| Catálogo + `drafts/` | CONFIRMADO | `catalog.py`, ADR-018 |
| UI inicia scan | CONFIRMADO | `ui.py` POST |
| HAR opcional no mesmo run | CONFIRMADO | `har.py`, `test_har.py` |
| Dorks executados no scan | CONFIRMADO | `dorks.py`, `versions.lock` GODORK |
| Correlate `corr/…` antes da IA | CONFIRMADO | `correlate.py`, `test_correlate.py` |
| Segunda arch testada | NÃO VERIFICADO | job `CI` ainda é placeholder |
| Metal/CUDA ativo no Ollama | NÃO VERIFICADO | |
| Quantização Q4 do qwen2.5:7b | NÃO VERIFICADO | só a tag |
| 16 GB é mínimo suficiente | INFERIDO | PDF estratégia + tamanho do modelo |
| 41153 prompt tokens num run observado | INFERIDO | soma do manifest na sessão |
| WP0–WP5 como plano tático oficial | HISTÓRICO/PLANEJADO | só no guia v2 |
| Groq/NVIDIA como provedor | CONFIRMADO (`--cloud`) | `cloud.py`; default continua Ollama |
| Gemini no scan sem `--cloud` | SUPERADO | default continua Ollama |
| FastAPI + React | SUPERADO / não feito | PDF |
| Profile `ai` como único caminho | SUPERADO | lockfile ainda menciona |
| `@latest` na instalação | SUPERADO | doc do script AS IS |

## Lacunas

- Plano Tático em arquivo próprio: ausente.
- Histórico git: existe no GitHub; ADRs pré-git continuam sem hash.
- Benchmarks reproduzíveis: ausentes.
- Revisão linha-a-linha do Bash legado vs princípio “fail ≠ sucesso”.
- Comentário em `versions.lock` (“só entra com o perfil ai”) está desactualizado em relação ao Compose.

## Checklist do guia §19

Código analisado; planos lidos; planned-vs-implemented; histórico; arquitectura e diagramas; JS→IA; 16K; otimização; hardware; parâmetros; exit codes; scope; store; adapters; schema; local vs cloud; itens fora do núcleo; ADRs; limitações; gaps; sem funcionalidade inventada; planos não vendidos como comportamento actual sem etiqueta.
