# ADR-010 — Ollama: perfil separado → dependência do scan

Status: Accepted (estado actual)  
Supersedes: “Ollama só com `--profile ai` e `recon ai` separado” (fase 4 / `versions.lock` / guia)

## Contexto

O guia isolava o modelo para caber em 16 GB e para a coleta não falhar se Ollama estivesse em baixo. O operador pediu scan completo com contribuição da IA na UI.

## Decisão

`analyze_run` corre no fim de `run_job` quando a coleta não foi cancelada/falhou. `ollama` sem profile; `recon` e `ui` fazem `depends_on`. `recon ai` permanece para reprocessar.

## Motivo

Evidência de código: `control.py`, `compose.yaml` (2026-10-04). Commits posteriores em `dev` mantêm a IA no scan completo (depois de `correlate`).

## Trade-off

Scan sem Ollama no ar falha a fase `ai` e o run fica `failed` mesmo com Nuclei ok. Mais honesto do que omitir a análise em silêncio. Mais tempo de wall-clock (JS grande).

## Revisitar se

Voltar a permitir coleta `ok` sem modelo (profile `ai` outra vez), com a UI a mostrar claramente “sem análise”.
