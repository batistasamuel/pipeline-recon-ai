# ADR-016 — Recon diferencial sem webhook

Status: Accepted  
Evidência: `diff.py`, `test_phase5`, `--webhook` recusado

## Decisão

No fim de um run `ok`, comparar assets (valor+kind) e findings (template+URL / severity) com o último `ok` do alvo. Escrever no resumo e no SQLite. Sem alerta externo.
