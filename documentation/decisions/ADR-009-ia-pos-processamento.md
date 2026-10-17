# ADR-009 — IA local como pós-processamento

Status: Accepted (momento da chamada: Superseded em parte pelo ADR-010)  
Evidência: `ai.py`, `analyze` só lê findings e `js/content`

## Decisão

O modelo não enumerar ativos. Classifica findings e extrai rotas de JS já baixado. Schema obrigatório.

## Motivo

A estratégia: IA filtra ruído; não substitui o investigador. Dados estruturados entram; JSON validável sai.
