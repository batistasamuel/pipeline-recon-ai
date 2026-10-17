# ADR-006 — SQLite como store

Status: Accepted  
Evidência: `recon_ai/db.py`

## Decisão

Um arquivo `recon.db` no volume de results. Sem PostgreSQL, sem Redis.

## Motivo

Um processo, histórico e resume sem broker. O PDF permitia SQLite/PostgreSQL; o guia fechou em SQLite para o uso actual.
