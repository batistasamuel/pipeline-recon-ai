# ADR-013 — Sem Celery/Redis no núcleo

Status: Accepted  
Evidência: ausência no Compose e em `requirements.txt`

## Decisão

Um processo por `compose run` (ou uma thread na UI). Lock de um scan na UI.

## Motivo

Guia: simplicidade para o uso actual. O PDF citava asyncio/Celery.
