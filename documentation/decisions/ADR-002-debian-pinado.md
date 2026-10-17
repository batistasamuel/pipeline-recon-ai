# ADR-002 — Debian 13 e imagens pinadas

Status: Accepted  
Data: 2026-10-03  
Evidência: `versions.lock`, `Dockerfile` digests `sha256:a99cfc51…` e `golang:1.27.1-trixie@sha256:3b77fc61…`

## Decisão

`debian:13-slim` e `golang:1.27.1-trixie` por digest. Sem `@latest`.

## Motivo

Reprodutibilidade e o critério de corte do guia (“dependência @latest não é aceitável”).

## Trade-off

Actualizar base exige bump consciente do lockfile e rebuild.
