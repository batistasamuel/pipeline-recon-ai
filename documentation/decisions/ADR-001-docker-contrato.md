# ADR-001 — Docker como contrato de execução

Status: Accepted  
Data: 2026-10-03  
Relacionado a: Plano estratégico §2, WP1, `Dockerfile`, `compose.yaml`

## Contexto

O script AS IS pedia Go no host e `go install @latest`. Conflitos de PATH em Kali/macOS.

## Decisão

A fronteira de execução é `docker compose run`. A imagem contém binários e o orquestrador.

## Alternativas

Instalação no host; Nix; VM Kali obrigatória.

## Motivo

Isolamento e o mesmo comando em amd64/arm64. Evidência: README da raiz, `compose.yaml`.

## Consequências

Operador precisa de Docker. Rebuild para mudar código Python na imagem (excepto volumes de results).

## O que faria revisitar

Runtime sem Docker (não está no núcleo).
