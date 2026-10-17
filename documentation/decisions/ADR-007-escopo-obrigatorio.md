# ADR-007 — Escopo obrigatório

Status: Accepted  
Evidência: `scope.py`, `control.refuse_scope`, `test_phase2`, `check-gates.sh`

## Decisão

Sem `scopes.txt` legível ou sem o alvo na lista, exit 3. Spec `in_scope` é segunda cerca.

## Motivo

O script AS IS aceitava qualquer domínio na linha de comando.
