# ADR-011 — Schema obrigatório na saída da IA

Status: Accepted  
Evidência: `validate_classification`, `validate_routes`, `test_phase4`

## Decisão

JSON fora do schema não é mascarado. Transporte aborta o lote. Schema de uma parte de rotas segue em frente mas pode impedir a publicação.

## Motivo

Critério de corte do guia: “IA não pode aceitar JSON inválido”.
