# ADR-014 — UI fora do caminho crítico, depois no perfil `ui`

Status: Accepted  
Evidência: `profiles: ["ui"]`, `recon_ai/ui.py`

## Contexto

Guia WP: UI adiada. PDF: dashboard FastAPI/React. Fase 6: só leitura. Fase 7: o mesmo processo HTTP passa a POST do spec.

## Decisão

UI stdlib, HTML estático, opcional. CLI continua completo. A UI **pode** iniciar e parar scan, receber HAR, mostrar Candidatos e Rascunhos, apagar run parado (`DELETE`), e **Consultar a IA** (prompt livre, `AI_CHAT_LOCK`). Iniciar fica desabilitado com scan `running`. `reap_stale_runs` na subida e antes de um POST novo. HTML relido a cada GET.

## Trade-off

Não é FastAPI. Um lock global. Página e API no mesmo processo.
