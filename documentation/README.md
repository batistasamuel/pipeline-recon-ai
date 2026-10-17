# Documentação — Recon AI

Pasta pedida na raiz do projeto. A árvore segue o conjunto obrigatório do *Guia de Geração da Documentação* (v2). O guia citava `docs/`; o destino efetivo é `documentation/`.

Fonte de verdade do **comportamento vigente**: código, `compose.yaml`, `versions.lock`, testes e o `README.md` da raiz (pipeline: coleta → dorks → har opcional → correlate → uma IA; catálogo reportable/note/coverage; rascunhos em `drafts/`; `--cloud` opt-in). Fonte de verdade da **intenção original**: `Plano Estratégico de Evolução_ Recon AI Automation (AS IS para TO BE).pdf`, `Estrategia_Automação_Recon_e_IA.md.pdf` e `Documentacao_Recon_Script_Full.docx`, todos na raiz. O *Plano Tático* WP0–WP5 aparece no guia v2; **não há um arquivo separado com esse nome no repositório**.

O histórico git do projecto está no repositório GitHub (`dev` / `hml` / `main`). Motivos de mudança sem evidência em arquivo estão marcados como *motivo não identificado no repositório*.

## Por público

| Público | Comece por |
| --- | --- |
| Operador | [operations/quick-start.md](operations/quick-start.md), [operations/usage.md](operations/usage.md), [security/authorized-use.md](security/authorized-use.md) |
| Desenvolvedor | [development/developer-guide.md](development/developer-guide.md), [development/testing.md](development/testing.md), [architecture/execution-flow.md](architecture/execution-flow.md) |
| Arquiteto / revisor | [architecture/architecture.md](architecture/architecture.md), [appendix/planned-vs-implemented.md](appendix/planned-vs-implemented.md), [decisions/](decisions/) |
| Novo mantenedor | [01-overview.md](01-overview.md), [03-history-and-evolution.md](03-history-and-evolution.md), [appendix/limitations.md](appendix/limitations.md) |

## Índice

1. [Visão geral](01-overview.md)
2. [Glossário](02-glossary.md)
3. [Histórico e evolução](03-history-and-evolution.md)
4. [Escopo e não-objetivos](04-scope-and-non-goals.md)
5. Arquitetura — [visão](architecture/architecture.md), [componentes](architecture/component-diagram.md), [deployment](architecture/deployment-diagram.md), [dados](architecture/data-flow.md), [execução](architecture/execution-flow.md), [sequências](architecture/sequence/end-to-end.md)
6. Configuração — [referência](configuration/reference.md), [defaults](configuration/defaults.md), [impacto](configuration/parameter-impact.md), [perfis](configuration/profiles.md)
7. IA — [arquitetura](ai/architecture.md), [janela](ai/context-window.md), [orçamento](ai/token-budget.md), [chunking](ai/chunking.md), [otimização](ai/optimization.md), [validação](ai/validation.md), [hardware](ai/hardware-adaptation.md)
8. Operação — [instalação](operations/installation.md), [início rápido](operations/quick-start.md), [uso](operations/usage.md), [falhas](operations/troubleshooting.md), [retomada](operations/recovery.md)
9. Segurança — [uso autorizado](security/authorized-use.md), [escopo](security/scope-policy.md), [dados](security/data-handling.md)
10. Observabilidade — [logs](observability/logging.md), [ciclo do run](observability/run-lifecycle.md), [manifest](observability/manifest.md)
11. Performance — [benchmarks](performance/benchmarks.md), [otimização](performance/optimization.md)
12. Desenvolvimento — [guia](development/developer-guide.md), [testes](development/testing.md), [adapters](development/adapters.md), [extensão](development/extension-guide.md)
13. [ADRs](decisions/) (inclui [ADR-018](decisions/ADR-018-reportable-vs-nota.md) — reportável vs nota)
14. Apêndice — [planejado × implementado](appendix/planned-vs-implemented.md), [limitações](appendix/limitations.md), [gaps](appendix/documentation-gaps.md)

O Word consolidado com o mesmo conteúdo está em [Recon_AI_Documentacao_Consolidada.docx](Recon_AI_Documentacao_Consolidada.docx).
