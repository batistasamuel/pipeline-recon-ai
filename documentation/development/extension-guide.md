# Extensão

Para acrescentar um coletor:

1. Entrada em `TOOL_CATALOG` com fase e params.
2. Chamada em `pipeline.py` na fase certa; honrar `_enabled` / `_param`.
3. Parser em `parse.py` se a saída não for linha-a-linha.
4. Fixture + ramo em `fixture_runner`.
5. ADR a explicar por que o coletor entra agora (o plano adiava Naabu/Nmap/FFuF/Gowitness).
6. `--check` / lockfile se for binário pinado.

Para outra regra de correlação: ramo em `correlate.py` com `template_id` `corr/…`, teste em `test_correlate.py`, e texto na checklist se for operador-facing. Não inventar exploit.

Para outro dork: linha em `recon_ai/dork_templates.txt` ou gerador em `dorks.py`; honrar `max_queries`. Testes de `test_dorks.py` não falam com o motor.

Para outro modelo local: hoje `MODEL` é constante. Trocar sem mudar `ai.py` e os testes de schema quebra o pin. Cloud é outro cliente (`gemini.py`) atrás de `--cloud`; não misturar provedores num fallback.

Para outro `template_id` no catálogo: entrada em `catalog.py` com `class` e textos do rascunho; teste em `test_catalog.py` / `test_drafts.py`.

UI: `ui_page.html` é relido a cada GET (`_page()`). Rebuild ou cópia para `/opt/recon/app/recon_ai/` no container. Alterar só CSS/HTML sem mexer em IDs/`fetch` não muda o contrato da API.
