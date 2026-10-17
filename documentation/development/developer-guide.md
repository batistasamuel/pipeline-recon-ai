# Guia do desenvolvedor

## Layout

```
Dockerfile          imagem multi-stage
compose.yaml        recon, ollama, ui
versions.lock       pinos
recon_ai/           orquestrador (pipeline, har, derive, dorks, correlate, catalog, drafts, verify, gemini, ai, ui)
tests/              unittest + fixtures + check-gates.sh
scripts/            fetch-tools.sh, verify-image.sh, common.sh
recon-claude-grok.sh  engine legado
scope/ config/ results/
```

## Como correr testes

```bash
python3 -m venv /tmp/recon-test-venv
/tmp/recon-test-venv/bin/pip install -r requirements.txt
/tmp/recon-test-venv/bin/python -m unittest discover -s tests -q
bash tests/check-gates.sh
```

Os testes de pipeline usam `fixture_runner` (sem rede). Testes de `run_job` injectam `FixtureAI` para não falar com Ollama.

## Invariantes

- Não inventar fallback silencioso para o Ollama. `--cloud` encadeia provedores ativos em `cloud.py`; falha de nuvem não cai no Ollama.
- Falha crítica não pode fechar o run como `ok`.
- Escopo recusa antes de criar artefatos de scan (dry-run também recusa).
- Novos coletores só com decisão registada (ADR + entrada no catálogo + fixture).
- Sem exploit automático (sqlmap, dalfox, ffuf, nuclei `-as` sem pin).
- Sem fallback de motor de busca: Shodan sem chave falha; Bing sem hits é `ok` com 0 resultados.

`settings.py` não está no caminho de `run_job`. Não o “corrija” em silêncio sem atualizar `config.py` e os testes.
