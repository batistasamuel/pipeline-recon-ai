# Visão geral

## Para que serve

Recon AI automatiza o reconhecimento autorizado (bug bounty / pentest com contrato) a partir de um alvo em allowlist. Coleta subdomínios, resolve DNS, classifica HTTP, junta URLs, corre dorks no motor de busca, baixa JavaScript, corre Nuclei, opcionalmente ingere um HAR do browser, correlaciona sinais fracos em candidatos `corr/…`, classifica só findings **reportáveis** e tenta extrair rotas de JS. O modelo padrão é local (`qwen2.5:7b`); Google AI Studio é opt-in (`--cloud`). Rascunhos de bounty saem em `drafts/`, separados do caderno PDF/Word.

## Para quem

Operador que já tem Docker e um alvo autorizado. Mantenedor que precisa reproduzir a imagem, o store e a fase de IA.

## Problema que resolve

O script Bash `recon-claude-grok.sh` já encadeava as mesmas ferramentas, mas dependia do PATH do host, aceitava `@latest` na documentação de instalação e não persistia histórico estruturado. O sistema atual isola as ferramentas numa imagem pinada, recusa alvo fora do escopo, grava SQLite + artefatos e acrescenta IA local com schema.

## O que entra

- Alvo: domínio ou IPv4 com porta opcional (`valid_target` em `recon_ai/scope.py`).
- Allowlist em `/scope/scopes.txt` (obrigatória).
- Spec opcional: `in_scope`, `out_scope`, ferramentas ligadas/desligadas, threads e parâmetros do catálogo (incluindo `dorks`).
- HAR opcional (arquivo ≤ 32 MB, `log.entries` lidas uma a uma, hosts filtrados por `url_allowed`).
- `--cloud` / `--verify` no spec do run.
- Chaves de API opcionais em `/config` (somente leitura). `SHODAN_API_KEY` só se `engine=shodan`. Chaves de nuvem (`GROQ_API_KEY`, `NVIDIA_API_KEY`, …) só com `--cloud`.

## O que sai

- Diretório `results/recon_<alvo>_<UTC>/` com fases, logs, listas, `resumo.txt`, `urls/provenance.tsv`, `live/fingerprints.jsonl`, `corr/findings.jsonl`, `corr/checklist.txt`, `clusters.json` e `drafts/*.md`.
- Linha em `results/recon.db` (`run`, `phase`, `asset`, `url`, `finding` com `kind`/`class`/`cluster_key`/`evidence`, `delta_*`, `ai_result`, `run_spec`, `run_control`). Findings `har/…` e `corr/…` usam o mesmo schema que Nuclei.
- `ai_manifest.jsonl` no diretório do run quando a fase `ai` corre.
- Export PDF/Word do caderno (`recon export`) e de um rascunho (`--draft CLUSTER`); UI com bloco Rascunhos.

## O que está fora do núcleo

Não há Celery, Redis, FastAPI, Streamlit ou React. Não há Naabu, Nmap, FFuF, Gowitness, Chaos, nem Shodan como coletor autônomo (só `go-dork -e shodan` com chave). Não há webhook nem exploit automático. `--cloud` é opt-in (Groq e NVIDIA ativos; Gemini e DeepSeek desligados por enquanto); o default continua Ollama local. Sem `--cloud` os dados do alvo não saem para API de modelo. O Bash permanece na imagem só se `RECON_ENGINE=bash`.

Evidência: `compose.yaml`, `recon_ai/pipeline.py`, `recon_ai/cli.py`, `recon_ai/ai.py`, `recon_ai/gemini.py`, `recon_ai/catalog.py`, `recon_ai/drafts.py`, `recon_ai/dorks.py`, `recon_ai/correlate.py`, testes `test_phase2`–`test_phase7`, `test_har`, `test_dorks`, `test_correlate`, `test_pseudonym`, `test_catalog`, `test_drafts`.
