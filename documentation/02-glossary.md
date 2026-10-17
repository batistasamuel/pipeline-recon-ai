# Glossário

| Termo | Significado neste projeto |
| --- | --- |
| Alvo / target | Domínio (`example.com`) ou IPv4 com porta opcional (`127.0.0.1:8080`). |
| Escopo | Allowlist em `scope/scopes.txt`. Sem arquivo, exit 3. Spec ainda pode restringir com `in_scope` / `out_scope`. |
| Run | Uma execução persistida. `run.id` é UUID hex. |
| Fase | Uma etapa de `PHASES`: `subdomains`, `dns`, `http`, `urls`, `dorks`, `js`, `nuclei`, `report`, `har`, `correlate`, `ai`. `SCAN_PHASES` exclui `har`, `correlate` e `ai`. |
| Status de fase | `running`, `ok`, `warn`, `skip`, `fail`, `cancelled`. `ok` e `skip` contam como concluídos no resume. |
| Status do run | `running`, `ok`, `failed`, `cancelled`. |
| Adapter | Chamada a um binário pinado + parser em `recon_ai/parse.py`. Não há pacote `adapters/`; o catálogo está em `recon_ai/job.py`. |
| Job spec | Mapa JSON/YAML com `target`, `threads`, `in_scope`, `out_scope`, `tools`. |
| Artefato | Arquivo no diretório do run (`all_subs.txt`, `results.jsonl`, `phases.tsv`, …). Fonte da verdade das listas; o SQLite é a memória entre runs. |
| Finding | Linha do JSONL do Nuclei, `har/findings.jsonl` (`har/…`) ou `corr/findings.jsonl` (`corr/…`) ingerida em `finding`. Colunas `kind`, `class`, `cluster_key`, `evidence`. |
| Classe | `reportable` (vai à IA e a `drafts/`), `note` ou `coverage` (só caderno / `clusters.json`). |
| Cluster | Grupo de findings com a mesma `cluster_key` (template + host, ou regra do catálogo). |
| Candidato | Finding `corr/…` nascido de um join (dois sinais). Não é CVE confirmada. |
| Classificação | Decisão da IA por finding **reportável**: `keep`, `review`, `false_positive`. |
| Rascunho | Markdown em `drafts/<cluster_key>.md` (8 seções) + `drafts/index.json`. Status `draft` \| `ready` \| `rejected`. |
| Verificação | `--verify`: CNAME, HEAD sem sessão, fingerprint no disco. `evidence.verified` = `skip` \| `yes` \| `no`. |
| Rota | Path HTTP começando com `/` extraído de JS (regex e/ou modelo). |
| Manifest | `ai_manifest.jsonl`: uma linha por parte de JS ou por lote de classificação. |
| Delta | Diff contra o último run `ok` do mesmo alvo. |
| Perfil Compose | Só `ui` existe hoje. `ollama` não tem profile. |
| Ollama | Runtime local em `http://ollama:11434`. Modelo pinado `qwen2.5:7b`. |
| Literal host | IPv4 (com ou sem porta). Atalho: não chama OSINT de subdomínio. |
| Loopback alias | `RECON_LOOPBACK_HOST` (Compose: `host.docker.internal`) para o container alcançar DVWA no host. |
| Dork | Query `site:{alvo}` gerada deste run (`dorks/queries.txt`) e executada pelo `go-dork` pinado. |
| Provenance | `urls/provenance.tsv`: origem de cada URL (`katana`, `gau`, `waybackurls`, `har`, `dorks`). |
| Fingerprint HTTP | Linha de `live/fingerprints.jsonl`: `url`, `status_code`, `title`, `tech`. |
| Checklist BB | Texto em `corr/checklist.txt` (401, buckets IDOR, HAR-only, secrets join, delta). Não é exploit. |
| Lockfile | `versions.lock`: versões e digests. `--check` recusa divergência (exit 4). |
| Engine | `RECON_ENGINE=python` (padrão) ou `bash` (script legado). |
| Cloud | Opt-in `--cloud`: Google AI Studio com prompt pseudonimizado. Sem fallback silencioso para Ollama. |
