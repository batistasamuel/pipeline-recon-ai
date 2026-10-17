# ADR-018 — Reportável versus nota; caderno e rascunho

Status: Accepted  
Evidência: `catalog.py`, `cluster.py`, `drafts.py`, `verify.py`, `ai.py` (`_classify`, `_analyze_drafts`), `export.py` (`--draft`)

## Contexto

O export do run era um caderno de operador: listava todos os findings. Num run com 144 `keep`, a maioria era `corr/har-not-crawled` — cobertura, não vulnerabilidade. A IA classificava cada URL e o ingest descartava CWE, curl e fingerprint.

## Decisão

1. **Catálogo** `template_id` → `reportable` | `note` | `coverage`. Nuclei fora do mapa: `reportable` se o JSON trouxer CWE/CVE; senão `note`.
2. **Dois artefatos.** O PDF/Word do run continua o caderno (inventário, clusters de cobertura, classificação). Envios de bounty saem de `drafts/<cluster_key>.md` e `recon export RUN --draft CLUSTER` (8 seções). Sem auto-submit.
3. **IA só no reportável.** Note e coverage não entram em `_classify`. Schema da classificação cobre só os ids enviados. Um rascunho por cluster reportável; título, CWE, passos e remediação vêm do catálogo + evidence. Cloud (`--cloud`) não manda host real no prompt de draft — o markdown é montado localmente.
4. **Verificação passiva opt-in** (`spec.verify` / `--verify`): DNS CNAME, HEAD sem sessão, fingerprint do segredo no disco. Default `skip`. Falha do check não inventa impacto.

## Motivo

Sem evidence o redator inventa CWE. Sem filtro a IA estoura timeout e trata cobertura como finding. Sem dois artefatos o operador cola o caderno no programa de bounty.

## Trade-off

Runs velhos com `class` vazio herdam a classe do catálogo quando o `template_id` é conhecido; templates desconhecidos viram `note`. Verificação nunca reusa cookie/Authorization do HAR.

## Revisitar se

O catálogo ficar defasado em relação aos templates Nuclei pinados; se o programa de bounty exigir um formato de seção diferente das 8 atuais.
