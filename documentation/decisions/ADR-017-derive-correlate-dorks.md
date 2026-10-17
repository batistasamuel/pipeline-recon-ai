# ADR-017 — Derive, correlate e dorks executados no scan

Status: Accepted  
Evidência: `derive.py`, `correlate.py`, `dorks.py`, `har.py`, `phases.py`, `versions.lock` (`GODORK_VERSION=1.0.3`), PR #6 (HAR), PR #7 (joins + dorks)

## Contexto

A coleta já cobria ~70 % do recon de bug bounty (subs, HTTP, URLs, JS, Nuclei). O valor em falta era juntar sinais fracos e consultar o motor de busca **com queries deste run**, não acrescentar mais enumeradores nem exploit automático.

## Decisão

1. **Derive** no pipeline: `live/fingerprints.jsonl`, `urls/provenance.tsv`, buckets regex em `urls/buckets/`, `js/secrets.jsonl` redactado (só para join).
2. **HAR opcional** (`--har` / upload): hosts filtrados por `url_allowed`; findings `har/…`; sem arquivo a fase é `skip`. Teto 32 MB.
3. **Correlate** depois de `har` e antes da IA: joins A∧B em `corr/findings.jsonl` + `corr/checklist.txt`. Schema de finding inalterado. A IA classifica também `corr/…`.
4. **Dorks no `SCAN_PHASES`** (entre `urls` e `js`): gerar queries, executar `go-dork` 1.0.3 (Bing, delay 12 s, máx. 24 queries), filtrar escopo, httpx no URL concreto, merge + provenance `dorks`. `--disable dorks` → `skip`. `engine=shodan` sem chave → `fail` (sem fallback de motor).
5. Sem sqlmap, dalfox, ffuf ou nuclei sem pin.

## Motivo

Joins e dorks usam artefatos que o run já tem. Executar dorks (não só gerar) fecha o ciclo: hits entram no mesmo SQLite e na mesma IA. O motor é pinado; a allowlist continua a ser o corte.

## Trade-off

Dorks dependem do motor de busca (0 hits pode ser `ok`). HAR de outro host autorizado mas fora do `in_scope` deste run dá 0 URLs. Scan sem `go-dork` na imagem falha a fase. Uma IA no fim, não por fase.

## Revisitar se

O motor pinado deixar de ser fiável; se o operador precisar de outro engine default; se regras `corr/` gerarem ruído demais sem segundo sinal.
