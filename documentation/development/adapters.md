# Adapters (ferramentas reais)

Não há classes `Adapter`. Cada linha é uma invocação no `Pipeline` + parse.

| Nome | Versão pinada | Comando essencial | Input | Output | Parser | Fixture | Erro | Entidade |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| subfinder | 2.16.0 | `subfinder -d -silent` (+ `-all` se vazio) | domínio | `subfinder.txt` | `names_from_text` | `subfinder.txt` | retry `-all`; vazio total pode fail da fase | subdomain |
| amass | 4.2.0 | `amass enum -passive -timeout -tr 1.1.1.1,8.8.8.8 -d -dir` | domínio | `amass.raw` | names | `amass.txt` | code≠0 ⇒ fonte fail / warn | subdomain |
| assetfinder | 0.1.1 / `4e95d870` | `timeout 180 assetfinder --subs-only` | domínio | `assetfinder.txt` | names | (vazio no runner se não listado) | code≠0 ⇒ warn | subdomain |
| crtsh | n/a (curl) | `curl crt.sh/?q=%25.dominio&output=json` | domínio | `crtsh.json` | JSON `name_value` | `crtsh.json` | HTTP/JSON ⇒ fail fonte | subdomain |
| dnsx | 1.3.1 | `-l all_subs -silent -a -resp -threads` + probe wildcard | lista | `resolved.txt` | `parse_dns` / `hosts_without_wildcard` | `dns.txt` | code≠0 ⇒ fail fase | host |
| httpx | 1.12.0 | `-json -status-code -title -tech-detect -follow-redirects` | hosts | `httpx.json` | `classify_http` | `http.jsonl` | code≠0 ⇒ fail | live / 401 / 403 |
| katana | 1.7.0 | `-list live -d -silent -jc -timeout` | live | `katana.txt` | `urls_for_domain` | `urls.txt` | não falha a fase sozinho | url |
| gau | 2.2.4 | `gau dominio --subs --threads` | domínio | `gau.txt` | urls | — | idem | url |
| waybackurls | 0.1.0 | `waybackurls dominio` | domínio | `waybackurls.txt` | urls | — | idem | url |
| go-dork | 1.0.3 | `-q -e bing -p -s` por query gerada | alvo + fingerprints | `dorks/hits.txt` | `parse_hits` + httpx | injectado | code≠0 ⇒ fail fase | url |
| js_httpx | httpx | `-mc 200` nos 200 primeiros `.js` | js_urls | `js_live.txt` | linhas | httpx ramo | — | js |
| js_curl | curl Debian | `curl -fsSL --http1.1 --max-time` | cada live JS | `content/*.js` | `endpoints_in_js` | `app.js` | fail incrementa warn | endpoints.txt |
| nuclei | 3.11.1 + tpl `893122ff` | `-jsonl` http/dns/ssl, severity, tags, rate | live | `results.jsonl` | `nuclei_findings` | `nuclei.jsonl` | code≠0 ⇒ fail | finding |
| nuclei HAR | mesmo binário | `-jsonl` + `-max-host-error 3`, lotes de 10, cap 50 | URLs da captura | `har/` | ingest `har/…` | `test_har` / `test_phase3` | host 403 sai cedo | finding |

Apex vindo do Amass permanece se passar em `name_allowed`. Contagem Nuclei é do JSONL, não de `results.txt` (o Pipeline Python só pede `-jsonl`).
