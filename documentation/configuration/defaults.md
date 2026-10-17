# Defaults

Valores do `TOOL_CATALOG` e constantes de `ai.py` / `config.py`.

| Parâmetro | Default | Tipo | Intervalo |
| --- | --- | --- | --- |
| threads (global) | 50 | int | 1–200 |
| amass.timeout_minutes | 5 | int | 1–200 |
| dnsx.threads | threads global | int | 1–200 |
| httpx.threads | global | int | 1–200 |
| httpx.timeout | 10 | int | 1–120 |
| httpx.retries | 2 | int | 0–10 |
| katana.threads | global | int | 1–200 |
| katana.depth | 3 | int | 1–10 |
| katana.timeout | 10 | int | 1–120 |
| gau.threads | global | int | 1–200 |
| js_httpx.threads | global (fallback httpx) | int | 1–200 |
| js_httpx.timeout | 8 | int | 1–120 |
| js_curl.timeout | 15 | int | 1–120 |
| nuclei.threads | global | int | 1–200 |
| nuclei.rate_limit | 150 | int | 1–200 no catálogo; YAML usa o mesmo helper 1–200 |
| nuclei.severity | `critical,high,medium` | string | passada ao binário |
| nuclei.tags | `cve,exposure,misconfiguration,takeover,tech,config,default-login` | string | passada ao binário |
| nuclei.timeout | 10 | int | 1–120 |
| nuclei.retries | 1 | int | 0–10 |
| HAR tamanho máximo | 32 MB | fixo | `MAX_HAR_BYTES` |
| HAR nuclei cap | 50 URLs | fixo | |
| HAR nuclei lote | 10 URLs | fixo | progresso `{done}/{total}` |
| HAR nuclei max-host-error | 3 | fixo | |
| Gemini retry | 4 tentativas, base 2 s | fixo | só HTTP 429/503 |
| `--verify` | `skip` | bool no spec | CNAME / HEAD / fingerprint |
| dorks.engine | bing | string | bing, google, duck, yahoo, ask, shodan |
| dorks.delay_s | 12 | int | 0–120 |
| dorks.max_queries | 24 | int | 1–80 |
| dorks.max_results | 20 | int | 1–100 |
| dorks.proxy | `-` (nenhum) | string | URL SOCKS/HTTP; `-` desliga |
| dorks.shodan_key | `-` | string | obrigatório se engine=shodan |
| JS head | 200 URLs | fixo no pipeline | não configurável |
| assetfinder | `timeout 180` | fixo | não configurável |
| crt.sh | curl 120 s | fixo | não configurável |
| modelo | `qwen2.5:7b` | fixo | outro digest/nome = `AiError` |
| num_ctx | 16384 | fixo | |
| num_predict | 2500 | fixo | |
| input budget | 12884 tokens | calculado | |
| classify output budget | 2000 tokens | fixo | fatia a classificação |
| chunk JS | 20000 chars | fixo | testes podem injetar |
| overlap | 400 chars | fixo | |
| Ollama timeout | 600 s | fixo | |
| keep_alive | 30m | fixo | |
| temperature | 0 | fixo | |
| Groq modelo | `openai/gpt-oss-120b` | env `RECON_GROQ_MODEL` | `--cloud` |
| Groq timeout | 600 s | fixo | |
| DeepSeek modelo | `deepseek-chat` | env `RECON_DEEPSEEK_MODEL` | `--cloud` |
| NVIDIA modelo | `openai/gpt-oss-20b` | env `RECON_NVIDIA_MODEL` | `--cloud` |
| Intervalo entre prompts | 2000 ms | `--ai-delay-ms` / UI | 10–600000 ms |
