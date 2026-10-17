# Otimização operacional

Já no código:

- 401/403 fora de Katana/Nuclei.
- Wildcard DNS.
- JS vivos limitados a 200.
- Dedup de JS na IA.
- Skip do modelo sem path literal.
- `LLAMA_ARG_CACHE_RAM=0`.
- Amass teto 5 min.
- HAR: `log.entries` uma a uma; nuclei da captura em lotes de 10 com `-max-host-error 3`.
- Classificação em lotes (`CLASSIFY_OUTPUT_BUDGET`); só reportável vai ao modelo.
- Gemini: retry só 429/503 (4 tentativas). Não troca para Ollama.

Alavancas do operador: `--disable gau/waybackurls`, baixar `katana.depth`, `nuclei.rate_limit`, `--threads`, `--cloud` (VRAM local ↓, latência da API), `--verify`. Sem paralelismo de IA.
