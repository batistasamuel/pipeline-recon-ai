# Limitações

- Sem IPv6. Sem wildcard `*` no `scopes.txt` (match exato do alvo).
- CI no GitHub ainda é placeholder (`echo TODO lint/test`). A segunda arquitectura (arm64) não está comprovada no job `CI`.
- Git existe (`dev` / `hml` / `main`); ADRs iniciais reconstruídos não apontam hash.
- Plano Tático WP0–WP5 não existe como arquivo autônomo; só no guia v2.
- `settings.py` é código morto relativamente a `run_job`.
- Fase `urls` não falha se gau/katana/waybackurls saírem mal.
- JS: no máximo 200 URLs vivos; regex de endpoints só `/api/` e `/vN/`.
- IA: um modelo local pinado; sem paralelo no Ollama; vendor JS não é filtrado. Sem JS em `js/content` a task de rotas não chama o modelo (`provider=none`).
- Cloud é opt-in (`--cloud`): Groq e NVIDIA ativos; Gemini e DeepSeek desligados. Sem fallback silencioso para Ollama. `recon ai RUN_ID` sem `--cloud` usa Ollama mesmo se o scan original era nuvem.
- Webhook inexistente (`--webhook` exit 2).
- UI um scan de cada vez; sem autenticação (loopback). Apagar run recusa status `running`.
- Dorks dependem do motor de busca; 0 hits é `ok` se `go-dork` sair 0. O banner do binário pode mostrar v1.0.1 embora o asset pinado seja 1.0.3.
- HAR só conta hosts do `in_scope` deste run; `scopes.txt` sozinho não chega.
- Engine Bash não passa pelas mesmas regras de spec/IA que o Python.
- Templates Nuclei não se actualizam sozinhos.
- Números de tempo/tokens de runs reais não são testes.
