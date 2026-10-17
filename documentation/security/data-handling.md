# Tratamento de dados

| Dado | Onde fica | Sai da máquina? |
| --- | --- | --- |
| Listas de hosts/URLs/JS | `results/` no volume | só se o operador copiar |
| Findings | SQLite + JSONL | local |
| Corpos JS | `js/content/` | enviados ao **Ollama local** (rede Compose) |
| Prompt de classificação | Ollama local; com `--cloud`, Gemini e, se falhar, Groq após pseudonimizar | ids, severity, template; URL com host trocado na nuvem |
| Secrets de API | `/config` ro → cópia em `state/home` | usadas pelas ferramentas para fontes OSINT (subfinder/amass/gau), se o operador as pôs |
| Queries de dork | `dorks/queries.txt` | enviadas ao motor de busca (`go-dork`; Bing por padrão). Não vão ao Ollama. |
| HAR | cópia no run se o operador enviou | local; só hosts `url_allowed` |
| `js/secrets.jsonl` | redactado; só para join | não vira finding sozinho; não vai ao prompt |
| Cloud | Groq e NVIDIA só com `--cloud` (Gemini/DeepSeek desligados) | prompt mascarado; chaves no ambiente |
| Mapa de tokens | `ai/pseudonym_map.json` no run | local; não vai no POST |
| Rascunhos | `drafts/*.md` no volume | local; `--cloud` não manda host real no prompt de draft |

`.gitignore` ignora `results/*` (exceto `.gitkeep`), `scope/scopes.txt` e `.env`.

No Ollama local o JS baixado vai ao modelo se passar o filtro de path (rede Compose). Com `--cloud`, o mesmo JS só sai depois de trocar hosts/IPs e redactar segredos; se a identidade sobrar, a fase falha.
