# Escopo e não-objetivos

## No escopo (confirmado no código)

- Reconhecimento passivo/ativo das ferramentas do `TOOL_CATALOG` contra um alvo na allowlist (incluindo dorks em motor de busca e correlação `corr/…`).
- Persistência em SQLite + arquivos no volume `results/`.
- Retomada pela primeira fase que não está `ok`/`skip`.
- Interrupção (`recon stop` / POST stop) com process group.
- Diff contra o último run `ok` do mesmo alvo.
- IA: classificação só de findings reportáveis, extração de rotas de JS já baixado, task `tech` e rascunhos em `drafts/`. Ollama no default; `--cloud` opt-in.
- `--verify`: checagens passivas (CNAME, HEAD sem sessão, fingerprint); default `skip`.
- UI opcional (perfil `ui`) para iniciar scan, upload de HAR, Consultar a IA, ver fluxo, Candidatos, Rascunhos, apagar run parado e exportar PDF/Word.
- Alvo domínio ou IPv4[:PORT], incluindo loopback via `host.docker.internal`.

## Fora do escopo (planejado e não feito, ou recusado)

| Item | Fonte | Estado |
| --- | --- | --- |
| Gemini / Groq / OpenAI | Plano estratégico, estratégia | Google AI Studio opt-in (`--cloud`); Groq como fallback se o Gemini falhar. OpenAI ausente. |
| Webhook Telegram/Discord | PDF Fase 4, WP5 | `--webhook` exit 2. |
| Naabu, Nmap, FFuF, Gowitness | PDF Fase 3 | Ausentes do catálogo. |
| Celery, Redis, PostgreSQL | PDF Estratégia 3 | Um processo + SQLite. |
| FastAPI, Streamlit, React | PDF Estratégia 1 | UI é `http.server` + HTML estático. |
| Exploração / exploit | nenhum plano de ataque | Só recon, templates Nuclei e joins `corr/…`. Sem sqlmap, dalfox, ffuf. |
| Atualização automática de templates | doc do script (`nuclei -update-templates`) | Templates pinados no commit do lockfile. |

## Uso autorizado

O sistema só deve correr contra ativos com autorização escrita (programa de bug bounty ou contrato). `scopes.txt` e `in_scope` são controlos técnicos, não substituto jurídico. Ver [security/authorized-use.md](security/authorized-use.md).
