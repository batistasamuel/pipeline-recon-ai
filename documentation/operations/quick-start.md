# Início rápido

Uso só em ativos autorizados.

```bash
# 1. alvo em scope/scopes.txt
# 2. modelo local
docker compose up -d ollama
docker compose exec ollama ollama pull qwen2.5:7b

# 3. plano sem rede
PUID="$(id -u)" PGID="$(id -g)" docker compose run --rm recon example.com --dry-run

# 4. scan completo (coleta + dorks + correlate + IA)
PUID="$(id -u)" PGID="$(id -g)" docker compose run --rm recon example.com

# 5. HAR opcional (arquivo em ./scope; hosts têm que coincidir com in_scope)
PUID="$(id -u)" PGID="$(id -g)" docker compose run --rm recon example.com --har /scope/captura.har

# 6. nuvem opt-in (GEMINI_API_KEY no ambiente) e verify passivo
PUID="$(id -u)" PGID="$(id -g)" docker compose run --rm recon example.com --cloud --verify

# 7. reprocessar só a IA (Ollama; acrescente --cloud para Gemini)
PUID="$(id -u)" PGID="$(id -g)" docker compose run --rm recon ai RUN_ID

# 8. UI (opcional)
PUID="$(id -u)" PGID="$(id -g)" docker compose --profile ui up ui
# http://127.0.0.1:8765 — scan, HAR, Rascunhos, Consultar a IA, Candidatos
```

O comando tem que correr no diretório do `compose.yaml` deste projeto. Noutro Compose (por exemplo DVWA) o serviço `recon` não existe.

`--disable dorks` omite o motor de busca. Sem HAR a fase `har` fica `skip`. `recon ai RUN_ID` sem `--cloud` usa Ollama mesmo se o scan original tinha nuvem. `--cloud` usa os provedores ativos (Groq/NVIDIA); sem chave a fase `ai` falha.

Saída: `run_id: <hex>` e pasta `results/recon_<alvo>_<UTC>/`.
