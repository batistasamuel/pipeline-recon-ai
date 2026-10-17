# Instalação

O host só precisa de Docker (e Compose v2). Ferramentas de recon **não** vão no PATH da máquina.

```bash
cd /caminho/do/clone   # raiz com compose.yaml
cp scope/scopes.txt.example scope/scopes.txt
# edite scopes.txt: um alvo autorizado por linha

PUID="$(id -u)" PGID="$(id -g)" docker compose build
PUID="$(id -u)" PGID="$(id -g)" docker compose run --rm recon --check
docker compose exec ollama ollama pull qwen2.5:7b
```

`--check` não consulta alvos. Confere checksums em `/opt/recon/bin-sha256.txt`, `-version`/`--version` das releases e o commit dos templates.

Chaves opcionais (ro em `/config`):

- `config/subfinder/provider-config.yaml`
- `config/amass/config.ini`
- `config/gau.toml`

`prepare_state` copia-as para `results/state/home`. Sem arquivos, as ferramentas usam fontes públicas.

`config/recon.yaml` é opcional; o exemplo está em `config/recon.yaml.example`.

`--cloud` lê as chaves do ambiente (veja `.env.example`: Groq e NVIDIA ativos). Não coloque as chaves em `/config` nem no spec. Consultar a IA na UI não usa essas chaves.
