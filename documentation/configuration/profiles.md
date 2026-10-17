# Perfis Compose

## Serviços reais (`compose.yaml`)

| Serviço | Profile | Quando sobe |
| --- | --- | --- |
| `recon` | nenhum | `docker compose run recon …` |
| `ollama` | **nenhum** (estado atual) | `depends_on` de `recon` e `ui`; `docker compose up -d ollama` |
| `ui` | `ui` | `docker compose --profile ui up ui` |

O guia e `versions.lock` ainda descrevem “Ollama só com perfil `ai`”. Isso era verdade na fase 4. O arquivo Compose atual removeu `profiles: ["ai"]` para o scan completo alcançar o modelo sem flag extra. **Divergência documentada.**

## O que cada combinação sobe

```bash
docker compose run --rm recon example.com
# sobe ollama (depends_on) + container efémero recon

docker compose --profile ui up ui
# sobe ollama + ui em 127.0.0.1:8765
```

Não há perfil Compose `cloud`. `--cloud` não sobe serviço: usa as chaves no processo `recon`/`ui` (hoje Groq e NVIDIA). Consultar a IA na UI permanece no `ollama`. `recon ai RUN_ID` sem a flag usa Ollama; `recon ai RUN_ID --cloud` usa a nuvem.

## Isolamento de memória

`LLAMA_ARG_CACHE_RAM=0` no serviço ollama. Motivo no README da raiz: o cache default de 8 GB do llama.cpp derruba o runner quando várias partes seguem-se no Docker.
