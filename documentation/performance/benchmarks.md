# Benchmarks

Não existe suíte de performance no repositório. Números abaixo são **observados em sessão**, não testes.

| Run | Alvo | Observação |
| --- | --- | --- |
| hash omitido | alvo autorizado (anônimo) | coleta ~40 min (urls 759 s, nuclei 1264 s); IA ~16 min; 61569 URLs, 48 JS, 12 findings |
| `f6219912…` | 127.0.0.1:8080 | 1 live, ~3552 URLs (ruído gau), 1 finding medium |
| hash omitido | alvo autorizado (anônimo) | HAR: nuclei sem sessão ~38 min no mesmo host 403 (cap 50, antes dos lotes de 10) |
| hash omitido | alvo autorizado (anônimo) | fase `ai` com `--cloud` e reprocessamento local (`recon ai`) ~232 s, 5 classificações, 0 rotas (`js/content` vazio) |

Não há comparativo amd64 vs arm64. Não há tokens/s oficiais do modelo neste repo.
