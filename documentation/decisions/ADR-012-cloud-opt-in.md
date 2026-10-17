# ADR-012 — Cloud opt-in com pseudonimização

Status: Accepted  
Evidência: `--cloud` / `spec.cloud`; `recon_ai/pseudonym.py`; `recon_ai/gemini.py`; `recon_ai/groq.py`; `recon_ai/cloud.py`

## Decisão

O default continua Ollama local. A nuvem é **opt-in** (`--cloud`). Ativos: Groq e NVIDIA. Gemini e DeepSeek estão desligados por enquanto. `--cloud-mode sequential` ou `parallel`. `--ai-delay-ms` (padrão 2 s) vale para todas as IAs. Sem fallback para o Ollama.

Só sai da máquina o prompt **já mascarado**: hosts → `HOST_n`, IPs → `IP_n`, e-mails do alvo → `EMAIL_n`, segredos redactados. A tarefa não pode depender do valor original (ex.: lista de libs sem o domínio).

Categorias enviadas com `--cloud` e gate limpo:

- classificação de findings (`at=` com host trocado);
- excerpts de rotas em JS;
- lista deduplicada de `tech` (sem URL).

Não vão à nuvem: HAR cru, cookies, `js/secrets.jsonl`, o mapa `ai/pseudonym_map.json`, prompt livre de **Consultar a IA**.

Sem chave de provedor ativo, ou com identidade residual no prompt: a fase `ai` falha. Sem fallback silencioso para o Ollama. Em modo sequencial, a falha de um provedor ativo passa ao seguinte.

`recon ai RUN_ID` passa `cloud=False` ao `analyze_run` e portanto **não** herda `spec.cloud`. Para reprocessar na nuvem: `recon ai RUN_ID --cloud`.

As chaves são secrets de ambiente / GitHub (`DEV_GROQ_API_KEY` / `DEV_NVIDIA_API_KEY`, e os prefixos `HML_` / `PRD_`; Gemini/DeepSeek desligados no código por enquanto). Nunca ficam no git, no spec, no SQLite nem nos logs.
