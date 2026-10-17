# Impacto de parâmetros

Não há benchmarks medidos neste repositório. Colunas de tempo/CPU/RAM/VRAM sem evidência ficam “não medido”.

| Parâmetro | Efeito funcional | Tokens | Tempo | CPU/RAM/VRAM | Cobertura / precisão | Trade-off |
| --- | --- | --- | --- | --- | --- | --- |
| threads ↑ | mais concorrência dnsx/httpx/katana/gau/nuclei | nenhum direto | tende a baixar wall-clock | CPU/rede ↑; VRAM nenhum | mais probes no mesmo intervalo | risco de rate-limit no alvo |
| threads ↓ | menos paralelo | — | ↑ | ↓ | pode perder janela em fontes lentas | mais educado com o alvo |
| amass.timeout_minutes ↑ | amass passivo corre mais | — | ↑ até o teto | CPU/rede amass | mais nomes possíveis | run mais longo; 5 min é o default |
| httpx.timeout/retries ↑ | menos falsos mortos | — | ↑ | ↑ | live mais completo | Nuclei/Katana em cima de mais hosts |
| katana.depth ↑ | crawler mais fundo | mais JS/URLs → mais partes de IA | ↑↑ | ↑ | mais superfície | ruído histórico menor que gau, mas ainda cresce |
| dorks.delay_s / max_queries | ritmo e teto de queries ao motor de busca | mais URLs se houver hits | ↑ com delay | IP do operador | paths indexados | ToS/ban; `--disable dorks` para omitir |
| nuclei.rate_limit ↑ | mais req/s | — | ↓ | rede no alvo ↑ | mesma precisão de template | pode cair WAF |
| nuclei.severity/tags | muda o conjunto de templates | mais findings → mais lotes de classificação | ↑ se mais matches | — | cobertura de vulns | ruído de medium/info |
| HAR nuclei lote 10 / max-host-error 3 | nuclei da captura não segura 50 URLs numa chamada só | — | ↓ em host 403 | rede no alvo ↓ | mesma cap 50 | host que responde erro sai mais cedo |
| `--cloud` | classificação/rotas/tech/draft no Google AI Studio | prompt mascarado | depende da API | VRAM local ↓ | mesma schema | HTTP 503 ainda pode falhar a fase após 4 tentativas |
| `--verify` | anota `evidence.verified` | nenhum no modelo | DNS/HEAD extra | rede no alvo ↑ | não inventa impacto | default `skip`; sem cookie do HAR |
| desligar gau/waybackurls | menos URLs de arquivo | menos JS falso-histórico | ↓ | ↓ | perde histórico; ganha sinal do host vivo | no DVWA, gau puxou milhares de URLs alheias |
| desligar nuclei | sem findings | classificação vazia, sem chamada se também sem JS | ↓ | ↓ | zero triagem Nuclei | |
| JS head=200 (fixo) | no máximo 200 JS vivos | teto de partes | teto | disco | pode omitir JS além dos 200 | não há flag |
| chunk 20k / overlap 400 | mais partes em arquivos grandes | overlap duplica ~400 chars | mais chamadas | RAM do runner + VRAM por chamada | menos risco de estourar ctx | custo de tempo (65 partes num run observado) |
| LLAMA_ARG_CACHE_RAM=0 | evita cache 8 GB no Docker | — | possível perda de cache de prompt | RAM do ollama ↓ | qualidade do modelo inalterada | |
| num_ctx 16384 | teto do runtime | input efetivo 12884 | — | VRAM/RAM do 7B | partes longas `over_budget` no manifest | não é configurável em runtime |

Alterar o modelo para outro que não comece por `qwen2.5:7b` falha a fase (`AiError` “Modelo divergente”).
