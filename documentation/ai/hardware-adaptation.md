# Hardware e adaptação

## O que o plano dizia

A estratégia (PDF) dimensionou Qwen 2.5 7B em Mac com 16 GB unified memory (~4,5–6 GB). Separar o container de IA da coleta era para não somar Nuclei e o modelo na mesma pressão de RAM.

## O que o código faz

- Dois serviços: `recon` (ferramentas) e `ollama` (modelo). **CONFIRMADO.**
- Já não é “Ollama só quando o operador pede `--profile ai`”: o scan completo depende do serviço. **CONFIRMADO** em `compose.yaml`.
- Sem GPU obrigatória. Ollama no Docker Desktop usa o que o runtime oferecer. **Não medido** neste repo se Metal/CUDA está ativo. `--cloud` tira inferência da máquina (Google AI Studio); o serviço `ollama` continua no Compose para Consultar a IA.
- `LLAMA_ARG_CACHE_RAM=0` reduz RAM do processo ollama. **CONFIRMADO.**
- Sem perfis `cpu` / `gpu` / `lowmem`. Sem detecção automática de RAM. Adaptação é manual (não subir UI+scan+outras VMs ao mesmo tempo).

## Requisitos (inferidos + observados)

| Recurso | Mínimo inferido | Recomendado inferido | Evidência |
| --- | --- | --- | --- |
| CPU | 4 núcleos | 8+ | não medido |
| RAM host | 16 GB (plano) | 16–32 GB | plano; modelo 4,7 GB + ferramentas + OS |
| GPU / VRAM | 0 | Apple Silicon ou NVIDIA | não medido |
| Disco | ~10 GB imagem + 4,7 GB modelo + results | SSD | lockfile / ollama list |
| OS | Docker no host | Docker Desktop macOS ou Linux | README |

amd64 e arm64: descritos no Dockerfile; segunda arch sem CI. Execução sem GPU: suportada pelo Ollama; latência maior — **não medido**.
