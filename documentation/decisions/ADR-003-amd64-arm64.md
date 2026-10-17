# ADR-003 — amd64 e arm64

Status: Accepted (prova CI pendente)  
Evidência: `TARGETARCH` no Dockerfile; README: “a prova da segunda arquitetura espera o primeiro CI”. Sem `.github/`.

## Decisão

Uma imagem multi-arch descrita no Dockerfile. assetfinder/waybackurls compilam nos dois archs.

## Gap

Segunda arch não verificada neste repo.
