# Sequência da coleta

```mermaid
sequenceDiagram
  participant P as Pipeline
  participant SF as subfinder
  participant AM as amass
  participant AF as assetfinder
  participant CRT as crt.sh
  participant DX as dnsx
  participant HX as httpx
  participant KT as katana
  participant GU as gau/waybackurls
  participant N as nuclei
  P->>SF: -d alvo -silent
  P->>AM: enum -passive -timeout N
  P->>AF: timeout 180 --subs-only
  P->>CRT: curl JSON
  P->>P: all_subs.txt
  alt lista vazia
    P-->>P: fail nenhum subdomínio
  end
  P->>DX: -l all_subs -a -resp
  P->>DX: wildcard-probe
  P->>HX: -json live
  P->>KT: -list live_hosts
  P->>GU: histórico
  P->>P: go-dork queries + httpx nos hits
  P->>HX: js 200 (até 200)
  P->>P: curl js/content
  P->>N: -jsonl http/dns/ssl
  P->>P: resumo.txt
```

Alvo literal: subdomains e dns não chamam OSINT; escrevem o próprio host (`test_phase3`). Uma fonte de subdomínio que falha incrementa o contador e a fase fica `warn` se ainda houver nomes.

Depois desta coleta (fora deste diagrama): fase `har` opcional (`iter_har_entries` + nuclei em lotes), `correlate`, depois `ai`.
