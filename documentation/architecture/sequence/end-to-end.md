# Sequência end-to-end

```mermaid
sequenceDiagram
  actor Op as Operador
  participant C as Compose recon
  participant P as Pipeline
  participant DB as recon.db
  participant O as Ollama
  participant G as Google AI Studio
  Op->>C: docker compose run recon alvo
  C->>C: valid_target + scopes.txt
  C->>C: --check / verify-image
  C->>DB: new_run running
  C->>P: SCAN_PHASES
  loop cada fase de coleta
    P->>DB: upsert running
    P->>P: binário + parse
    P->>DB: upsert ok/warn/fail/skip
  end
  C->>DB: ingest assets/urls/Nuclei
  C->>C: fase har (skip sem arquivo)
  C->>C: fase correlate corr/…
  alt sem --cloud
    C->>O: chat qwen2.5:7b
    O-->>C: JSON
  else --cloud
    C->>G: generateContent (prompt mascarado; retry 429/503)
    G-->>C: JSON
  end
  C->>DB: ai_result + phase ai
  C->>DB: finish ok + delta
  C-->>Op: run_id
```

Falha de `--check`: exit 4, sem run. Fora de escopo: exit 3. Alvo inválido: exit 2. Fase crítica ou IA com erro de transporte: run `failed`, exit 1.
