# Sequência JS → IA

```mermaid
sequenceDiagram
  participant R as analyze / analyze_run
  participant FS as js/content
  participant O as Ollama
  participant M as ai_manifest.jsonl
  participant DB as ai_result
  R->>FS: glob *.js único por SHA-256
  loop cada parte 20000 / overlap 400
    alt sem path " /... "
      R->>M: model_called=false routes=[]
    else
      R->>O: routes prompt
      alt transporte
        R->>M: error
        R-->>R: AiError (para o loop)
      else schema inválido
        R->>M: valid=false
        R-->>R: continua
      else JSON válido
        R->>R: só path com / e presente no trecho
        R->>M: valid=true
      end
    end
  end
  alt houve transporte
    R-->>R: não publica
  else findings reportáveis
    loop cada lote de classificação
      R->>O: classification prompt
    end
    R->>DB: items mesclados + routes se tudo válido
    R->>R: drafts/ por cluster reportável
  else sem findings reportáveis
    R->>DB: classification provider=none
  end
```

Com `--cloud` o participante O é o Google AI Studio (mesmo schema). Sem JS em disco a task de rotas grava `provider=none`.

Erro de schema numa parte **não** apaga o manifest; a publicação em `ai_result` só ocorre se o loop inteiro e a classificação passarem. Erro de transporte encerra. Resultado anterior publicado **não** é apagado nesse caso (`ai.py`).

Fluxo de erro da IA:

```mermaid
flowchart TD
  A[parte JS] --> B{transporte?}
  B -->|sim| C[manifest + raise]
  B -->|não| D{schema?}
  D -->|não| E[manifest inválido; próxima parte]
  D -->|sim| F[ground + merge]
  C --> G[ai_result anterior intacto]
  E --> H{mais partes?}
  F --> H
  H -->|sim| A
  H -->|não| I{reportável?}
  I -->|sim| J[classificação]
  J --> K{schema?}
  K -->|não| L[não publica este lote]
  K -->|sim| M[save_ai_results]
  I -->|não| M
```
