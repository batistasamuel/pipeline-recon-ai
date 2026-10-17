# Política de escopo

## Allowlist de arquivo

`scope/scopes.txt`: um alvo por linha, `#` inicia comentário, casefold, espaços removidos. Comparação **exata** com o target (`domain_in_scope`). `example.com` não autoriza sozinho `www.example.com` no arquivo — o operador tem que listar o que quiser iniciar.

Arquivo ausente ⇒ código 2 interno ⇒ exit 3.

## Spec `in_scope` / `out_scope`

Além do arquivo, o job recusa se o alvo não estiver em `in_scope` (quando a lista não é vazia). Parsers usam `entry_covers_host`: um entry `example.com` cobre `www.example.com`; `out_scope` remove.

Nuclei exige httpx. Ferramenta desconhecida no JSON do `--job` é `JobError`.

## Validação do alvo

- Domínio: labels DNS, sem path, sem `../`.
- IPv4: cada octeto 0–255; porta 1–65535 se presente.
- Não há IPv6 no validador.

## Terceiros e redirects

httpx corre com `-follow-redirects`. O parser **só** guarda URLs cujo host passa em `url_allowed`. Um redirect para fora do escopo não deve entrar nas listas finais — **CONFIRMADO** no filtro pós-httpx. O pedido HTTP em si já pode ter seguido o redirect (comportamento do binário). HAR usa o mesmo `url_allowed`: host em `scopes.txt` mas fora do `in_scope` deste run não entra (0 URLs, 0 JS).

## Rate

`nuclei -rate-limit` default 150. Threads 1–200. Sem rate global do orquestrador.
