# Uso autorizado

Este software é para programas de bug bounty e testes com autorização escrita. Allowlist técnica (`scopes.txt`) **não** substitui o contrato.

Não use para:

- ativos sem permissão;
- exploração além do que os templates Nuclei já fazem;
- envio de dados do alvo a APIs de nuvem **sem** `--cloud` e **sem** o gate de pseudonimização (hosts/IPs/e-mails do alvo no prompt). Com `--cloud`, HAR cru, cookies e `js/secrets.jsonl` continuam locais.

Dorking consulta um motor de busca (Bing por padrão) com o `site:` do alvo. Isso é passivo relativamente ao alvo, mas está sujeito aos termos do motor; delay e proxy são obrigação operacional. O httpx nos hits é ativo **só** em URLs já filtradas por `scopes.txt` / `in_scope`.

A UI escuta só `127.0.0.1:8765` no Compose. Não a publique na internet sem outro controlo.
