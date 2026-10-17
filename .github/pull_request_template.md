## O que mudou

<!-- Resumo em 2–5 linhas. -->

## Tipo de mudança

- [ ] `feature` (nova funcionalidade)
- [ ] `fix` (correção)
- [ ] `chore` (manutenção)
- [ ] `hotfix` (emergência a partir de `main`)
- [ ] `promotion` (`dev` → `hml` ou `hml` → `main`)
- [ ] `backport` (hotfix voltando para `hml` e/ou `dev`)

## Checklist

- [ ] Testes locais (ou justificativa se ainda não houver suíte no CI)
- [ ] `CHANGELOG.md` atualizado quando couber
- [ ] Método de merge correto para o **destino**:
  - squash se o destino for `dev` (feature/fix/chore)
  - merge commit se o destino for `hml` ou `main`
- [ ] Resultado do **CI** conferido
- [ ] Resultado do **Promotion Guard** conferido (check vermelho = não mesclar; no plano Free o GitHub não bloqueia)
- [ ] Impacto no ambiente de destino (DEV / HML / PRD) entendido
