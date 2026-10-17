# Como contribuir

Único maintainer: [@batistasamuel](https://github.com/batistasamuel). Fluxo curto para não quebrar DEV/HML/PRD.

## Branches

- Trabalho diário a partir de `dev`: `feature/<assunto>`, `fix/<assunto>`, `chore/<assunto>`
- Emergência de produção a partir de `main`: `hotfix/<assunto>`
- Retorno do hotfix: `backport/<assunto>` → PRs para `hml` e `dev`

Não dê push em `dev`, `hml` ou `main`. Abra um Pull Request.

## Clone novo

```bash
./scripts/setup-hooks.sh
```

## Pull Request

Use o template. Antes do merge:

1. CI verde (quando deixar de ser placeholder)
2. Promotion Guard verde — se estiver vermelho, o caminho de branches está errado
3. Método de merge: **squash** para `dev`; **merge commit** para `hml` e `main`
4. Changelog atualizado quando a mudança for visível

Mensagens de commit em inglês, [Conventional Commits](https://www.conventionalcommits.org/). Documentação em português (BR).

No plano Free, nenhum desses itens é proteção do GitHub. São convenções. O merge continua possível com checks vermelhos — não faça isso.
