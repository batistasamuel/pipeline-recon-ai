#!/usr/bin/env bash
# Configura hooks versionados neste clone (core.hooksPath = .githooks).
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
chmod +x "$root/.githooks/"*
git -C "$root" config core.hooksPath .githooks
echo "Guardrail local ativo: core.hooksPath=.githooks"
echo "Push direto em dev, hml e main fica bloqueado neste clone."
echo "Bypass consciente: ALLOW_PROTECTED_PUSH=1 git push …"
