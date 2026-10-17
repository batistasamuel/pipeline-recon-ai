#!/bin/bash
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck disable=SC1091
source "${ROOT}/scripts/common.sh"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

is_valid_domain "example.com" || fail "example.com deveria ser válido"
is_valid_domain "a.b.co" || fail "a.b.co deveria ser válido"
if is_valid_domain "../etc"; then fail "../etc deveria ser recusado"; fi
if is_valid_domain "example.com/admin"; then fail "barra deveria ser recusada"; fi
if is_valid_domain "example.com extra"; then fail "espaço deveria ser recusado"; fi
if is_valid_domain "-example.com"; then fail "hífen inicial deveria ser recusado"; fi
if is_valid_domain "example"; then fail "rótulo único deveria ser recusado"; fi

is_valid_threads 1 || fail "1 thread"
is_valid_threads 200 || fail "200 threads"
if is_valid_threads 0; then fail "0 threads"; fi
if is_valid_threads 201; then fail "201 threads"; fi
if is_valid_threads foo; then fail "threads texto"; fi

SCOPE=$(mktemp)
printf '%s\n' '# comentário' '' 'Example.COM' 'other.org # nota' > "$SCOPE"
domain_in_scope "example.com" "$SCOPE" || fail "escopo deveria aceitar example.com"
domain_in_scope "EXAMPLE.com" "$SCOPE" || fail "escopo deveria ignorar caixa"
domain_in_scope "other.org" "$SCOPE" || fail "escopo deveria aceitar other.org"
rc=0
domain_in_scope "evil.com" "$SCOPE" || rc=$?
[ "$rc" -eq 1 ] || fail "evil.com deveria estar fora, rc=${rc}"
rc=0
domain_in_scope "example.com" "/tmp/does-not-exist-recon-scope" || rc=$?
[ "$rc" -eq 2 ] || fail "arquivo ausente deveria ser rc=2, rc=${rc}"
rm -f "$SCOPE"

names=$(printf '%s\n' 'example.com' 'www.example.com' 'notexample.com' 'foo.example.com.evil.net' | keep_names example.com)
printf '%s\n' "$names" | grep -qx 'example.com' || fail "apex ausente: ${names}"
printf '%s\n' "$names" | grep -qx 'www.example.com' || fail "subdomínio ausente: ${names}"
if printf '%s\n' "$names" | grep -qx 'notexample.com'; then fail "notexample.com entrou"; fi
if printf '%s\n' "$names" | grep -q 'evil.net'; then fail "sufixo falso entrou: ${names}"; fi

urls=$(printf '%s\n' \
    'https://example.com/a' \
    'https://www.example.com/b?x=1' \
    'https://notexample.com/c' \
    'https://evil.com/example.com' | keep_urls example.com)
printf '%s\n' "$urls" | grep -q 'https://example.com/a' || fail "url do apex"
printf '%s\n' "$urls" | grep -q 'https://www.example.com/b?x=1' || fail "url do subdomínio"
if printf '%s\n' "$urls" | grep -q 'notexample.com'; then fail "url frouxa"; fi
if printf '%s\n' "$urls" | grep -q 'evil.com'; then fail "url de outro host"; fi

bash -n "${ROOT}/recon-claude-grok.sh"
bash -n "${ROOT}/scripts/entrypoint.sh"
bash -n "${ROOT}/scripts/fetch-tools.sh"
bash -n "${ROOT}/scripts/common.sh"

grep -q 'sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a' "${ROOT}/Dockerfile"
grep -q 'sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a' "${ROOT}/versions.lock"
grep -q 'sha256:3b77fc618ec235a1ab412de7737f120dd507c57e8d87de4cbb7994fb94275ed5' "${ROOT}/Dockerfile"
grep -q 'sha256:3b77fc618ec235a1ab412de7737f120dd507c57e8d87de4cbb7994fb94275ed5' "${ROOT}/versions.lock"

TMP=$(mktemp -d)
printf '%s\n' 'allowed.example' > "${TMP}/scopes.txt"
set +e
SCOPE_FILE="${TMP}/scopes.txt" bash "${ROOT}/recon-claude-grok.sh" '../x' 2>"${TMP}/err"
rc=$?
set -e
[ "$rc" -eq 2 ] || fail "domínio inválido deveria sair 2, saiu ${rc}"

set +e
SCOPE_FILE="${TMP}/scopes.txt" bash "${ROOT}/recon-claude-grok.sh" 'denied.example' 2>"${TMP}/err"
rc=$?
set -e
[ "$rc" -eq 3 ] || fail "fora do escopo deveria sair 3, saiu ${rc}: $(cat "${TMP}/err")"

set +e
SCOPE_FILE="${TMP}/scopes.txt" bash "${ROOT}/recon-claude-grok.sh" 'allowed.example' 'foo' 2>"${TMP}/err"
rc=$?
set -e
[ "$rc" -eq 2 ] || fail "threads inválidas deveriam sair 2, saiu ${rc}"

if [ -d "${ROOT}/recon_allowed.example_"* ]; then
    fail "o script criou diretório antes de recusar o alvo"
fi

set +e
SCOPE_FILE="${TMP}/scopes.txt" bash "${ROOT}/recon-claude-grok.sh" --from dns allowed.example 2>"${TMP}/err"
rc=$?
set -e
[ "$rc" -eq 2 ] || fail "--from sem --output deveria sair 2, saiu ${rc}"

rm -rf "$TMP"
echo "gates ok"
