#!/bin/bash
# Funções compartilhadas pelo entrypoint, pelo script e pelos testes.

is_valid_domain() {
    local domain="$1"
    [[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]
}

is_valid_threads() {
    local threads="$1"
    [[ "$threads" =~ ^[0-9]+$ ]] || return 1
    [ "$threads" -ge 1 ] && [ "$threads" -le 200 ]
}

# 0 = presente, 1 = arquivo ok e domínio ausente, 2 = arquivo ausente ou ilegível
domain_in_scope() {
    local domain="$1"
    local file="$2"
    local line trimmed

    [ -f "$file" ] && [ -r "$file" ] || return 2
    domain=$(printf '%s' "$domain" | tr '[:upper:]' '[:lower:]')

    while IFS= read -r line || [ -n "$line" ]; do
        trimmed=${line%%#*}
        trimmed=$(printf '%s' "$trimmed" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
        [ -z "$trimmed" ] && continue
        if [ "$trimmed" = "$domain" ]; then
            return 0
        fi
    done < "$file"
    return 1
}

escape_domain() {
    printf '%s' "$1" | sed 's/[.[\*^$()+?{|\\]/\\&/g'
}

strip_ansi() {
    sed -E 's/\x1b\[[0-9;]*[mK]//g'
}

# Emite nomes que são o domínio ou um rótulo abaixo dele.
keep_names() {
    local domain
    domain=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    awk -v d="$domain" '
        {
            n = split(tolower($0), parts, /[^a-z0-9._-]+/)
            for (i = 1; i <= n; i++) {
                t = parts[i]
                if (t == d || (length(t) > length(d) && substr(t, length(t) - length(d)) == "." d)) {
                    print t
                }
            }
        }
    '
}

# Emite URLs cujo host é o domínio ou um rótulo abaixo dele.
keep_urls() {
    local domain
    domain=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    awk -v d="$domain" '
        tolower($0) ~ /^https?:\/\// {
            line = tolower($0)
            sub(/^https?:\/\//, "", line)
            host = line
            sub(/[\/:?#].*/, "", host)
            if (host == d || (length(host) > length(d) && substr(host, length(host) - length(d)) == "." d)) {
                print $0
            }
        }
    '
}
