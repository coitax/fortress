#!/usr/bin/env bash
# Per-connection DevTools gate. docker-entrypoint.sh runs this once for every
# client of the published port, with the client socket on stdin/stdout.
#
# The first request on a connection must carry the debug token, either as
# `Authorization: Bearer <token>` or, on a /devtools/ websocket path, as the
# only query parameter (`/devtools/browser/<id>?token=<token>`). Until it does,
# nothing is sent to Chromium: the client gets a 401 and the connection closes.
# Once it does, the connection is spliced to Chromium's loopback port as is.
set -u
export LC_ALL=C

INTERNAL="${TILION_INTERNAL_PORT:?}"
EXPECTED="${TILION_CDP_TOKEN_SHA256:?}"
MAX_LINE=8192
MAX_HEADERS=100
DEADLINE=$((SECONDS + 10))

deny() {
  local body="$2"$'\n'
  printf 'HTTP/1.1 %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nWWW-Authenticate: Bearer\r\nConnection: close\r\n\r\n%s' \
    "$1" "${#body}" "$body" 2>/dev/null
  exit 0
}

# Reads one CRLF-terminated line into $line, without the CRLF.
next_line() {
  local left=$((DEADLINE - SECONDS))
  ((left > 0)) || return 1
  IFS= read -r -t "$left" -n "$MAX_LINE" line || return 1
  [[ "$line" == *$'\r' ]] || return 1
  line="${line%$'\r'}"
}

next_line || deny "400 Bad Request" "malformed request"
[[ "$line" =~ ^([A-Z]+)\ ([^ ]+)\ (HTTP/1\.[01])$ ]] || deny "400 Bad Request" "malformed request"
method="${BASH_REMATCH[1]}"
target="${BASH_REMATCH[2]}"
version="${BASH_REMATCH[3]}"

presented=""
if [[ "$target" =~ ^(/devtools/[^?]*)\?token=([^\&]+)$ ]]; then
  target="${BASH_REMATCH[1]}"
  presented="${BASH_REMATCH[2]}"
fi

headers=()
while :; do
  next_line || deny "400 Bad Request" "malformed request"
  [[ -z "$line" ]] && break
  ((${#headers[@]} < MAX_HEADERS)) || deny "431 Request Header Fields Too Large" "too many headers"
  if [[ "$line" =~ ^[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]:[\ $'\t']*(.*)$ ]]; then
    if [[ "${BASH_REMATCH[1]}" =~ ^[Bb][Ee][Aa][Rr][Ee][Rr]\ +([^\ $'\t']+)[\ $'\t']*$ ]]; then
      presented="${BASH_REMATCH[1]}"
    fi
    continue
  fi
  headers+=("$line")
done

# Compare digests so the comparison time says nothing about the token.
if [[ -z "$presented" ]] || [[ "$(printf '%s' "$presented" | sha256sum | cut -d' ' -f1)" != "$EXPECTED" ]]; then
  deny "401 Unauthorized" "DevTools token required"
fi

exec 3<>"/dev/tcp/127.0.0.1/$INTERNAL" || deny "502 Bad Gateway" "DevTools is not up"
{
  printf '%s %s %s\r\n' "$method" "$target" "$version"
  for h in "${headers[@]}"; do printf '%s\r\n' "$h"; done
  printf '\r\n'
} >&3
exec socat STDIO FD:3
