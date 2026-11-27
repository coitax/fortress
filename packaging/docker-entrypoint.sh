#!/usr/bin/env bash
# Chromium 151 binds the DevTools endpoint to 127.0.0.1 only (it ignores
# --remote-debugging-address). Since `docker -p` forwards to the container's
# veth IP rather than its localhost, we run Chrome on an internal localhost
# port and bridge 0.0.0.0:9222 -> 127.0.0.1:9223 with socat. CDP clients that
# resolve the endpoint by URL (Playwright connect_over_cdp, Puppeteer connect)
# work transparently through the bridge.
#
# The bridge connects to Chrome from inside the container, so Chrome sees every
# client as loopback. Each connection therefore goes through devtools-gate.sh,
# which requires the debug token before anything reaches Chrome. Set it with
# TILION_CDP_TOKEN or TILION_CDP_TOKEN_FILE; if neither is set, a random token
# is generated and printed to the container log.
set -e
INTERNAL=9223
EXTERNAL=9222
GATE="$(dirname "$0")/devtools-gate.sh"

TOKEN="${TILION_CDP_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -n "${TILION_CDP_TOKEN_FILE:-}" ]; then
  TOKEN="$(tr -d '\r\n' < "$TILION_CDP_TOKEN_FILE")"
fi
unset TILION_CDP_TOKEN TILION_CDP_TOKEN_FILE
if [ -z "$TOKEN" ]; then
  TOKEN="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  echo "[fortress] TILION_CDP_TOKEN not set; generated DevTools token: $TOKEN" >&2
fi
if ! [[ "$TOKEN" =~ ^[A-Za-z0-9._~-]{16,}$ ]]; then
  echo "[fortress] TILION_CDP_TOKEN must be at least 16 characters of [A-Za-z0-9._~-]" >&2
  exit 1
fi
echo "[fortress] DevTools on :$EXTERNAL requires 'Authorization: Bearer <token>'" >&2
TILION_CDP_TOKEN_SHA256="$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)"
unset TOKEN

/opt/tilion/tilion \
  --headless=new \
  --no-sandbox \
  --enable-unsafe-swiftshader \
  --remote-debugging-port="$INTERNAL" \
  --user-data-dir=/tmp/tilion-profile \
  "$@" &
CHROME_PID=$!
trap 'kill "$CHROME_PID" 2>/dev/null || true' TERM INT

# Wait for Chrome's internal DevTools port to come up.
for _ in $(seq 1 80); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$INTERNAL") 2>/dev/null; then exec 3>&-; break; fi
  sleep 0.5
done

export TILION_INTERNAL_PORT="$INTERNAL" TILION_CDP_TOKEN_SHA256
exec socat TCP-LISTEN:"$EXTERNAL",fork,reuseaddr EXEC:"$GATE",nofork
