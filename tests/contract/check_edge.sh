#!/usr/bin/env bash
# Contract checks against the real Cloudflare edge in front of a Home Assistant hostname.
#
# Run from a shell with:
#   HA_HOST=ha.example.com          hostname the integration manages
#   CF_JWT=<application token>      copy the CF_Authorization cookie from browser devtools
#   HA_TOKEN=<long-lived token>     a Home Assistant long-lived access token
#   MODE=gated | off                gate_enabled on or off
# Optional:
#   BYPASS="/api/webhook/abc /api/tts_proxy"   the bypassed paths listed in the options
#
# Exit status is non-zero on any mismatch. Run before and after every Access change.
set -u

: "${HA_HOST:?set HA_HOST}"
: "${CF_JWT:?set CF_JWT}"
: "${HA_TOKEN:?set HA_TOKEN}"
MODE="${MODE:-gated}"
BYPASS="${BYPASS:-}"
BASE="https://${HA_HOST}"
COOKIE="Cookie: CF_Authorization=${CF_JWT}"
fail=0

hdrs=$(mktemp)
trap 'rm -f "$hdrs"' EXIT
probe() {  # probe <path> [curl args...] -> "STATUS LOCATION [WWW-Authenticate]"
  local path=$1; shift
  local r; r=$(curl -sS -o /dev/null -D "$hdrs" -w '%{http_code} %{redirect_url}' --max-time 20 "$@" "${BASE}${path}")
  # Access answers a non-browser client with 401 + WWW-Authenticate (managed OAuth); mark it
  if grep -qi '^www-authenticate:' "$hdrs"; then r="$r WWW-Authenticate"; fi
  echo "$r"
}

is_access() {  # "302 https://team.cloudflareaccess.com/..." or "401 ... WWW-Authenticate"
  [[ "$1" =~ ^30[0-9]\ https://[^/]*\.cloudflareaccess\.com/ ]] || [[ "$1" == 401*WWW-Authenticate ]]
}

expect_gated() {
  local path=$1; shift
  local r; r=$(probe "$path" "$@")
  if is_access "$r"; then echo "ok    gated    $path ($r)"; else echo "FAIL  gated    $path -> $r"; fail=1; fi
}

expect_reaches_ha() {
  local path=$1; shift
  local r; r=$(probe "$path" "$@")
  if is_access "$r"; then echo "FAIL  open     $path -> $r"; fail=1; else echo "ok    open     $path ($r)"; fi
}

expect_status() {
  local want=$1 path=$2; shift 2
  local r; r=$(probe "$path" "$@")
  if [[ "$r" == "$want"* ]]; then echo "ok    $want     $path"; else echo "FAIL  want $want $path -> $r"; fail=1; fi
}

if [[ "$MODE" == "off" ]]; then
  echo "== gate off: Home Assistant answers directly"
  for p in / /api/ /auth/providers /api/websocket; do expect_reaches_ha "$p"; done
  expect_status 401 /api/
  expect_status 200 /api/ -H "Authorization: Bearer ${HA_TOKEN}"
else
  echo "== gate on: everything requires Access, the login surface included"
  for p in / /api/ /api/websocket /auth/providers /auth/token /frontend_latest/ /static/ /local/ \
           /api/webhook/definitely-not-a-real-webhook-id /api/google_assistant /api/alexa/smart_home /api/mcp; do
    expect_gated "$p"
  done
  echo "== a Home Assistant bearer alone does not pass the edge"
  expect_gated /api/ -H "Authorization: Bearer ${HA_TOKEN}"
  echo "== with the Access cookie, Home Assistant's own authentication applies"
  expect_status 200 /api/ -H "$COOKIE" -H "Authorization: Bearer ${HA_TOKEN}"
  expect_status 401 /api/ -H "$COOKIE"
  echo "== Access serves the OAuth discovery document for self-registering clients"
  if curl -sS --max-time 20 "${BASE}/.well-known/oauth-authorization-server" | grep -q authorization_endpoint; then
    echo "ok    oauth    /.well-known/oauth-authorization-server served by Access"
  else
    echo "FAIL  oauth    /.well-known/oauth-authorization-server is not Access's document"; fail=1
  fi
  echo "== websocket upgrade with cookie"
  ws=$(curl -sS -i -N --max-time 5 -H "$COOKIE" -H "Connection: Upgrade" -H "Upgrade: websocket" \
        -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" "${BASE}/api/websocket" 2>/dev/null | head -c 2000)
  if grep -q "auth_required" <<<"$ws"; then echo "ok    websocket auth_required"; else echo "FAIL  websocket: $(head -1 <<<"$ws")"; fail=1; fi
  if [[ -n "$BYPASS" ]]; then
    echo "== listed paths are bypassed"
    for p in $BYPASS; do expect_reaches_ha "$p"; done
  fi
fi

exit $fail
