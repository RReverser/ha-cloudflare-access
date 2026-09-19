#!/usr/bin/env bash
# Contract checks against the real Cloudflare edge in front of a Home Assistant hostname.
#
# Run from a shell with:
#   HA_HOST=ha.example.com          hostname the integration manages
#   CF_JWT=<application token>      copy the CF_Authorization cookie from browser devtools
#   HA_TOKEN=<long-lived token>     a Home Assistant long-lived access token
#   MODE=gated | staged             gated: gate_enabled=true; staged: only the callback path is gated
# Optional:
#   EXTRA_BYPASS="/api/webhook/abc /api/google_assistant"   extra_bypass_paths from the options
#   DEVICE_WEBHOOK=<webhook id>     a companion-app device's webhook id (Settings → Devices →
#                                   the device → download diagnostics), expected gated
#
# Exit status is non-zero on any mismatch. Run before and after every Access change.
set -u

: "${HA_HOST:?set HA_HOST}"
: "${CF_JWT:?set CF_JWT}"
: "${HA_TOKEN:?set HA_TOKEN}"
MODE="${MODE:-gated}"
EXTRA_BYPASS="${EXTRA_BYPASS:-}"
DEVICE_WEBHOOK="${DEVICE_WEBHOOK:-}"
BASE="https://${HA_HOST}"
COOKIE="Cookie: CF_Authorization=${CF_JWT}"
fail=0

# status_and_location <path> [curl args...] -> "STATUS LOCATION"
probe() {
  local path=$1; shift
  curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 20 "$@" "${BASE}${path}"
}

is_access_redirect() {  # "302 https://team.cloudflareaccess.com/..."
  [[ "$1" =~ ^30[0-9]\ https://[^/]*\.cloudflareaccess\.com/ ]]
}

expect_gated() {
  local path=$1; shift
  local r; r=$(probe "$path" "$@")
  if is_access_redirect "$r"; then echo "ok    gated    $path ($r)"; else echo "FAIL  gated    $path -> $r"; fail=1; fi
}

expect_reaches_ha() {
  local path=$1; shift
  local r; r=$(probe "$path" "$@")
  if is_access_redirect "$r"; then echo "FAIL  bypassed $path -> $r"; fail=1; else echo "ok    bypassed $path ($r)"; fi
}

expect_status() {
  local want=$1 path=$2; shift 2
  local r; r=$(probe "$path" "$@")
  if [[ "$r" == "$want"* ]]; then echo "ok    $want     $path"; else echo "FAIL  want $want $path -> $r"; fail=1; fi
}

echo "== bypassed paths reach Home Assistant without a cookie"
for p in /auth/providers /auth/token /auth/authorize /frontend_latest/ /frontend_es5/ /static/ \
         /cloudflare_access_relay/connect /cloudflare_access_relay/static/relay.js \
         /api/cloudflare_access_relay/session $EXTRA_BYPASS; do
  expect_reaches_ha "$p"
done

echo "== relay endpoints keep Home Assistant's own auth"
expect_status 401 /api/cloudflare_access_relay/session
expect_status 401 /api/cloudflare_access_relay/flow -X POST
expect_status 200 /api/cloudflare_access_relay/session -H "Authorization: Bearer ${HA_TOKEN}"

echo "== callback path is gated (both modes)"
expect_gated "/cloudflare_access_relay/callback?flow=bogus"
expect_status 404 "/cloudflare_access_relay/callback?flow=bogus" -H "$COOKIE"

if [[ "$MODE" == "gated" ]]; then
  echo "== hostname is gated"
  expect_gated /
  expect_gated /api/
  # webhooks carry their own secret id and are bypassed by rule; Home Assistant answers 200 to unknown ids
  expect_status 200 /api/webhook/definitely-not-a-real-webhook-id -X POST
  # a companion-app device's own webhook is gated: its exact path beats the bypassed prefix
  [[ -n "$DEVICE_WEBHOOK" ]] && expect_gated "/api/webhook/${DEVICE_WEBHOOK}" -X POST
  expect_gated /api/websocket
  expect_status 200 /api/ -H "$COOKIE" -H "Authorization: Bearer ${HA_TOKEN}"
  expect_status 401 /api/ -H "$COOKIE"
  echo "== websocket upgrade with cookie"
  ws=$(curl -sS -i -N --max-time 5 -H "$COOKIE" -H "Connection: Upgrade" -H "Upgrade: websocket" \
        -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" "${BASE}/api/websocket" 2>/dev/null | head -c 2000)
  if grep -q "auth_required" <<<"$ws"; then echo "ok    websocket auth_required"; else echo "FAIL  websocket: $(head -1 <<<"$ws")"; fail=1; fi
  wsno=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 -H "Connection: Upgrade" -H "Upgrade: websocket" \
        -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" "${BASE}/api/websocket")
  if [[ "$wsno" == 30* ]]; then echo "ok    websocket without cookie -> $wsno"; else echo "FAIL  websocket without cookie -> $wsno"; fail=1; fi
else
  echo "== staged: nothing but the callback is gated"
  expect_reaches_ha /
  expect_reaches_ha /api/
  expect_status 200 /api/ -H "Authorization: Bearer ${HA_TOKEN}"
fi

echo
if [[ $fail -eq 0 ]]; then echo "ALL OK"; else echo "MISMATCHES FOUND"; fi
exit $fail
