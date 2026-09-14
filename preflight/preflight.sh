#!/usr/bin/env bash
# Pre-flight tests P1-P8 against real Cloudflare (plan section 7). No Home Assistant involved.
#
# Prerequisites
#   1. Deploy preflight/worker on a throwaway hostname:  cd preflight/worker && npx wrangler deploy
#   2. Run "preflight.sh provision" once: it creates two Access applications on the throwaway
#      hostname through the API (gate: whole host, allow <EMAIL>; bypass: /setcookie and /page).
#   3. Log in once in a browser at https://$TEST_HOST/echo, copy the "cf-access-jwt-assertion"
#      value it echoes, export it as CF_JWT, and run "preflight.sh check" from a DIFFERENT
#      machine/IP than the browser used (P2 must prove the cookie is not bound to the client).
#
# Environment
#   TEST_HOST=cfa-test.example.com  CF_API_TOKEN=...  CF_ACCOUNT_ID=...  EMAIL=you@example.com
#   CF_JWT=<token copied from /echo>   (check only)
#
# P5 (binding cookie) and P6 (session ceiling) are read/toggled in the dashboard; P7 is manual
# on an Android device (open https://$TEST_HOST/page as a "webpage" card or via the app's
# external URL, tap the link: the system browser must open on the team domain and the WebView
# must stay on /page). Failure of P1, P2, P7 or P8 kills the design.
set -euo pipefail

: "${TEST_HOST:?}"; : "${CF_API_TOKEN:?}"; : "${CF_ACCOUNT_ID:?}"
API="https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/access"
auth=(-H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json")

provision() {
  : "${EMAIL:?}"
  echo "creating bypass app (/setcookie, /page)"
  curl -sS "${auth[@]}" -X POST "${API}/apps" --data @- <<JSON | python3 -c 'import json,sys; d=json.load(sys.stdin); print("ok" if d["success"] else d["errors"])'
{"type":"self_hosted","name":"test-host bypass","domain":"${TEST_HOST}/setcookie",
 "destinations":[{"type":"public","uri":"${TEST_HOST}/setcookie"},{"type":"public","uri":"${TEST_HOST}/page"}],
 "app_launcher_visible":false,
 "policies":[{"name":"bypass everyone","decision":"bypass","precedence":1,"include":[{"everyone":{}}]}]}
JSON
  echo "creating gate app (whole host, allow ${EMAIL}, 15m session for the expiry rehearsal, binding cookie off)"
  curl -sS "${auth[@]}" -X POST "${API}/apps" --data @- <<JSON | python3 -c 'import json,sys; d=json.load(sys.stdin); print("ok aud=" + d["result"]["aud"] if d["success"] else d["errors"])'
{"type":"self_hosted","name":"test-host gate","domain":"${TEST_HOST}",
 "destinations":[{"type":"public","uri":"${TEST_HOST}"}],
 "session_duration":"15m","enable_binding_cookie":false,"path_cookie_attribute":false,
 "http_only_cookie_attribute":true,"same_site_cookie_attribute":"lax","app_launcher_visible":false,
 "policies":[{"name":"allow","decision":"allow","precedence":1,"include":[{"email":{"email":"${EMAIL}"}}]}]}
JSON
  echo "P6: the API accepted the durations above; the dashboard dropdown documents the ceiling (one month)."
}

cleanup() {
  for id in $(curl -sS "${auth[@]}" "${API}/apps?per_page=100" | python3 -c 'import json,sys; [print(a["id"]) for a in json.load(sys.stdin)["result"] if a["name"].startswith("test-host")]'); do
    curl -sS "${auth[@]}" -X DELETE "${API}/apps/${id}" >/dev/null && echo "deleted ${id}"
  done
}

check() {
  : "${CF_JWT:?export CF_JWT from the browser's /echo output}"
  local base="https://${TEST_HOST}" fail=0
  echo "P1: origin Set-Cookie passes through Cloudflare unmodified"
  local sc; sc=$(curl -sS -i -X POST "${base}/setcookie" -H 'content-type: application/json' -d '{"v":"probe-value"}' | tr -d '\r' | grep -i '^set-cookie:' || true)
  if [[ "$sc" == *"CF_Authorization=probe-value; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600"* ]]; then echo "  ok"; else echo "  FAIL: $sc"; fail=1; fi

  echo "P8: path-specific bypass app beats the hostname-wide gate app"
  local r; r=$(curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' "${base}/page")
  [[ "$r" == 200* ]] && echo "  ok bypassed /page ($r)" || { echo "  FAIL /page -> $r"; fail=1; }
  r=$(curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' "${base}/echo")
  [[ "$r" =~ ^30[0-9]\ https://.*cloudflareaccess\.com ]] && echo "  ok gated /echo ($r)" || { echo "  FAIL /echo -> $r"; fail=1; }

  echo "P2: Access accepts a CF_Authorization cookie it did not set in this client"
  local echo_out; echo_out=$(curl -sS -w '\n%{http_code}' -b "CF_Authorization=${CF_JWT}" "${base}/echo")
  local code; code=$(tail -1 <<<"$echo_out")
  if [[ "$code" == 200 ]]; then echo "  ok (200)"; else echo "  FAIL ($code)"; fail=1; fi

  echo "P4: header token equals the cookie token"
  local hdr; hdr=$(head -n -1 <<<"$echo_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["headers"].get("cf-access-jwt-assertion",""))' 2>/dev/null || true)
  if [[ "$hdr" == "$CF_JWT" ]]; then echo "  ok"; else echo "  FAIL (header differs or missing)"; fail=1; fi

  echo "P3: exp - iat equals the configured session duration (15m in provision)"
  python3 - "$CF_JWT" <<'PY'
import base64, json, sys
payload = sys.argv[1].split(".")[1]
claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
print(f"  exp-iat = {claims['exp'] - claims['iat']} s; aud={claims.get('aud')}; email={claims.get('email')}")
PY

  echo "P5: enable 'Binding Cookie' on the gate app in the dashboard and re-run 'check': P2 is expected to FAIL then; it must stay off."
  echo
  [[ $fail -eq 0 ]] && echo "P1/P2/P4/P8 OK" || { echo "PRE-FLIGHT FAILED"; exit 1; }
}

case "${1:-}" in
  provision) provision ;;
  check) check ;;
  cleanup) cleanup ;;
  *) echo "usage: $0 provision|check|cleanup"; exit 2 ;;
esac
