#!/usr/bin/env bash
# Pre-flight checks against real Cloudflare (plan section 7), from a shell.
#
# The automated version of these checks is tests/live/test_live_edge.py (run by CI with the
# repository secrets). This script is the manual equivalent for a shell with curl.
#
# Setup (once): deploy preflight/worker on the test hostname (cd preflight/worker && npx
# wrangler deploy, with a route or a Workers custom domain), and let the integration's own
# provisioning create the Access applications for that hostname, e.g. by running the live
# tests once, or with the integration itself pointed at the test hostname. Create an Access
# service token and add its id to the "service token IDs" option so this script can log in.
#
# Environment
#   TEST_HOST=test-host.example.com
#   CF_ACCESS_CLIENT_ID=...   CF_ACCESS_CLIENT_SECRET=...   (an Access service token)
# Optional: CF_JWT=<identity token from `cloudflared access login https://$TEST_HOST/api/echo`>
#
# P5 (binding cookie), P6 (session ceiling) and P7 (Android WebView, manual) are described
# in the README. Failure of P1, P2 or P8 kills the design.
set -euo pipefail
: "${TEST_HOST:?}"; : "${CF_ACCESS_CLIENT_ID:?}"; : "${CF_ACCESS_CLIENT_SECRET:?}"
B="https://${TEST_HOST}"; fail=0
short() { sed -E 's#(cloudflareaccess\.com/cdn-cgi/access/login/[^?]*)\?.*#\1?…#'; }
status() { curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' "$@" | short; }
is_gated() { [[ "$1" =~ ^30[0-9]\ https://[^/]*\.cloudflareaccess\.com/ ]]; }

echo "== P8: a path-specific bypass application beats the hostname-wide gate"
r=$(status "$B/api/echo");                        is_gated "$r" && echo "  ok gated /api/echo" || { echo "  FAIL /api/echo -> $r"; fail=1; }
r=$(status "$B/api/cloudflare_access_relay/echo"); [[ "$r" == 200* ]] && echo "  ok bypassed /api/cloudflare_access_relay/echo" || { echo "  FAIL -> $r"; fail=1; }
r=$(status "$B/cloudflare_access_relay/callback?flow=x"); is_gated "$r" && echo "  ok gated callback" || { echo "  FAIL callback -> $r"; fail=1; }

echo "== P1: origin Set-Cookie passes through unmodified (bypassed path)"
sc=$(curl -sS -D - -o /dev/null -X POST -H 'content-type: application/json' -d '{"v":"probe-value"}' "$B/auth/token/setcookie" | tr -d '\r' | grep -i '^set-cookie:' || true)
[[ "$sc" == *"CF_Authorization=probe-value; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600"* ]] && echo "  ok" || { echo "  FAIL: $sc"; fail=1; }

echo "== service-token login: token as header and as cookie"
curl -sS -D hdr.txt -o body.json -H "CF-Access-Client-Id: $CF_ACCESS_CLIENT_ID" -H "CF-Access-Client-Secret: $CF_ACCESS_CLIENT_SECRET" "$B/api/echo"
JWT=$(python3 -c 'import json;print(json.load(open("body.json"))["headers"].get("cf-access-jwt-assertion",""))')
COOKIE=$(tr -d '\r' < hdr.txt | sed -n 's/^[Ss]et-[Cc]ookie: CF_Authorization=\([^;]*\).*/\1/p' | head -1)
[[ -n "$JWT" ]] && echo "  ok header present" || { echo "  FAIL no Cf-Access-Jwt-Assertion"; fail=1; }
[[ "$JWT" == "$COOKIE" ]] && echo "  ok P4 header == cookie" || { echo "  FAIL P4"; fail=1; }
python3 - "$JWT" <<'PY'
import base64, json, sys
p = sys.argv[1].split(".")[1]; c = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
print(f"  P3: exp-iat = {c['exp']-c['iat']} s; aud={c['aud']}; iss={c['iss']}")
PY
rm -f hdr.txt body.json

echo "== P2: the token alone, as a cookie, from a client that never logged in"
for tok in "$JWT" "${CF_JWT:-}"; do
  [[ -z "$tok" ]] && continue
  r=$(status -A 'okhttp/4.12.0' -b "CF_Authorization=$tok" "$B/api/echo")
  [[ "$r" == 200* ]] && echo "  ok (200)" || { echo "  FAIL -> $r"; fail=1; }
done
r=$(status -b "CF_Authorization=${JWT%???}xyz" "$B/api/echo"); is_gated "$r" && echo "  ok tampered cookie refused" || { echo "  FAIL tampered -> $r"; fail=1; }

echo; [[ $fail -eq 0 ]] && echo "PRE-FLIGHT OK" || { echo "PRE-FLIGHT FAILED"; exit 1; }
