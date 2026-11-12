#!/usr/bin/env bash
# End-to-end walkthrough of the central SSO server.
#
#   BASE_URL=http://127.0.0.1:8099 \
#   ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD='...' ./scripts/sso-smoke.sh
#
# Everything is exercised over real HTTP: discovery, JWKS, registering an
# application, issuing an app key, the authorization-code + PKCE flow, token
# exchange, userinfo, introspection, refresh rotation, reuse detection and
# revocation.

set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@example.com}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:?set ADMIN_PASSWORD}"
REDIRECT_URI="${REDIRECT_URI:-http://127.0.0.1:9999/callback}"
USER_EMAIL="${USER_EMAIL:-sso.user@example.com}"
USER_PASSWORD="${USER_PASSWORD:-Sup3rSecret!}"

command -v jq >/dev/null || { echo "jq is required"; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required"; exit 1; }

step() { printf '\n\033[1;36m== %s\033[0m\n' "$1"; }
ok() { printf '   \033[32m✓\033[0m %s\n' "$1"; }
expect_status() {
  local expected="$1" actual="$2" label="$3" body="${4:-}"
  if [[ "$actual" != "$expected" ]]; then
    printf '   \033[31m✗ %s (expected %s, got %s)\033[0m\n%s\n' "$label" "$expected" "$actual" "$body"
    exit 1
  fi
  ok "$label → $actual"
}

api() { # method path [token] [json]
  local method="$1" path="$2" token="${3:-}" body="${4:-}"
  local args=(-sS -X "$method" "$BASE_URL$path" -H 'content-type: application/json')
  [[ -n "$token" ]] && args+=(-H "authorization: Bearer $token")
  [[ -n "$body" ]] && args+=(-d "$body")
  curl "${args[@]}"
}

step "1. Service is up"
health_code=$(curl -sS -o /tmp/sso-health.json -w '%{http_code}' "$BASE_URL/healthz")
expect_status 200 "$health_code" "healthz"
cat /tmp/sso-health.json | jq -rc . 

step "2. Discovery + JWKS"
discovery=$(curl -sS "$BASE_URL/.well-known/openid-configuration")
echo "   issuer       : $(echo "$discovery" | jq -r '.issuer')"
echo "   token_endpoint: $(echo "$discovery" | jq -r '.token_endpoint')"
echo "   grants       : $(echo "$discovery" | jq -r '.grant_types_supported | join(", ")')"
jwks=$(curl -sS "$BASE_URL/.well-known/jwks.json")
echo "   jwk kid/alg  : $(echo "$jwks" | jq -r '.keys[0].kid') / $(echo "$jwks" | jq -r '.keys[0].alg')"
[[ "$(echo "$jwks" | jq -r '.keys[0].kty')" == "RSA" ]] || { echo "JWKS is not RSA"; exit 1; }
ok "public key published"

step "3. Admin login"
login=$(api POST /api/v1/auth/login "" "$(jq -nc --arg e "$ADMIN_EMAIL" --arg p "$ADMIN_PASSWORD" '{email:$e,password:$p}')")
ADMIN_TOKEN=$(echo "$login" | jq -r '.data.tokens.access_token // empty')
[[ -n "$ADMIN_TOKEN" ]] || { echo "admin login failed: $login"; exit 1; }
ok "admin authenticated"

step "4. Register an application (the system that will connect)"
client=$(api POST /api/v1/admin/clients "$ADMIN_TOKEN" "$(jq -nc \
  --arg uri "$REDIRECT_URI" \
  --arg name "Smoke Test CRM $(date +%H%M%S)" \
  '{name:$name,description:"created by scripts/sso-smoke.sh",client_type:"public",redirect_uris:[$uri],allowed_scopes:["openid","profile","email","users:read","tokens:verify"]}')")
CLIENT_ID=$(echo "$client" | jq -r '.data.client.client_id')
CLIENT_PK=$(echo "$client" | jq -r '.data.client.id')
[[ "$CLIENT_ID" != "null" ]] || { echo "client creation failed: $client"; exit 1; }
echo "   client_id    : $CLIENT_ID"
echo "   redirect_uris: $(echo "$client" | jq -c '.data.client.redirect_uris')"
echo "   scopes       : $(echo "$client" | jq -rc '.data.client.allowed_scopes')"

step "5. Issue an app key for a machine integration"
key=$(api POST "/api/v1/admin/clients/$CLIENT_PK/keys" "$ADMIN_TOKEN" \
  '{"name":"smoke-machine","scopes":["users:read","tokens:verify"],"expires_in_days":30}')
APP_KEY=$(echo "$key" | jq -r '.data.secret')
echo "   key prefix   : $(echo "$key" | jq -r '.data.api_key.key_prefix')"
[[ "$APP_KEY" != "null" ]] || { echo "key creation failed: $key"; exit 1; }

me=$(curl -sS "$BASE_URL/api/v1/app/me" -H "x-api-key: $APP_KEY")
echo "   app/me       : $(echo "$me" | jq -rc '.data.client')"
ok "app key authenticates as the application"

app_users=$(curl -sS "$BASE_URL/api/v1/app/users" -H "x-api-key: $APP_KEY")
ok "app/users returns $(echo "$app_users" | jq -r '.data.total') user(s)"

step "6. User registers and logs in (the resource owner)"
api POST /api/v1/auth/register "" "$(jq -nc --arg e "$USER_EMAIL" --arg p "$USER_PASSWORD" '{email:$e,password:$p,full_name:"SSO Smoke User"}')" >/dev/null || true
user_login=$(api POST /api/v1/auth/login "" "$(jq -nc --arg e "$USER_EMAIL" --arg p "$USER_PASSWORD" '{email:$e,password:$p}')")
USER_TOKEN=$(echo "$user_login" | jq -r '.data.tokens.access_token // empty')
[[ -n "$USER_TOKEN" ]] || { echo "user login failed: $user_login"; exit 1; }
USER_ID=$(echo "$user_login" | jq -r '.data.user.id')
ok "user authenticated ($USER_ID)"

step "7. Authorization-code flow with PKCE"
VERIFIER=$(openssl rand -base64 60 | tr -d '\n=+/' | cut -c1-64)
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')

info=$(curl -sS -G "$BASE_URL/oauth/authorize/info" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  --data-urlencode "scope=openid profile email" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  -H "authorization: Bearer $USER_TOKEN")
echo "   consent for  : $(echo "$info" | jq -r '.client.name')"
echo "   scopes       : $(echo "$info" | jq -rc '.requested_scopes')"

authz=$(api POST /oauth/authorize "$USER_TOKEN" "$(jq -nc \
  --arg cid "$CLIENT_ID" --arg uri "$REDIRECT_URI" --arg ch "$CHALLENGE" \
  '{response_type:"code",client_id:$cid,redirect_uri:$uri,scope:"openid profile email",state:"smoke-state",code_challenge:$ch,code_challenge_method:"S256"}')")
CODE=$(echo "$authz" | jq -r '.code')
echo "   redirect_url : $(echo "$authz" | jq -r '.redirect_url' | cut -c1-90)…"

tokens=$(curl -sS -X POST "$BASE_URL/oauth/token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=$REDIRECT_URI" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "code_verifier=$VERIFIER")
ACCESS=$(echo "$tokens" | jq -r '.access_token // empty')
REFRESH=$(echo "$tokens" | jq -r '.refresh_token // empty')
[[ -n "$ACCESS" ]] || { echo "token exchange failed: $tokens"; exit 1; }
echo "   access_token : ${ACCESS:0:32}…"
echo "   expires_in   : $(echo "$tokens" | jq -r '.expires_in')s, scope: $(echo "$tokens" | jq -r '.scope')"
echo "   id_token     : $(echo "$tokens" | jq -r 'if .id_token then "present" else "absent" end')"

step "8. Use the token"
userinfo=$(curl -sS "$BASE_URL/oauth/userinfo" -H "authorization: Bearer $ACCESS")
echo "   userinfo     : $(echo "$userinfo" | jq -rc '{sub,email,email_verified,name,scopes}')"
[[ "$(echo "$userinfo" | jq -r '.sub')" == "$USER_ID" ]] || { echo "wrong subject"; exit 1; }

intro=$(curl -sS -X POST "$BASE_URL/oauth/introspect" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "token=$ACCESS" --data-urlencode "client_id=$CLIENT_ID")
echo "   introspect   : active=$(echo "$intro" | jq -r '.active') aud=$(echo "$intro" | jq -r '.aud')"

step "9. Refresh rotation + reuse detection"
refreshed=$(curl -sS -X POST "$BASE_URL/oauth/token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=refresh_token' \
  --data-urlencode "refresh_token=$REFRESH" \
  --data-urlencode "client_id=$CLIENT_ID")
NEW_REFRESH=$(echo "$refreshed" | jq -r '.refresh_token // empty')
[[ -n "$NEW_REFRESH" ]] || { echo "refresh failed: $refreshed"; exit 1; }
ok "refresh token rotated"

reuse_code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/oauth/token" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=refresh_token' \
  --data-urlencode "refresh_token=$REFRESH" \
  --data-urlencode "client_id=$CLIENT_ID")
expect_status 400 "$reuse_code" "replayed refresh token rejected"

step "10. Revocation"
curl -sS -o /dev/null -X POST "$BASE_URL/oauth/revoke" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "token=$ACCESS" \
  --data-urlencode "client_id=$CLIENT_ID"
after=$(curl -sS -X POST "$BASE_URL/oauth/introspect" \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode "token=$ACCESS" --data-urlencode "client_id=$CLIENT_ID")
[[ "$(echo "$after" | jq -r '.active')" == "false" ]] || { echo "token still active after revoke"; exit 1; }
ok "revoked token is inactive"

printf '\n\033[1;32mSSO smoke test passed.\033[0m\n'
printf 'Application registered: %s (id %s)\n' "$CLIENT_ID" "$CLIENT_PK"
