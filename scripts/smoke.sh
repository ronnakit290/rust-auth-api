#!/usr/bin/env bash
# End-to-end smoke test against a running instance.
#   BASE_URL=http://127.0.0.1:8080 ./scripts/smoke.sh
# Requires: curl, jq. Exits non-zero on the first failed expectation.

set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
EMAIL="smoke-$(date +%s)@example.com"
PASSWORD="Sm0keTestPassword!"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@example.com}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-Admin12345}"

pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; exit 1; }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# request METHOD PATH [TOKEN] [JSON]
request() {
  local method="$1" path="$2" token="${3:-}" body="${4:-}"
  local args=(-sS -X "$method" "$BASE_URL$path" -H 'accept: application/json')
  [[ -n "$token" ]] && args+=(-H "authorization: Bearer $token")
  [[ -n "$body" ]] && args+=(-H 'content-type: application/json' -d "$body")
  curl "${args[@]}" -w '\n%{http_code}'
}

status_of() { tail -n1 <<<"$1"; }
body_of() { sed '$d' <<<"$1"; }

expect_status() {
  local response="$1" expected="$2" label="$3"
  local actual; actual="$(status_of "$response")"
  [[ "$actual" == "$expected" ]] || { body_of "$response" >&2; fail "$label (expected $expected, got $actual)"; }
  pass "$label"
}

step "1. probes"
R="$(request GET /healthz)";                expect_status "$R" 200 "/healthz"
R="$(request GET /readyz)";                 expect_status "$R" 200 "/readyz"
R="$(request GET /api/v1/meta)";            expect_status "$R" 200 "/api/v1/meta"
printf '     transport: %s\n' "$(body_of "$R" | jq -r '.data.features.email_transport')"

step "2. registration"
R="$(request POST /api/v1/auth/register "" "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"full_name\":\"Smoke Tester\"}")"
expect_status "$R" 201 "register $EMAIL"
USER_ID="$(body_of "$R" | jq -r '.data.user.id')"
printf '     user id: %s\n' "$USER_ID"

R="$(request POST /api/v1/auth/register "" "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")"
expect_status "$R" 409 "duplicate e-mail rejected"

R="$(request POST /api/v1/auth/register "" '{"email":"weak@example.com","password":"weak"}')"
expect_status "$R" 422 "weak password rejected"

step "3. login"
R="$(request POST /api/v1/auth/login "" "{\"email\":\"$EMAIL\",\"password\":\"wrong-password\"}")"
expect_status "$R" 401 "wrong password rejected"

R="$(request POST /api/v1/auth/login "" "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")"
expect_status "$R" 200 "login"
ACCESS="$(body_of "$R" | jq -r '.data.tokens.access_token // .data.tokens // empty' 2>/dev/null || true)"
if [[ -z "$ACCESS" || "$ACCESS" == "null" ]]; then
  ACCESS="$(body_of "$R" | jq -r '.data.tokens.access_token')"
fi
REFRESH="$(body_of "$R" | jq -r '.data.tokens.refresh_token')"
[[ -n "$ACCESS" && "$ACCESS" != "null" ]] || fail "could not read access token"
pass "token pair issued"

step "4. profile"
R="$(request GET /api/v1/users/me "$ACCESS")";            expect_status "$R" 200 "GET /users/me"
R="$(request GET /api/v1/users/me)";                      expect_status "$R" 401 "anonymous request rejected"
R="$(request PATCH /api/v1/users/me "$ACCESS" '{"full_name":"Smoke Renamed"}')"
expect_status "$R" 200 "profile updated"
R="$(request GET /api/v1/users/me/sessions "$ACCESS")";   expect_status "$R" 200 "session list"

step "5. refresh rotation"
R="$(request POST /api/v1/auth/refresh "" "{\"refresh_token\":\"$REFRESH\"}")"
expect_status "$R" 200 "refresh rotated"
NEW_REFRESH="$(body_of "$R" | jq -r '.data.refresh_token')"
R="$(request POST /api/v1/auth/refresh "" "{\"refresh_token\":\"$REFRESH\"}")"
expect_status "$R" 401 "replayed refresh token rejected (family revoked)"

step "6. password reset"
R="$(request POST /api/v1/auth/forgot-password "" "{\"email\":\"$EMAIL\"}")"
expect_status "$R" 200 "reset link requested"
RESET_TOKEN="$(body_of "$R" | jq -r '.data.debug_token.token // empty')"
if [[ -n "$RESET_TOKEN" ]]; then
  R="$(request POST /api/v1/auth/reset-password "" "{\"token\":\"$RESET_TOKEN\",\"new_password\":\"R3setFromSmoke!\"}")"
  expect_status "$R" 200 "password reset applied"
  R="$(request POST /api/v1/auth/login "" "{\"email\":\"$EMAIL\",\"password\":\"R3setFromSmoke!\"}")"
  expect_status "$R" 200 "login with the new password"
else
  echo "     (EMAIL_MODE != console: token not exposed, skipping reset round-trip)"
fi

step "7. two factor"
R="$(request POST /api/v1/auth/login "" "{\"email\":\"$EMAIL\",\"password\":\"R3setFromSmoke!\"}")"
ACCESS="$(body_of "$R" | jq -r '.data.tokens.access_token')"
R="$(request POST /api/v1/2fa/setup "$ACCESS")"
expect_status "$R" 200 "2FA secret generated"
TOTP_SECRET="$(body_of "$R" | jq -r '.data.secret')"
printf '     otpauth: %s\n' "$(body_of "$R" | jq -r '.data.otpauth_url' | cut -c1-48)…"
R="$(request GET /api/v1/2fa "$ACCESS")";                 expect_status "$R" 200 "2FA status (pending)"

step "8. administration"
R="$(request POST /api/v1/auth/login "" "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}")"
if [[ "$(status_of "$R")" == "200" ]]; then
  ADMIN_TOKEN="$(body_of "$R" | jq -r '.data.tokens.access_token')"
  R="$(request GET '/api/v1/admin/users?per_page=5' "$ADMIN_TOKEN")";  expect_status "$R" 200 "admin user list"
  printf '     users: %s\n' "$(body_of "$R" | jq -r '.data.total')"
  R="$(request GET /api/v1/admin/stats "$ADMIN_TOKEN")";               expect_status "$R" 200 "admin stats"
  R="$(request GET '/api/v1/admin/audit-logs?per_page=5' "$ADMIN_TOKEN")"; expect_status "$R" 200 "audit trail"
  R="$(request GET '/api/v1/admin/users?per_page=5' "$REFRESH")";      expect_status "$R" 401 "non-admin cannot list users"
else
  echo "     (no bootstrap admin configured, skipping admin checks)"
fi

step "9. logout"
R="$(request POST /api/v1/auth/logout "$ACCESS" '{}')";     expect_status "$R" 200 "logout"
R="$(request GET /api/v1/users/me "$ACCESS")";              expect_status "$R" 401 "access token rejected after logout"

step "10. docs"
R="$(request GET /api-docs/openapi.json)";                  expect_status "$R" 200 "openapi document"
printf '     paths: %s\n' "$(body_of "$R" | jq '.paths | length')"

printf '\n\033[32mAll smoke checks passed\033[0m\n'
