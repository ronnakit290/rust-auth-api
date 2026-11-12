# Rust Auth API

ระบบ Authentication + User Management API และ **SSO Server กลาง** ที่ออก App Key
ให้ระบบอื่นมาต่อได้ เขียนด้วยภาษา Rust (Axum 0.8 + SQLx 0.8 + SQLite + JWT + Argon2id + TOTP
+ OAuth2 RS256/JWKS) พร้อม OpenAPI/Swagger

- เวอร์ชัน: 0.1.0
- Rust: 1.82 ขึ้นไป (ทดสอบบน 1.99.1)
- ฐานข้อมูล: SQLite (ไฟล์เดียว, WAL) — พร้อมสลับเป็น PostgreSQL (ดูหัวข้อท้ายไฟล์)
- เอกสาร API สด: `http://127.0.0.1:8080/docs` (Swagger UI) และ `/api-docs/openapi.json`

---

## 1. มีอะไรบ้าง (Features)

Authentication
- สมัครสมาชิก + นโยบายรหัสผ่าน (ความยาว, ต้องมีตัวอักษรและตัวเลข, blocklist รหัสยอดนิยม)
- Login ด้วยอีเมล/รหัสผ่าน พร้อม Argon2id และ timing-safe comparison (ไม่บอกว่าอีเมลมีอยู่จริงหรือไม่)
- JWT access token (HS256, อายุสั้น 15 นาที โดยปริยาย) + opaque refresh token แบบหมุนทุกครั้ง
- Refresh token rotation + ตรวจจับการนำ token เก่ากลับมาใช้ซ้ำ (reuse detection) → revoke ทั้ง family
- Logout ราย session / ออกจากทุกอุปกรณ์
- Email verification (token ใช้ครั้งเดียว, เก็บเฉพาะ hash)
- Forgot / Reset password (token ใช้ครั้งเดียว, reset แล้ว revoke ทุก session + ปลดล็อก account)
- เปลี่ยนรหัสผ่าน (ต้องยืนยันรหัสเดิม, revoke session อื่นทั้งหมด)
- ล็อกบัญชีชั่วคราวเมื่อใส่รหัสผิดติดกันเกินกำหนด (ค่าเริ่มต้น 5 ครั้ง / ล็อก 15 นาที)
- Rate limiting ต่อ IP ต่อ endpoint (login, register, forgot, resend, refresh) + limiter ระดับ global

Two-Factor (TOTP)
- ตั้งค่า secret + `otpauth://` URI สำหรับแอป authenticator
- เปิดใช้งานด้วยการยืนยันโค้ด 6 หลัก (ยังไม่เปิดจนกว่าจะยืนยันสำเร็จ)
- Recovery codes 10 ใบ (แสดงครั้งเดียว, เก็บเป็น hash)
- Login แบบสองขั้น: คืน `mfa_required` + `mfa_token` อายุ 5 นาที แล้วแลกเป็น token pair ที่ `/auth/2fa/verify`
- ปิด 2FA ต้องใช้ทั้งรหัสผ่านและโค้ด (TOTP หรือ recovery code)

Authorization / Administration
- RBAC 4 ระดับ: `user` < `moderator` < `admin` < `superadmin`
- Admin จัดการผู้ใช้: list (ค้นหา/กรอง/เรียง/แบ่งหน้า), ดูรายคน, แก้ role/status/ชื่อ, ปลดล็อก, ลบ (soft/hard), revoke session
- กันการยกระดับสิทธิ์ (ให้ role สูงกว่าตัวเองไม่ได้), กันลบ/แก้ role ตัวเอง, กันลบ admin คนสุดท้าย
- Audit log ทุกเหตุการณ์สำคัญ (register, login, login fail, lock, refresh reuse, reset, 2FA, admin actions) พร้อม IP/User-Agent/metadata และ query ได้
- Statistics: จำนวนผู้ใช้แยกสถานะ, verified, 2FA, active sessions, login/failed login 24 ชม.

Central SSO (OAuth2 / OIDC-style)
- ลงทะเบียน "application" (OAuth2 client) ได้ไม่จำกัด: confidential (มี secret) หรือ public (SPA/mobile, บังคับ PKCE)
- Grant types: `authorization_code` (+ PKCE S256/plain), `refresh_token`, `client_credentials`
- **App Key** สำหรับระบบที่ทำ OAuth dance ไม่ได้ (`ssok_live_…`): เก็บเฉพาะ SHA-256, มี scope, วันหมดอายุ, rotate/revoke ได้
- Access token เป็น **JWT RS256** — ระบบอื่น verify เองได้ด้วย `/.well-known/jwks.json` ไม่ต้องถามกลับทุกครั้ง
- Discovery document `/.well-known/openid-configuration`, `id_token` เมื่อขอ scope `openid`
- `/oauth/userinfo`, `/oauth/introspect` (RFC 7662), `/oauth/revoke` (RFC 7009) + denylist สำหรับ token ที่ถูกเพิกถอน
- Refresh token rotation + ตรวจจับการใช้ซ้ำ → revoke ทั้ง family ของ app นั้น
- Scope ที่จำกัดต่อ app และต่อ key; ปิด/ลบ app = ตัด app key + refresh token ทันที
- Error ของ endpoint มาตรฐานตอบตาม RFC (`{"error":"invalid_grant"}`) เพื่อให้ client library ทั่วไปใช้ได้เลย
- Admin API จัดการ app/key ทั้งหมด + audit log ทุกการออก/เพิกถอน

Platform
- Response envelope มาตรฐาน + error code ที่เครื่องอ่านได้
- Validation ครบทุก body (`validator`) → 422 พร้อมรายละเอียดรายฟิลด์
- Request id (`x-request-id`) ทุก response, security headers, CORS, compression, timeout, body limit 1 MB
- Health probes: `/healthz` (liveness), `/readyz` (ตรวจ DB จริง)
- Graceful shutdown (SIGTERM/Ctrl+C) + background purge session หมดอายุทุกชั่วโมง
- Email transport แบบ console (log + in-memory outbox สำหรับ dev/test) สลับเป็น SMTP/API ได้ที่จุดเดียว
- Integration tests 27 เคส (API 19 + SSO 8) + unit tests 6 เคส + smoke script 2 ชุดยิง API จริงด้วย curl

---

## 2. เริ่มใช้งานเร็ว (Quick start)

```bash
cd rust-auth-api
cp .env.example .env          # แก้ JWT_SECRET ให้ยาว >= 32 ตัวอักษร

# สร้าง key สำหรับ SSO (RS256) — development ปล่อยว่างได้แต่ token จะหายทุก restart
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out sso.pem
# แล้วใส่ SSO_RSA_PRIVATE_KEY เป็นบรรทัดเดียว (แทน newline ด้วย \n)
python3 - <<'EOF'
pem = open('sso.pem').read().strip().replace('\n', '\\n')
print(f'SSO_RSA_PRIVATE_KEY="{pem}"')
EOF

cargo run                     # ครั้งแรกใน debug mode: อย่าลืมใส่ key ไม่งั้น keygen จะช้า
```

เปิด `http://127.0.0.1:8080/docs` จะเห็น Swagger UI ของทุก endpoint (53 operations)

ทดสอบทั้งระบบด้วยสคริปต์:

```bash
./scripts/smoke.sh                                  # auth: register → 2FA → admin
ADMIN_PASSWORD='...' ./scripts/sso-smoke.sh         # SSO: app → PKCE → token → revoke
python3 scripts/verify_jwt.py                       # verify token ด้วย JWKS เท่านั้น
make sso-smoke verify-token                         # หรือผ่าน make
```

สร้าง superadmin คนแรกผ่าน environment (สร้างให้อัตโนมัติตอน start ถ้ายังไม่มี):

```bash
BOOTSTRAP_ADMIN_EMAIL=admin@example.com \
BOOTSTRAP_ADMIN_PASSWORD='Admin12345' \
cargo run
```

หรือใช้ Docker:

```bash
JWT_SECRET=$(openssl rand -hex 32) \
SSO_RSA_PRIVATE_KEY="$(python3 -c "print(open('sso.pem').read().strip().replace(chr(10), chr(92)+'n'))")" \
docker compose up --build
```

---

## 3. Endpoint ทั้งหมด

ทุก path อยู่ใต้ `/api/v1` (ยกเว้น probes, `/oauth/*` และ `/.well-known/*`) และทุก response ถูกห่อด้วย
`{"success": true, "data": ...}` หรือ `{"success": false, "error": {"code", "message", "details"}}`

ข้อยกเว้น: endpoint มาตรฐาน OAuth2 (`/oauth/token`, `/oauth/introspect`, `/oauth/revoke`,
`/oauth/userinfo`, `/oauth/authorize`, discovery, JWKS) ตอบ JSON ตาม RFC 6749/7662 — ไม่ห่อ envelope
เพื่อให้ library ภายนอกใช้ได้ตรง ๆ

### Auth — ต้อง login ไหม?

| Method | Path | Auth | คำอธิบาย |
|---|---|---|---|
| POST | `/auth/register` | – | สมัครสมาชิก (201) |
| POST | `/auth/login` | – | เข้าสู่ระบบ → token pair หรือ `mfa_required` |
| POST | `/auth/2fa/verify` | mfa_token | แลก mfa_token + TOTP/recovery code เป็น token pair |
| POST | `/auth/refresh` | refresh token | หมุน refresh token (ตรวจจับ reuse) |
| POST | `/auth/logout` | Bearer | ออกจากระบบ (หรือ `all_sessions: true`) |
| POST | `/auth/forgot-password` | – | ขอลิงก์รีเซ็ต (ตอบ 200 เสมอ ไม่ให้เดาบัญชีได้) |
| POST | `/auth/reset-password` | – | ใช้ token ตั้งรหัสใหม่ + revoke ทุก session |
| POST | `/auth/verify-email` | – | ยืนยันอีเมลด้วย token |
| POST | `/auth/resend-verification` | – | ขอส่งอีเมลยืนยันใหม่ |

### Profile & Sessions

| Method | Path | Auth | คำอธิบาย |
|---|---|---|---|
| GET | `/users/me` | Bearer | โปรไฟล์ปัจจุบัน |
| PATCH | `/users/me` | Bearer | แก้ชื่อ / เปลี่ยนอีเมล (ต้องยืนยันใหม่) |
| POST | `/users/me/change-password` | Bearer | เปลี่ยนรหัสผ่าน |
| POST | `/users/me/deactivate` | Bearer | ปิดบัญชี (soft delete + revoke session) |
| GET | `/users/me/sessions` | Bearer | ดู session ที่ยัง active |
| DELETE | `/users/me/sessions/{session_id}` | Bearer | revoke 1 session |
| DELETE | `/users/me/sessions` | Bearer | revoke session อื่นทั้งหมด |

### Two-factor

| Method | Path | Auth | คำอธิบาย |
|---|---|---|---|
| GET | `/2fa` | Bearer | สถานะ 2FA + จำนวน recovery code คงเหลือ |
| POST | `/2fa/setup` | Bearer | สร้าง secret + otpauth URI (ยังไม่เปิดใช้) |
| POST | `/2fa/enable` | Bearer | ยืนยันโค้ดแล้วเปิดใช้ + คืน recovery codes |
| POST | `/2fa/disable` | Bearer | ปิด 2FA (รหัสผ่าน + โค้ด) |
| POST | `/2fa/recovery-codes` | Bearer | สร้าง recovery codes ชุดใหม่ |

### Admin (admin / superadmin)

| Method | Path | คำอธิบาย |
|---|---|---|
| GET | `/admin/users` | list + `page`, `per_page`, `search`, `role`, `status`, `email_verified`, `two_factor`, `sort`, `order` |
| GET | `/admin/users/{user_id}` | ดูผู้ใช้รายคน |
| PATCH | `/admin/users/{user_id}` | แก้ role / status / full_name / `unlock: true` |
| DELETE | `/admin/users/{user_id}` | soft delete (หรือ `?hard=true` เพื่อลบจริง) |
| POST | `/admin/users/{user_id}/sessions/revoke` | revoke ทุก session ของผู้ใช้ |
| GET | `/admin/audit-logs` | query audit: `action`, `actor_id`, `target_id`, `from`, `to` (unix seconds) |
| GET | `/admin/stats` | สถิติภาพรวม |

### SSO — มาตรฐาน OAuth2 (ไม่ห่อ envelope)

| Method | Path | Auth | คำอธิบาย |
|---|---|---|---|
| GET | `/.well-known/openid-configuration` | – | discovery: รายชื่อ endpoint, grant, scope ที่รองรับ |
| GET | `/.well-known/jwks.json` | – | public key (RS256) สำหรับ verify token — cache ได้ 5 นาที |
| GET | `/oauth/authorize/info` | Bearer (ผู้ใช้) | ข้อมูลสำหรับหน้าจอ consent + ตรวจ request |
| POST | `/oauth/authorize` | Bearer (ผู้ใช้) | อนุมัติ → คืน `code`, `redirect_url` (มี `state` ต่อท้าย) |
| POST | `/oauth/token` | client auth | `authorization_code` / `refresh_token` / `client_credentials` |
| POST | `/oauth/introspect` | client auth | token ยังใช้ได้ไหม (RFC 7662) |
| POST | `/oauth/revoke` | client auth | เพิกถอน token (RFC 7009) |
| GET | `/oauth/userinfo` | Bearer (SSO token) | โปรไฟล์เจ้าของ token ตาม scope |

### SSO Admin — จัดการระบบที่มาต่อ (admin / superadmin)

| Method | Path | คำอธิบาย |
|---|---|---|
| GET | `/api/v1/admin/clients` | list app + `search`, `status`, แบ่งหน้า |
| POST | `/api/v1/admin/clients` | ลงทะเบียน app → คืน `client_id` + `client_secret` (ครั้งเดียว) |
| GET | `/api/v1/admin/clients/{client_ref}` | ดู app (รับ id หรือ `client_id`) |
| PATCH | `/api/v1/admin/clients/{client_ref}` | แก้ชื่อ/redirect URIs/scopes/`status` |
| DELETE | `/api/v1/admin/clients/{client_ref}` | ลบ app (codes, refresh tokens, keys หายตาม) |
| POST | `/api/v1/admin/clients/{client_ref}/secret/rotate` | หมุน client secret |
| GET | `/api/v1/admin/clients/{client_ref}/keys` | list app key (เห็นแค่ prefix) |
| POST | `/api/v1/admin/clients/{client_ref}/keys` | ออก App Key → คืน secret ครั้งเดียว |
| DELETE | `/api/v1/admin/clients/{client_ref}/keys/{key_id}` | เพิกถอน key |
| POST | `/api/v1/admin/clients/{client_ref}/keys/{key_id}/rotate` | ออก key ใหม่แล้วเพิกถอนตัวเก่า |

### App — endpoint สำหรับระบบที่ใช้ App Key

| Method | Path | Scope ที่ต้องมี | คำอธิบาย |
|---|---|---|---|
| GET | `/api/v1/app/me` | – | app นี้คือใคร, key นี้ถือ scope อะไร |
| GET | `/api/v1/app/users` | `users:read` | list ผู้ใช้ (แบ่งหน้า) |
| GET | `/api/v1/app/users/{user_id}` | `users:read` | ดูผู้ใช้รายคน |
| POST | `/api/v1/app/introspect` | `tokens:verify` | ตรวจ token ด้วย App Key (ไม่ต้องมี client secret) |

### Probes / Meta / Dev

| Method | Path | คำอธิบาย |
|---|---|---|
| GET | `/healthz` | liveness (ไม่แตะ DB) |
| GET | `/readyz` | readiness (ping DB, 503 เมื่อ DB ล่ม) |
| GET | `/api/v1/meta` | เวอร์ชัน + capabilities + TTL ของ token |
| GET/DELETE | `/api/v1/dev/outbox` | ดู/ล้างอีเมลที่ส่ง (เฉพาะ `EMAIL_MODE=console` และไม่ใช่ production) |
| GET | `/api/v1/dev/outbox/{email}` | ดูอีเมลล่าสุดของอีเมลหนึ่ง (ใช้ใน dev/test) |
| GET | `/docs`, `/api-docs/openapi.json` | Swagger UI + OpenAPI 3.1 |

---

## 4. ตัวอย่างการเรียกใช้

```bash
BASE=http://127.0.0.1:8080

# สมัคร
curl -sS -X POST $BASE/api/v1/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"user@example.com","password":"Sup3rSecret","full_name":"Somchai"}'

# เข้าสู่ระบบ
curl -sS -X POST $BASE/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"user@example.com","password":"Sup3rSecret"}'

ACCESS=<access_token ที่ได้>
curl -sS $BASE/api/v1/users/me -H "authorization: Bearer $ACCESS"

# หมุน refresh token
curl -sS -X POST $BASE/api/v1/auth/refresh \
  -H 'content-type: application/json' -d '{"refresh_token":"<refresh_token>"}'
```

ตัวอย่าง error (422):

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "One or more fields are invalid",
    "details": [{ "field": "password", "message": "must contain at least one digit" }]
  }
}
```

---

## 5. SSO กลาง — ให้ระบบอื่นมาต่อ

เซิร์ฟเวอร์นี้ทำหน้าที่เป็น Authorization Server กลาง: ทุกระบบ (CRM, ERP, dashboard, cron job,
บริการภายนอก) ลงทะเบียนเป็น "application" ครั้งเดียว แล้วเลือกวิธีต่อได้ 3 แบบ

| ระบบปลายทาง | วิธีต่อ | เหมาะกับ |
|---|---|---|
| มีผู้ใช้ล็อกอิน (web / SPA / mobile) | `authorization_code` + PKCE | portal, CRM, dashboard |
| ระบบอัตโนมัติที่มี secret ได้ | `client_credentials` | worker, cron, service-to-service |
| ระบบที่ทำ OAuth dance ไม่ได้ | **App Key** (`X-API-Key`) | webhook, legacy, script ภายใน |

ผลลัพธ์ที่ระบบปลายทางได้คือ **JWT RS256** ที่ verify เองได้ด้วย public key จาก JWKS
จึงไม่ต้องเรียกกลับมาที่ SSO ทุก request (และยังมี `/oauth/introspect` ไว้ใช้เมื่อต้องการเช็กสด ๆ)

### 5.1 ลงทะเบียนระบบ (ทำครั้งเดียว โดย admin)

```bash
BASE=http://127.0.0.1:8080
ADMIN=$(curl -sS -X POST $BASE/api/v1/auth/login -H 'content-type: application/json' \
  -d '{"email":"admin@example.com","password":"..."}' | jq -r .data.tokens.access_token)

# 1) สร้าง application (public = SPA/mobile, บังคับ PKCE)
curl -sS -X POST $BASE/api/v1/admin/clients \
  -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d '{
        "name": "CRM Dashboard",
        "client_type": "public",
        "redirect_uris": ["https://crm.example.com/callback"],
        "allowed_scopes": ["openid", "profile", "email", "users:read"]
      }'
# → data.client.client_id = "app_xxxxxxxx", data.client_secret = "cs_..." (ใช้ครั้งเดียว)

# 2) ถ้าระบบนั้นเป็น service/cron ให้ออก App Key
curl -sS -X POST $BASE/api/v1/admin/clients/<id>/keys \
  -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d '{"name":"nightly-sync","scopes":["users:read"],"expires_in_days":365}'
# → data.secret = "ssok_live_xxxxxxxx_yyyy..." (แสดงครั้งเดียว เก็บเฉพาะ hash)
```

### 5.2 Flow ผู้ใช้: authorization code + PKCE

1. ระบบปลายทางพา user ไปล็อกอินที่ SSO (frontend ของ SSO เรียก `/api/v1/auth/login` แล้วเก็บ Bearer)
2. ขอ consent: `GET /oauth/authorize/info?...` (ได้ชื่อ app + scopes ที่ขอ + `already_consented`)
3. อนุมัติ: `POST /oauth/authorize` → ได้ `code` (อายุ 5 นาที, ใช้ได้ครั้งเดียว) และ `redirect_url`
4. แลก token ที่หลังบ้าน: `POST /oauth/token` พร้อม `code_verifier`

```bash
VERIFIER=$(openssl rand -base64 60 | tr -d '\n=+/' | cut -c1-64)
CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A \
  | tr '+/' '-_' | tr -d '=')

# 3) อนุมัติ (Bearer = token ของผู้ใช้จาก SSO)
curl -sS -X POST $BASE/oauth/authorize -H "authorization: Bearer $USER_TOKEN" \
  -H 'content-type: application/json' -d "{
    \"response_type\":\"code\",\"client_id\":\"$CLIENT_ID\",
    \"redirect_uri\":\"https://crm.example.com/callback\",\"scope\":\"openid profile email\",
    \"state\":\"random-csrf-state\",\"code_challenge\":\"$CHALLENGE\",
    \"code_challenge_method\":\"S256\"}"

# 4) แลกเป็น token (public client = ส่งแค่ client_id)
curl -sS -X POST $BASE/oauth/token -H 'content-type: application/x-www-form-urlencoded' \
  -d "grant_type=authorization_code&code=$CODE&redirect_uri=https://crm.example.com/callback" \
  -d "client_id=$CLIENT_ID&code_verifier=$VERIFIER"
# → access_token (1 ชม.), refresh_token, id_token (เมื่อขอ scope openid)
```

ได้ `access_token` มาแล้วใช้กับ `/oauth/userinfo` หรือส่งต่อไปยัง resource server ของตัวเองได้เลย

### 5.3 Flow เครื่อง: client_credentials

```bash
# Basic auth หรือ client_id/client_secret ใน body ก็ได้
curl -sS -X POST $BASE/oauth/token -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&scope=users:read'
# → access_token ที่ sub = "client:app_xxx" (ไม่มี refresh token)
```

### 5.4 Flow App Key (ไม่ต้องมี OAuth)

```bash
curl -sS $BASE/api/v1/app/me      -H "x-api-key: $APP_KEY"
curl -sS $BASE/api/v1/app/users   -H "x-api-key: $APP_KEY"?page=1
curl -sS -X POST $BASE/api/v1/app/introspect -H "x-api-key: $APP_KEY" \
  -H 'content-type: application/json' -d '{"token":"<access token>"}'
```

ทุก endpoint ตรวจ scope ของ **key นั้น** (ไม่ใช่ของ app) — key หนึ่งถือได้แค่ subset ของ app
ถ้า scope ไม่พอจะได้ `403 INSUFFICIENT_SCOPE`

### 5.5 ฝั่ง resource server: verify token เอง

```javascript
// Node — npm i jose
import { createRemoteJWKSet, jwtVerify } from 'jose';

const jwks = createRemoteJWKSet(new URL('https://sso.example.com/.well-known/jwks.json'));

export async function requireUser(req) {
  const token = req.headers.authorization?.replace(/^Bearer /, '');
  const { payload } = await jwtVerify(token, jwks, {
    issuer: 'https://sso.example.com',
    audience: 'app_xxxxxxxxxxxx',   // client_id ของระบบเรา
  });
  if (!payload.scope.split(' ').includes('users:read')) throw new Error('forbidden');
  return payload;                    // { sub, email, name, role, scope, exp, ... }
}
```

- ดึง JWKS ครั้งเดียวแล้ว cache (มี `cache-control: public, max-age=300`)
- ตรวจ `iss` (ต้องเท่ากับ `SSO_ISSUER`), `aud` (ต้องเป็น client_id ของตัวเอง), `exp`
- **`aud` สำคัญ**: token ที่ออกให้ระบบอื่นต้องใช้กับเราไม่ได้
- ถ้าต้องการให้การ revoke มีผลทันที ให้เรียก `/oauth/introspect` (หรือ `/api/v1/app/introspect` ด้วย App Key)
  เพราะ access token ที่เซ็นไปแล้วจะยังใช้ได้จนหมดอายุ (`SSO_ACCESS_TTL_SECONDS`)

### 5.6 Scope ที่รองรับ

| Scope | ให้ข้อมูลอะไร |
|---|---|
| `openid` | ออก `id_token` + `sub` + `email` |
| `profile` | `name`, `role` ใน token และ `/oauth/userinfo` |
| `email` | `email`, `email_verified` |
| `offline_access` | สื่อเจตนาขอ refresh token (ระบบนี้ออกให้อยู่แล้วสำหรับ user flow) |
| `users:read` | `/api/v1/app/users*` |
| `users:write` | สงวนไว้สำหรับ endpoint เขียนของผู้ใช้ (ยังไม่เปิด) |
| `tokens:verify` | `/oauth/introspect`, `/api/v1/app/introspect` |
| `audit:read` | สงวนไว้สำหรับอ่าน audit ของ app |
| `read:*` / `write:*` | custom scope สำหรับ resource server ของคุณเอง |

กำหนด scope ได้ต่อ app (`allowed_scopes`) และต่อ key (`scopes`)

### 5.7 ความปลอดภัยของ SSO

- `client_secret` และ App Key เก็บเป็น **SHA-256 hash** — แสดง plaintext ครั้งเดียวตอนสร้าง/rotate
- App Key ฝัง prefix ไว้แสดงผล (`ssok_live_ab12cd34_…`) และเพิกถอนได้ทันที (มีผลกับ request ถัดไป)
- Public client **บังคับ PKCE**; `redirect_uri` ต้องตรงกับที่ลงทะเบียนแบบ exact match (ไม่รับ wildcard)
- Authorization code ใช้ครั้งเดียว, อายุสั้น, ผูกกับ client + redirect_uri + PKCE challenge
- Refresh token หมุนทุกครั้ง; ใช้ตัวเก่าซ้ำ = สัญญาณถูกขโมย → revoke ทั้ง family ของ app+user
- `/oauth/token`, `/oauth/introspect`, `/oauth/revoke` ถูกจำกัด 60 req/นาที/IP (กัน brute-force secret)
- ปิด/ลบ app → app key และ refresh token ตายทันที; access token ที่เซ็นแล้วรอหมดอายุ (ลด TTL ได้)
- ทุกการออก token/เพิกถอน/สร้าง app เขียน audit log (`sso.*`)

## 6. ความปลอดภัยที่ออกแบบไว้

- **รหัสผ่าน**: Argon2id (m=19 MiB, t=2, p=1) + salt สุ่มต่อผู้ใช้; ไม่เก็บ plaintext ไม่ว่ากรณีใด
- **Access token**: HS256, มี `sub`, `sid`, `role`, `jti`, `iss`, `aud`, `exp`; ตรวจ issuer/audience/leeway ทุกครั้ง
- **Refresh token**: สุ่ม 256-bit, เก็บเฉพาะ SHA-256, ใช้ครั้งเดียว, ผูกกับ `family_id` ของ session
- **Reuse detection**: ถ้า token ที่ถูกหมุนแล้วถูกนำมาใช้อีก → revoke ทั้ง family + เขียน audit
- **Revocation ทันที**: middleware ตรวจ session ใน DB ทุก request (`VERIFY_SESSION_ON_REQUEST=true`) ดังนั้น logout/ban มีผลทันที ไม่ต้องรอ token หมดอายุ
- **Timing attack**: login ที่ไม่พบอีเมลยังรัน Argon2 กับ dummy hash เพื่อให้เวลาตอบใกล้เคียง
- **Account lockout**: นับ failed attempt ใน DB, ล็อกพร้อม `Retry-After` (HTTP 423) และล้างเมื่อ login สำเร็จ
- **Anti-enumeration**: forgot-password/resend ตอบข้อความเดียวกันเสมอไม่ว่าบัญชีจะมีจริงหรือไม่
- **RBAC**: role/status ถูกอ่านจาก DB ทุก request (ไม่เชื่อ claim ใน token), มี guard กันแก้ตัวเองและกัน admin คนสุดท้าย
- **2FA**: TOTP SHA1/6 หลัก/30 วินาที skew ±1 step; recovery code เก็บเป็น hash และใช้ได้ครั้งเดียว
- **Transport hygiene**: body limit 1 MB, timeout 30 วินาที, security headers, `cache-control: no-store` สำหรับ `/api`
- **Secrets**: `JWT_SECRET` ต้อง ≥ 32 ตัวอักษร และบังคับใน production (dev เท่านั้นที่สร้างชั่วคราวให้)

---

## 7. โครงสร้างโปรเจกต์

```
src/
  main.rs              bootstrap, tracing, graceful shutdown, background cleanup
  lib.rs               module map
  config.rs            อ่าน/ตรวจ environment ทั้งหมด (ที่เดียว)
  state.rs             AppState (pool, jwt, email, limiter), bootstrap admin
  error.rs             ApiError → JSON envelope + HTTP status
  response.rs          ApiResponse / Page / MessageResponse
  extract.rs           AuthUser, StaffUser, AdminUser, ApiClient (App Key), ClientInfo
  oauth_error.rs       error ตาม RFC 6749/7662 สำหรับ /oauth/*
  middleware.rs        request-id, security headers, global rate limit, 404
  routes.rs            รวมทุก route + layers (CORS, timeout, compression, body limit)
  openapi.rs           OpenAPI document + Swagger UI
  db/                  users, sessions, tokens, two_factor, audit,
                       oauth_clients (apps + app keys), oauth_flow (codes, consents,
                       refresh tokens, JWT denylist)
  security/            password (argon2), jwt (HS256 ผู้ใช้), sso_jwt (RS256 + JWKS),
                       tokens (random/sha256), totp, rate_limit
  services/            auth, users, admin, two_factor, audit, email,
                       clients (จัดการ app + key), sso (protocol ทั้งหมด)
  handlers/            HTTP layer: validate → service → response
                       (auth, users, sessions, two_factor, admin, sso, clients, health)
migrations/            SQL migration ที่ฝังเข้า binary (sqlx::migrate!)
tests/api.rs           integration tests ของ auth/user (19 เคส)
tests/sso.rs           integration tests ของ SSO + app key (8 เคส)
scripts/smoke.sh       end-to-end auth ด้วย curl + jq
scripts/sso-smoke.sh   end-to-end SSO: ลงทะเบียน app → PKCE → token → revoke
scripts/verify_jwt.py  พิสูจน์ว่า token verify ได้ด้วย JWKS อย่างเดียว (cryptography)
```

หลักการ: handler บาง ๆ → service ถือ business rule → db module ถือ SQL
ทำให้เปลี่ยนฐานข้อมูลหรือเพิ่ม endpoint ใหม่ได้โดยไม่แตะตรรกะที่กระจายอยู่

---

## 8. Environment variables

| ตัวแปร | ค่าเริ่มต้น | ความหมาย |
|---|---|---|
| `APP_ENV` | development | `development` / `test` / `production` |
| `APP_NAME` | rust-auth-api | ชื่อบริการ (ใช้ใน issuer ของ TOTP ด้วย) |
| `HOST` / `PORT` | 127.0.0.1 / 8080 | ที่อยู่ที่ bind |
| `DATABASE_URL` | sqlite://./data/auth.db?mode=rwc | path ของ SQLite |
| `DB_MAX_CONNECTIONS` | 10 | ขนาด pool |
| `JWT_SECRET` | (บังคับใน production) | ≥ 32 ตัวอักษร |
| `JWT_ISSUER` / `JWT_AUDIENCE` | rust-auth-api / rust-auth-api-clients | ตรวจใน token |
| `ACCESS_TOKEN_TTL_SECONDS` | 900 | อายุ access token |
| `REFRESH_TOKEN_TTL_SECONDS` | 2592000 | อายุ refresh token (30 วัน) |
| `MFA_TOKEN_TTL_SECONDS` | 300 | อายุ mfa_token |
| `MAX_LOGIN_ATTEMPTS` / `LOCKOUT_SECONDS` | 5 / 900 | นโยบายล็อกบัญชี |
| `PASSWORD_MIN_LENGTH` / `PASSWORD_MAX_LENGTH` | 8 / 128 | นโยบายรหัสผ่าน |
| `REQUIRE_EMAIL_VERIFICATION` | false | บังคับยืนยันอีเมลก่อน login |
| `VERIFY_SESSION_ON_REQUEST` | true | ตรวจ session ทุก request (revoke มีผลทันที) |
| `LOGIN_RATE_LIMIT` / `_WINDOW_SECONDS` | 10 / 60 | จำกัด login ต่อ IP |
| `REGISTER_RATE_LIMIT` / `_WINDOW_SECONDS` | 5 / 3600 | จำกัดสมัครต่อ IP |
| `RESET_RATE_LIMIT` / `_WINDOW_SECONDS` | 5 / 3600 | จำกัด forgot/resend |
| `GLOBAL_RATE_LIMIT` / `_WINDOW_SECONDS` | 300 / 60 | limiter ระดับทั้งบริการ (0 = ปิด) |
| `EMAIL_MODE` | console | `console` (log + outbox) หรือ `disabled` |
| `EMAIL_FROM`, `FRONTEND_URL` | – | ใช้สร้างลิงก์ในอีเมล |
| `EMAIL_VERIFICATION_TTL_SECONDS` / `PASSWORD_RESET_TTL_SECONDS` | 86400 / 3600 | อายุ token |
| `CORS_ALLOWED_ORIGINS` | localhost:3000,5173 | คั่นด้วย comma, `*` = อนุญาตทั้งหมด |
| `TRUST_PROXY` | false | อ่าน IP จาก `x-forwarded-for` (เปิดเมื่ออยู่หลัง reverse proxy) |
| `SWAGGER_ENABLED` | true | เปิด `/docs` |
| `BOOTSTRAP_ADMIN_EMAIL` / `_PASSWORD` / `_NAME` | – | สร้าง superadmin คนแรกตอน start |
| `SSO_ENABLED` | true | เปิด/ปิด `/oauth/*` (ปิดแล้ว token endpoint ตอบ `unauthorized_client`) |
| `SSO_ISSUER` | `http://HOST:PORT` | public base URL ของ SSO — ใช้เป็น `iss` และใน discovery (ต้องตรงกับที่ระบบอื่นเห็น) |
| `SSO_RSA_PRIVATE_KEY` | – | PKCS#8 PEM ของ private key (ใส่ `\n` แบบ escape) — ถ้าไม่ใส่จะสร้างชั่วคราวทุก boot |
| `SSO_ACCESS_TTL_SECONDS` | 3600 | อายุ SSO access token / id_token |
| `SSO_CODE_TTL_SECONDS` | 300 | อายุ authorization code |
| `SSO_REFRESH_TTL_SECONDS` | 2592000 | อายุ SSO refresh token |
| `APP_KEY_PREFIX` | ssok | prefix ของ App Key (`ssok_live_…`) |

---

## 9. การทดสอบ

```bash
cargo test                 # unit 6 + integration 27 (auth 19 + SSO 8)
cargo clippy --all-targets -- -D warnings
./scripts/smoke.sh         # auth end-to-end ด้วย curl (ต้องมี server รันอยู่)
ADMIN_PASSWORD=... ./scripts/sso-smoke.sh   # SSO end-to-end (PKCE, introspect, revoke)
python3 scripts/verify_jwt.py               # verify JWT ด้วย JWKS อย่างเดียว
```

integration test ครอบคลุม: register/duplicate/weak password, login ผิด/ถูกรหัส, account lockout,
token required, refresh rotation + reuse detection, logout revoke ทันที, change password,
password reset ทั้งวงจร, email verification gate, 2FA enroll + login 2 ขั้น, RBAC,
admin จัดการผู้ใช้ + audit logs, rate limit 429, 404 JSON, OpenAPI document

`tests/sso.rs` ครอบคลุม: discovery/JWKS, ลงทะเบียน app + ชื่อซ้ำ, ออก/เพิกถอน/rotate app key,
scope ของ key, authorization code + PKCE (สำเร็จ/ผิด), redirect_uri ที่ไม่ลงทะเบียน,
code ใช้ซ้ำ, refresh rotation + reuse detection, client_credentials + machine token,
secret rotation, ปิด app แล้วตัดสิทธิ์ทันที, RBAC ของ admin API

---

## 10. ขึ้น production (checklist)

1. `JWT_SECRET` จาก secret manager (≥ 32 chars) — อย่าใช้ค่าใน `.env.example`
1.1 `SSO_RSA_PRIVATE_KEY`: `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048` แล้วเก็บใน secret manager
    (ถ้าไม่ตั้ง เครื่องจะสร้าง key ชั่วคราวและ token ทั้งหมดจะเสียทุกครั้งที่ restart)
1.2 `SSO_ISSUER` ต้องเป็น URL จริงที่ระบบอื่นเข้าถึงได้ (https) — เปลี่ยนแล้ว token เก่าจะ verify ไม่ผ่าน
2. `APP_ENV=production` (บังคับให้ต้องมี JWT_SECRET, เปิด HSTS, ปิด `/dev/outbox`)
3. `REQUIRE_EMAIL_VERIFICATION=true` และต่อ email transport จริง (แก้ `EmailService::deliver`)
4. `TRUST_PROXY=true` เมื่ออยู่หลัง nginx/Cloudflare และให้ proxy ส่ง `x-forwarded-for`
5. เปิด HTTPS ที่ proxy, ตั้ง CORS ให้เป็น origin จริงเท่านั้น
6. Backup ไฟล์ `data/auth.db` (โหมด WAL มี `-wal`/`-shm` ควรมาในชุด backup ด้วย)
7. ถ้าหลาย instance: ย้าย rate limiter ไป Redis และเปลี่ยน SQLite → PostgreSQL (ดูข้อ 10)
8. ตั้ง log shipping และเฝ้า `error`/`ACCOUNT_LOCKED`/`RATE_LIMITED` ใน audit

---

## 11. ข้อจำกัดที่รู้ตัว / ทางต่อยอด

- **Email transport**: ค่าเริ่มต้นเป็น console (ไม่ส่งออกจริง) — จุดต่อเดียวคือ `EmailService::deliver`
- **SQLite**: เหมาะกับ single-node; หลาย instance ต้องใช้ PostgreSQL (query ส่วนใหญ่เป็น SQL มาตรฐาน,
  เปลี่ยน `SqlitePool` → `PgPool` และ tipo `?` → `$1`; โครงสร้างถูกแยกไว้ใน `db/` แล้ว)
- **Rate limiter**: in-memory ต่อ process — หลาย node ต้องใช้ Redis
- **SSO**: access token ที่เซ็นแล้วไม่ถูกเพิกถอนทันทีเมื่อปิด app (รอหมดอายุ) — ถ้าต้องการแบบนั้น
  ให้ลด `SSO_ACCESS_TTL_SECONDS` หรือตรวจ `/oauth/introspect` ทุก request (แลกมาด้วย latency)
- **SSO**: ยังไม่มีหน้าจอ consent ให้ผู้ใช้เลือก scope เอง — `POST /oauth/authorize` คือการอนุมัติ
  (frontend ของ SSO เป็นคนแสดงรายละเอียดจาก `/oauth/authorize/info` แล้วเรียกต่อ) และไม่รองรับ `nonce`
- **ยังไม่มี**: social login (Google/GitHub), WebAuthn/passkeys, magic link, SAML, การเข้ารหัส
  TOTP secret at-rest (ควรใช้ KMS + AES-GCM ใน production จริงจัง), email change double-opt-in
- **mfa_token** อายุ 5 นาทีและใช้ซ้ำได้ภายในหน้าต่างนั้น (ออกแบบให้ stateless) — ถ้าต้อง single-use
  ให้เพิ่มตาราง nonce

---

## License

MIT
