# Rust Auth API

ระบบ Authentication + User Management API แบบครบวงจร เขียนด้วยภาษา Rust
(Axum 0.8 + SQLx 0.8 + SQLite + JWT + Argon2id + TOTP) พร้อม OpenAPI/Swagger

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

Platform
- Response envelope มาตรฐาน + error code ที่เครื่องอ่านได้
- Validation ครบทุก body (`validator`) → 422 พร้อมรายละเอียดรายฟิลด์
- Request id (`x-request-id`) ทุก response, security headers, CORS, compression, timeout, body limit 1 MB
- Health probes: `/healthz` (liveness), `/readyz` (ตรวจ DB จริง)
- Graceful shutdown (SIGTERM/Ctrl+C) + background purge session หมดอายุทุกชั่วโมง
- Email transport แบบ console (log + in-memory outbox สำหรับ dev/test) สลับเป็น SMTP/API ได้ที่จุดเดียว
- Integration tests 18 เคส + unit tests 5 เคส + smoke script ยิง API จริงด้วย curl

---

## 2. เริ่มใช้งานเร็ว (Quick start)

```bash
cd rust-auth-api
cp .env.example .env          # แก้ JWT_SECRET ให้ยาว >= 32 ตัวอักษร
cargo run
```

เปิด `http://127.0.0.1:8080/docs` จะเห็น Swagger UI ของทุก endpoint

ทดสอบทั้งระบบด้วยสคริปต์:

```bash
./scripts/smoke.sh                                  # default http://127.0.0.1:8080
BASE_URL=http://127.0.0.1:8080 ADMIN_EMAIL=... ./scripts/smoke.sh
```

สร้าง superadmin คนแรกผ่าน environment (สร้างให้อัตโนมัติตอน start ถ้ายังไม่มี):

```bash
BOOTSTRAP_ADMIN_EMAIL=admin@example.com \
BOOTSTRAP_ADMIN_PASSWORD='Admin12345' \
cargo run
```

หรือใช้ Docker:

```bash
JWT_SECRET=$(openssl rand -hex 32) docker compose up --build
```

---

## 3. Endpoint ทั้งหมด

ทุก path อยู่ใต้ `/api/v1` (ยกเว้น probes) และทุก response ถูกห่อด้วย
`{"success": true, "data": ...}` หรือ `{"success": false, "error": {"code", "message", "details"}}`

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

## 5. ความปลอดภัยที่ออกแบบไว้

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

## 6. โครงสร้างโปรเจกต์

```
src/
  main.rs              bootstrap, tracing, graceful shutdown, background cleanup
  lib.rs               module map
  config.rs            อ่าน/ตรวจ environment ทั้งหมด (ที่เดียว)
  state.rs             AppState (pool, jwt, email, limiter), bootstrap admin
  error.rs             ApiError → JSON envelope + HTTP status
  response.rs          ApiResponse / Page / MessageResponse
  extract.rs           AuthUser, StaffUser, AdminUser, ClientInfo (Bearer + DB lookup)
  middleware.rs        request-id, security headers, global rate limit, 404
  routes.rs            รวมทุก route + layers (CORS, timeout, compression, body limit)
  openapi.rs           OpenAPI document + Swagger UI
  db/                  users, sessions, tokens, two_factor, audit (SQL ตรง ๆ ต่อ aggregate)
  security/            password (argon2), jwt, tokens (random/sha256), totp, rate_limit
  services/            auth, users, admin, two_factor, audit, email (workflow ทั้งหมด)
  handlers/            HTTP layer: validate → service → response
migrations/            SQL migration ที่ฝังเข้า binary (sqlx::migrate!)
tests/api.rs           integration tests ยิงผ่าน router จริง
scripts/smoke.sh       end-to-end ด้วย curl + jq
```

หลักการ: handler บาง ๆ → service ถือ business rule → db module ถือ SQL
ทำให้เปลี่ยนฐานข้อมูลหรือเพิ่ม endpoint ใหม่ได้โดยไม่แตะตรรกะที่กระจายอยู่

---

## 7. Environment variables

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

---

## 8. การทดสอบ

```bash
cargo test                 # unit tests (5) + integration tests (18)
cargo clippy --all-targets # 0 warnings
./scripts/smoke.sh         # ยิง API จริงด้วย curl (ต้องมี server รันอยู่)
```

integration test ครอบคลุม: register/duplicate/weak password, login ผิด/ถูกรหัส, account lockout,
token required, refresh rotation + reuse detection, logout revoke ทันที, change password,
password reset ทั้งวงจร, email verification gate, 2FA enroll + login 2 ขั้น, RBAC,
admin จัดการผู้ใช้ + audit logs, rate limit 429, 404 JSON, OpenAPI document

---

## 9. ขึ้น production (checklist)

1. `JWT_SECRET` จาก secret manager (≥ 32 chars) — อย่าใช้ค่าใน `.env.example`
2. `APP_ENV=production` (บังคับให้ต้องมี JWT_SECRET, เปิด HSTS, ปิด `/dev/outbox`)
3. `REQUIRE_EMAIL_VERIFICATION=true` และต่อ email transport จริง (แก้ `EmailService::deliver`)
4. `TRUST_PROXY=true` เมื่ออยู่หลัง nginx/Cloudflare และให้ proxy ส่ง `x-forwarded-for`
5. เปิด HTTPS ที่ proxy, ตั้ง CORS ให้เป็น origin จริงเท่านั้น
6. Backup ไฟล์ `data/auth.db` (โหมด WAL มี `-wal`/`-shm` ควรมาในชุด backup ด้วย)
7. ถ้าหลาย instance: ย้าย rate limiter ไป Redis และเปลี่ยน SQLite → PostgreSQL (ดูข้อ 10)
8. ตั้ง log shipping และเฝ้า `error`/`ACCOUNT_LOCKED`/`RATE_LIMITED` ใน audit

---

## 10. ข้อจำกัดที่รู้ตัว / ทางต่อยอด

- **Email transport**: ค่าเริ่มต้นเป็น console (ไม่ส่งออกจริง) — จุดต่อเดียวคือ `EmailService::deliver`
- **SQLite**: เหมาะกับ single-node; หลาย instance ต้องใช้ PostgreSQL (query ส่วนใหญ่เป็น SQL มาตรฐาน,
  เปลี่ยน `SqlitePool` → `PgPool` และ tipo `?` → `$1`; โครงสร้างถูกแยกไว้ใน `db/` แล้ว)
- **Rate limiter**: in-memory ต่อ process — หลาย node ต้องใช้ Redis
- **ยังไม่มี**: OAuth/social login, WebAuthn/passkeys, magic link, API keys, email change confirmation
  แบบ double-opt-in, และการเข้ารหัส TOTP secret at-rest (ควรใช้ KMS + AES-GCM ใน production จริงจัง)
- **mfa_token** อายุ 5 นาทีและใช้ซ้ำได้ภายในหน้าต่างนั้น (ออกแบบให้ stateless) — ถ้าต้อง single-use
  ให้เพิ่มตาราง nonce

---

## License

MIT
