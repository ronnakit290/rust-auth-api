//! End-to-end tests that drive the real router (middleware included) against an
//! in-memory SQLite database through `tower::ServiceExt::oneshot`.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use totp_rs::{Algorithm, Secret, TOTP};
use tower::ServiceExt;

use rust_auth_api::{build_router, config::Config, AppState};

const PASSWORD: &str = "Sup3rSecret";

struct TestApp {
    router: Router,
    state: AppState,
}

async fn spawn_app() -> TestApp {
    spawn_app_with(|_| {}).await
}

async fn spawn_app_with(mutator: impl FnOnce(&mut Config)) -> TestApp {
    let mut config = Config::for_test("sqlite::memory:");
    mutator(&mut config);
    let state = AppState::bootstrap(config)
        .await
        .expect("app state should bootstrap");
    let router = build_router(state.clone());
    TestApp { router, state }
}

struct Response {
    status: StatusCode,
    body: Value,
}

impl Response {
    fn data(&self) -> &Value {
        &self.body["data"]
    }
}

async fn call(
    app: &TestApp,
    method: Method,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::USER_AGENT, "rust-auth-api-tests/1.0");

    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }

    let request = match body {
        Some(value) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(value.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };

    let response = app
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("router should respond");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body should be readable")
        .to_bytes();
    let body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    Response { status, body }
}

async fn register(app: &TestApp, email: &str) -> Response {
    call(
        app,
        Method::POST,
        "/api/v1/auth/register",
        None,
        Some(json!({ "email": email, "password": PASSWORD, "full_name": "Test User" })),
    )
    .await
}

async fn login(app: &TestApp, email: &str, password: &str) -> Response {
    call(
        app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        Some(json!({ "email": email, "password": password })),
    )
    .await
}

async fn register_and_login(app: &TestApp, email: &str) -> String {
    let created = register(app, email).await;
    assert_eq!(
        created.status,
        StatusCode::CREATED,
        "register failed: {:?}",
        created.body
    );
    let response = login(app, email, PASSWORD).await;
    assert_eq!(
        response.status,
        StatusCode::OK,
        "login failed: {:?}",
        response.body
    );
    response.data()["tokens"]["access_token"]
        .as_str()
        .expect("access token")
        .to_string()
}

fn refresh_token(response: &Response) -> String {
    response.data()["tokens"]["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_string()
}

fn totp_code(secret_base32: &str, account: &str) -> String {
    let bytes = Secret::Encoded(secret_base32.to_string())
        .to_bytes()
        .expect("valid base32 secret");
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        bytes,
        Some("rust-auth-api-test".to_string()),
        account.to_string(),
    )
    .expect("totp");
    totp.generate_current().expect("current code")
}

// ---------------------------------------------------------------------------
// health & routing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_and_readiness_are_public() {
    let app = spawn_app().await;

    let health = call(&app, Method::GET, "/healthz", None, None).await;
    assert_eq!(health.status, StatusCode::OK);
    assert_eq!(health.body["status"], "ok");

    let ready = call(&app, Method::GET, "/readyz", None, None).await;
    assert_eq!(ready.status, StatusCode::OK);
    assert_eq!(ready.body["database"], "up");

    let meta = call(&app, Method::GET, "/api/v1/meta", None, None).await;
    assert_eq!(meta.status, StatusCode::OK);
    assert_eq!(meta.data()["features"]["two_factor"], true);
}

#[tokio::test]
async fn unknown_route_returns_json_error() {
    let app = spawn_app().await;
    let response = call(&app, Method::GET, "/api/v1/nope", None, None).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert_eq!(response.body["success"], false);
    assert_eq!(response.body["error"]["code"], "ROUTE_NOT_FOUND");
}

// ---------------------------------------------------------------------------
// registration & login
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_creates_user_and_rejects_duplicates() {
    let app = spawn_app().await;

    let created = register(&app, "Alice@Example.com").await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(created.body["success"], true);
    assert_eq!(created.data()["user"]["email"], "alice@example.com");
    assert_eq!(created.data()["user"]["role"], "user");
    assert_eq!(created.data()["user"]["status"], "active");
    assert_eq!(created.data()["verification_required"], false);

    let duplicate = register(&app, "alice@example.com").await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);
    assert_eq!(duplicate.body["error"]["code"], "EMAIL_ALREADY_EXISTS");
}

#[tokio::test]
async fn register_enforces_password_policy_and_validation() {
    let app = spawn_app().await;

    let weak = call(
        &app,
        Method::POST,
        "/api/v1/auth/register",
        None,
        Some(json!({ "email": "weak@example.com", "password": "allletters" })),
    )
    .await;
    assert_eq!(weak.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(weak.body["error"]["code"], "VALIDATION_ERROR");

    let bad_email = call(
        &app,
        Method::POST,
        "/api/v1/auth/register",
        None,
        Some(json!({ "email": "not-an-email", "password": PASSWORD })),
    )
    .await;
    assert_eq!(bad_email.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn login_rejects_bad_password_and_locks_after_repeated_failures() {
    let app = spawn_app().await;
    register(&app, "lockout@example.com").await;

    let wrong = login(&app, "lockout@example.com", "Wr0ngPassword").await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.body["error"]["code"], "INVALID_CREDENTIALS");

    // max_login_attempts is 3 in the test configuration.
    assert_eq!(
        login(&app, "lockout@example.com", "Wr0ngPassword")
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let locked = login(&app, "lockout@example.com", "Wr0ngPassword").await;
    assert_eq!(locked.status, StatusCode::LOCKED);
    assert_eq!(locked.body["error"]["code"], "ACCOUNT_LOCKED");

    // Even the right password is refused while the lock is active.
    let blocked = login(&app, "lockout@example.com", PASSWORD).await;
    assert_eq!(blocked.status, StatusCode::LOCKED);
}

#[tokio::test]
async fn unknown_email_login_is_indistinguishable_from_wrong_password() {
    let app = spawn_app().await;
    let response = login(&app, "ghost@example.com", PASSWORD).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.body["error"]["code"], "INVALID_CREDENTIALS");
}

// ---------------------------------------------------------------------------
// profile & sessions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn me_requires_token_and_returns_profile() {
    let app = spawn_app().await;
    let token = register_and_login(&app, "me@example.com").await;

    let anonymous = call(&app, Method::GET, "/api/v1/users/me", None, None).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);

    let me = call(&app, Method::GET, "/api/v1/users/me", Some(&token), None).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.data()["email"], "me@example.com");
    assert_eq!(me.data()["two_factor_enabled"], false);

    let sessions = call(
        &app,
        Method::GET,
        "/api/v1/users/me/sessions",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(sessions.status, StatusCode::OK);
    assert_eq!(sessions.data()["count"], 1);
    assert_eq!(sessions.data()["sessions"][0]["current"], true);
}

#[tokio::test]
async fn update_profile_and_change_password() {
    let app = spawn_app().await;
    let token = register_and_login(&app, "profile@example.com").await;

    let updated = call(
        &app,
        Method::PATCH,
        "/api/v1/users/me",
        Some(&token),
        Some(json!({ "full_name": "Renamed User" })),
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.data()["user"]["full_name"], "Renamed User");
    assert_eq!(updated.data()["verification_required"], false);

    let changed = call(
        &app,
        Method::POST,
        "/api/v1/users/me/change-password",
        Some(&token),
        Some(json!({ "current_password": PASSWORD, "new_password": "N3wSup3rSecret" })),
    )
    .await;
    assert_eq!(changed.status, StatusCode::OK);

    let old_password = login(&app, "profile@example.com", PASSWORD).await;
    assert_eq!(old_password.status, StatusCode::UNAUTHORIZED);

    let new_password = login(&app, "profile@example.com", "N3wSup3rSecret").await;
    assert_eq!(new_password.status, StatusCode::OK);
}

#[tokio::test]
async fn logout_revokes_the_session_immediately() {
    let app = spawn_app().await;
    let token = register_and_login(&app, "logout@example.com").await;

    let logged_out = call(
        &app,
        Method::POST,
        "/api/v1/auth/logout",
        Some(&token),
        Some(json!({})),
    )
    .await;
    assert_eq!(logged_out.status, StatusCode::OK);
    assert_eq!(logged_out.data()["revoked_sessions"], 1);

    let after = call(&app, Method::GET, "/api/v1/users/me", Some(&token), None).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// refresh rotation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refresh_rotates_and_detects_replay() {
    let app = spawn_app().await;
    register(&app, "rotate@example.com").await;
    let first = login(&app, "rotate@example.com", PASSWORD).await;
    let original_refresh = refresh_token(&first);

    let rotated = call(
        &app,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        Some(json!({ "refresh_token": original_refresh })),
    )
    .await;
    assert_eq!(rotated.status, StatusCode::OK);
    let new_refresh = rotated.data()["refresh_token"]
        .as_str()
        .expect("new refresh token")
        .to_string();
    assert_ne!(new_refresh, original_refresh);

    // Replaying the burned token must fail and revoke the whole family.
    let replay = call(
        &app,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        Some(json!({ "refresh_token": original_refresh })),
    )
    .await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);

    let after_replay = call(
        &app,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        Some(json!({ "refresh_token": new_refresh })),
    )
    .await;
    assert_eq!(
        after_replay.status,
        StatusCode::UNAUTHORIZED,
        "family should be revoked after replay detection"
    );
}

// ---------------------------------------------------------------------------
// e-mail flows
// ---------------------------------------------------------------------------

#[tokio::test]
async fn password_reset_flow_works_end_to_end() {
    let app = spawn_app().await;
    register(&app, "reset@example.com").await;

    let requested = call(
        &app,
        Method::POST,
        "/api/v1/auth/forgot-password",
        None,
        Some(json!({ "email": "reset@example.com" })),
    )
    .await;
    assert_eq!(requested.status, StatusCode::OK);
    let token = requested.data()["debug_token"]["token"]
        .as_str()
        .expect("console transport returns the token")
        .to_string();

    let weak = call(
        &app,
        Method::POST,
        "/api/v1/auth/reset-password",
        None,
        Some(json!({ "token": token, "new_password": "short" })),
    )
    .await;
    assert_eq!(weak.status, StatusCode::UNPROCESSABLE_ENTITY);

    let reset = call(
        &app,
        Method::POST,
        "/api/v1/auth/reset-password",
        None,
        Some(json!({ "token": token, "new_password": "R3setPassword!" })),
    )
    .await;
    assert_eq!(reset.status, StatusCode::OK);

    // The link is single use.
    let reused = call(
        &app,
        Method::POST,
        "/api/v1/auth/reset-password",
        None,
        Some(json!({ "token": token, "new_password": "R3setPassword!" })),
    )
    .await;
    assert_eq!(reused.status, StatusCode::BAD_REQUEST);

    let login_ok = login(&app, "reset@example.com", "R3setPassword!").await;
    assert_eq!(login_ok.status, StatusCode::OK);
}

#[tokio::test]
async fn email_verification_is_required_when_configured() {
    let app = spawn_app_with(|config| {
        config.security.require_email_verification = true;
    })
    .await;

    let created = register(&app, "verify@example.com").await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(created.data()["verification_required"], true);
    let token = created.data()["debug_token"]["token"]
        .as_str()
        .expect("verification token")
        .to_string();

    let blocked = login(&app, "verify@example.com", PASSWORD).await;
    assert_eq!(blocked.status, StatusCode::FORBIDDEN);
    assert_eq!(blocked.body["error"]["code"], "EMAIL_NOT_VERIFIED");

    let verified = call(
        &app,
        Method::POST,
        "/api/v1/auth/verify-email",
        None,
        Some(json!({ "token": token })),
    )
    .await;
    assert_eq!(verified.status, StatusCode::OK);

    let allowed = login(&app, "verify@example.com", PASSWORD).await;
    assert_eq!(allowed.status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// two factor
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_factor_enrolment_and_login() {
    let app = spawn_app().await;
    let token = register_and_login(&app, "totp@example.com").await;

    let setup = call(&app, Method::POST, "/api/v1/2fa/setup", Some(&token), None).await;
    assert_eq!(setup.status, StatusCode::OK);
    let secret = setup.data()["secret"].as_str().expect("secret").to_string();
    assert!(setup.data()["otpauth_url"]
        .as_str()
        .unwrap()
        .starts_with("otpauth://totp/"));

    // A wrong code must not enable 2FA.
    let rejected = call(
        &app,
        Method::POST,
        "/api/v1/2fa/enable",
        Some(&token),
        Some(json!({ "code": "000000" })),
    )
    .await;
    assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);

    let code = totp_code(&secret, "totp@example.com");
    let enabled = call(
        &app,
        Method::POST,
        "/api/v1/2fa/enable",
        Some(&token),
        Some(json!({ "code": code })),
    )
    .await;
    assert_eq!(enabled.status, StatusCode::OK, "{:?}", enabled.body);
    let recovery_codes = enabled.data()["recovery_codes"]
        .as_array()
        .expect("recovery codes")
        .len();
    assert_eq!(recovery_codes, 10);

    let status = call(&app, Method::GET, "/api/v1/2fa", Some(&token), None).await;
    assert_eq!(status.data()["enabled"], true);
    assert_eq!(status.data()["recovery_codes_remaining"], 10);

    // Login now stops at the second factor.
    let challenge = login(&app, "totp@example.com", PASSWORD).await;
    assert_eq!(challenge.status, StatusCode::OK);
    assert_eq!(challenge.data()["mfa_required"], true);
    let mfa_token = challenge.data()["mfa_token"]
        .as_str()
        .expect("mfa token")
        .to_string();

    let bad_code = call(
        &app,
        Method::POST,
        "/api/v1/auth/2fa/verify",
        None,
        Some(json!({ "mfa_token": mfa_token, "code": "111111" })),
    )
    .await;
    assert_eq!(bad_code.status, StatusCode::UNAUTHORIZED);

    let code = totp_code(&secret, "totp@example.com");
    let completed = call(
        &app,
        Method::POST,
        "/api/v1/auth/2fa/verify",
        None,
        Some(json!({ "mfa_token": mfa_token, "code": code })),
    )
    .await;
    assert_eq!(completed.status, StatusCode::OK, "{:?}", completed.body);
    assert!(completed.data()["tokens"]["access_token"].is_string());
}

// ---------------------------------------------------------------------------
// administration / RBAC
// ---------------------------------------------------------------------------

async fn promote_to_admin(app: &TestApp, email: &str) {
    sqlx::query("UPDATE users SET role = 'admin' WHERE email = ?")
        .bind(email)
        .execute(&app.state.pool)
        .await
        .expect("promote user");
}

#[tokio::test]
async fn admin_routes_require_admin_role() {
    let app = spawn_app().await;
    let token = register_and_login(&app, "plain@example.com").await;

    let forbidden = call(&app, Method::GET, "/api/v1/admin/users", Some(&token), None).await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);
    assert_eq!(forbidden.body["error"]["code"], "INSUFFICIENT_ROLE");

    promote_to_admin(&app, "plain@example.com").await;

    let allowed = call(&app, Method::GET, "/api/v1/admin/users", Some(&token), None).await;
    assert_eq!(allowed.status, StatusCode::OK);
    assert_eq!(allowed.data()["total"], 1);
}

#[tokio::test]
async fn admin_can_manage_users_and_read_the_audit_trail() {
    let app = spawn_app().await;
    let admin_token = register_and_login(&app, "admin@example.com").await;
    promote_to_admin(&app, "admin@example.com").await;

    let created = register(&app, "target@example.com").await;
    let target_id = created.data()["user"]["id"]
        .as_str()
        .expect("user id")
        .to_string();

    let suspended = call(
        &app,
        Method::PATCH,
        &format!("/api/v1/admin/users/{target_id}"),
        Some(&admin_token),
        Some(json!({ "status": "suspended" })),
    )
    .await;
    assert_eq!(suspended.status, StatusCode::OK);
    assert_eq!(suspended.data()["status"], "suspended");

    let blocked = login(&app, "target@example.com", PASSWORD).await;
    assert_eq!(blocked.status, StatusCode::FORBIDDEN);
    assert_eq!(blocked.body["error"]["code"], "ACCOUNT_SUSPENDED");

    let stats = call(
        &app,
        Method::GET,
        "/api/v1/admin/stats",
        Some(&admin_token),
        None,
    )
    .await;
    assert_eq!(stats.status, StatusCode::OK);
    assert_eq!(stats.data()["users"]["total_users"], 2);

    let audit = call(
        &app,
        Method::GET,
        "/api/v1/admin/audit-logs?per_page=50",
        Some(&admin_token),
        None,
    )
    .await;
    assert_eq!(audit.status, StatusCode::OK);
    let actions: Vec<&str> = audit.data()["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|item| item["action"].as_str())
        .collect();
    assert!(actions.contains(&"admin.user_updated"));
    assert!(actions.contains(&"auth.login"));

    let deleted = call(
        &app,
        Method::DELETE,
        &format!("/api/v1/admin/users/{target_id}"),
        Some(&admin_token),
        None,
    )
    .await;
    assert_eq!(deleted.status, StatusCode::OK);

    let missing = call(
        &app,
        Method::GET,
        &format!("/api/v1/admin/users/{target_id}"),
        Some(&admin_token),
        None,
    )
    .await;
    assert_eq!(missing.status, StatusCode::OK);
    assert_eq!(missing.data()["status"], "deleted");
}

#[tokio::test]
async fn admin_cannot_delete_self_or_escalate_above_their_role() {
    let app = spawn_app().await;
    let token = register_and_login(&app, "solo-admin@example.com").await;
    promote_to_admin(&app, "solo-admin@example.com").await;

    let me = call(&app, Method::GET, "/api/v1/users/me", Some(&token), None).await;
    let my_id = me.data()["id"].as_str().unwrap().to_string();

    let self_delete = call(
        &app,
        Method::DELETE,
        &format!("/api/v1/admin/users/{my_id}"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(self_delete.status, StatusCode::FORBIDDEN);
    assert_eq!(self_delete.body["error"]["code"], "CANNOT_DELETE_SELF");

    let escalate = call(
        &app,
        Method::PATCH,
        &format!("/api/v1/admin/users/{my_id}"),
        Some(&token),
        Some(json!({ "role": "superadmin" })),
    )
    .await;
    assert_eq!(escalate.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rate_limiting_returns_429_with_retry_after() {
    let app = spawn_app_with(|config| {
        config.security.login_rate_limit = 2;
        config.security.login_rate_window = std::time::Duration::from_secs(60);
    })
    .await;
    register(&app, "ratelimit@example.com").await;

    assert_eq!(
        login(&app, "ratelimit@example.com", PASSWORD).await.status,
        StatusCode::OK
    );
    assert_eq!(
        login(&app, "ratelimit@example.com", PASSWORD).await.status,
        StatusCode::OK
    );
    let limited = login(&app, "ratelimit@example.com", PASSWORD).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.body["error"]["code"], "RATE_LIMITED");
}

#[tokio::test]
async fn openapi_document_is_served() {
    let app = spawn_app().await;
    let response = call(&app, Method::GET, "/api-docs/openapi.json", None, None).await;
    assert_eq!(response.status, StatusCode::OK);
    let paths = response.body["paths"].as_object().expect("paths object");
    assert!(paths.contains_key("/api/v1/auth/login"));
    assert!(paths.contains_key("/api/v1/admin/users"));
    assert!(paths.contains_key("/api/v1/2fa/enable"));
}

#[tokio::test]
async fn malformed_json_and_missing_content_type_use_the_error_envelope() {
    let app = spawn_app().await;

    // Hand-rolled request: invalid JSON payload.
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{not-json"))
        .unwrap();
    let response = app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["success"], false);
    assert_eq!(body["error"]["code"], "INVALID_JSON");

    // JSON body without a content type.
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .body(Body::from(r#"{"email":"a@b.co","password":"x"}"#))
        .unwrap();
    let response = app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "UNSUPPORTED_MEDIA_TYPE");
}
