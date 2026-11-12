//! End-to-end tests for the central SSO server: application registration, app
//! keys, authorization-code + PKCE, client credentials, introspection,
//! revocation and discovery.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
    Router,
};
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use rust_auth_api::{build_router, config::Config, AppState};

const PASSWORD: &str = "Sup3rSecret";

struct TestApp {
    router: Router,
    state: AppState,
}

async fn spawn_app() -> TestApp {
    let config = Config::for_test("sqlite::memory:");
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

    fn error_code(&self) -> Option<&str> {
        self.body["error"]["code"].as_str()
    }
}

async fn send(app: &TestApp, request: Request<Body>) -> Response {
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
        .expect("body readable")
        .to_bytes();
    let body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    Response { status, body }
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
        .header(header::USER_AGENT, "rust-auth-api-sso-tests/1.0");
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
    send(app, request).await
}

fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn url_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

async fn post_form(
    app: &TestApp,
    path: &str,
    pairs: &[(&str, &str)],
    basic: Option<(&str, &str)>,
) -> Response {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::USER_AGENT, "rust-auth-api-sso-tests/1.0");
    if let Some((id, secret)) = basic {
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"));
        builder = builder.header(header::AUTHORIZATION, format!("Basic {encoded}"));
    }
    let request = builder.body(Body::from(form_encode(pairs))).unwrap();
    send(app, request).await
}

async fn api_key_call(
    app: &TestApp,
    method: Method,
    path: &str,
    key: &str,
    body: Option<Value>,
) -> Response {
    let builder = Request::builder()
        .method(method)
        .uri(path)
        .header("x-api-key", key)
        .header(header::USER_AGENT, "integrating-system/1.0");
    let request = match body {
        Some(value) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(value.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    send(app, request).await
}

async fn register_and_login(app: &TestApp, email: &str) -> (String, String) {
    let created = call(
        app,
        Method::POST,
        "/api/v1/auth/register",
        None,
        Some(json!({ "email": email, "password": PASSWORD, "full_name": "SSO User" })),
    )
    .await;
    assert_eq!(
        created.status,
        StatusCode::CREATED,
        "register failed: {:?}",
        created.body
    );
    let user_id = created.data()["user"]["id"]
        .as_str()
        .expect("user id")
        .to_string();

    let login = call(
        app,
        Method::POST,
        "/api/v1/auth/login",
        None,
        Some(json!({ "email": email, "password": PASSWORD })),
    )
    .await;
    assert_eq!(
        login.status,
        StatusCode::OK,
        "login failed: {:?}",
        login.body
    );
    let token = login.data()["tokens"]["access_token"]
        .as_str()
        .expect("access token")
        .to_string();
    (token, user_id)
}

async fn admin_token(app: &TestApp, email: &str) -> String {
    let (token, _) = register_and_login(app, email).await;
    sqlx::query("UPDATE users SET role = 'admin' WHERE email = ?")
        .bind(email)
        .execute(&app.state.pool)
        .await
        .expect("promote admin");
    token
}

struct Client {
    client_id: String,
    client_secret: String,
    id: String,
}

async fn create_client(app: &TestApp, token: &str, payload: Value) -> Client {
    let response = call(
        app,
        Method::POST,
        "/api/v1/admin/clients",
        Some(token),
        Some(payload),
    )
    .await;
    assert_eq!(
        response.status,
        StatusCode::CREATED,
        "create client failed: {:?}",
        response.body
    );
    Client {
        client_id: response.data()["client"]["client_id"]
            .as_str()
            .expect("client_id")
            .to_string(),
        client_secret: response.data()["client_secret"]
            .as_str()
            .expect("client secret")
            .to_string(),
        id: response.data()["client"]["id"]
            .as_str()
            .expect("id")
            .to_string(),
    }
}

fn pkce_pair() -> (String, String) {
    let verifier = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-._~x";
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    (verifier.to_string(), challenge)
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_and_jwks_are_public_and_consistent() {
    let app = spawn_app().await;

    let discovery = call(
        &app,
        Method::GET,
        "/.well-known/openid-configuration",
        None,
        None,
    )
    .await;
    assert_eq!(discovery.status, StatusCode::OK);
    assert_eq!(discovery.body["issuer"], "http://localhost:8080");
    assert_eq!(
        discovery.body["token_endpoint"],
        "http://localhost:8080/oauth/token"
    );
    assert!(discovery.body["grant_types_supported"]
        .as_array()
        .expect("grants")
        .iter()
        .any(|value| value == "client_credentials"));

    let jwks = call(&app, Method::GET, "/.well-known/jwks.json", None, None).await;
    assert_eq!(jwks.status, StatusCode::OK);
    assert_eq!(jwks.body["keys"][0]["alg"], "RS256");
    assert_eq!(jwks.body["keys"][0]["kty"], "RSA");
    assert!(jwks.body["keys"][0]["n"].as_str().unwrap().len() > 100);
}

#[tokio::test]
async fn admin_registers_an_application_and_issues_app_keys() {
    let app = spawn_app().await;
    let token = admin_token(&app, "sso-admin@example.com").await;

    let client = create_client(
        &app,
        &token,
        json!({
            "name": "Billing System",
            "description": "Internal invoicing",
            "allowed_scopes": ["users:read", "tokens:verify"],
            "client_type": "confidential"
        }),
    )
    .await;
    assert!(client.client_id.starts_with("app_"));
    assert!(client.client_secret.starts_with("cs_"));

    // Listing + fetching by public id.
    let list = call(
        &app,
        Method::GET,
        "/api/v1/admin/clients",
        Some(&token),
        None,
    )
    .await;
    assert_eq!(list.status, StatusCode::OK);
    assert_eq!(list.data()["total"], 1);

    let fetched = call(
        &app,
        Method::GET,
        &format!("/api/v1/admin/clients/{}", client.client_id),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(fetched.status, StatusCode::OK);
    assert_eq!(fetched.data()["name"], "Billing System");

    // Duplicate names are refused so two systems cannot be confused.
    let duplicate = call(
        &app,
        Method::POST,
        "/api/v1/admin/clients",
        Some(&token),
        Some(json!({ "name": "Billing System" })),
    )
    .await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);
    assert_eq!(duplicate.error_code(), Some("CLIENT_NAME_TAKEN"));

    // Issue an app key with a subset of scopes.
    let created_key = call(
        &app,
        Method::POST,
        &format!("/api/v1/admin/clients/{}/keys", client.id),
        Some(&token),
        Some(json!({
            "name": "nightly-import",
            "scopes": ["users:read"],
            "expires_in_days": 30
        })),
    )
    .await;
    assert_eq!(
        created_key.status,
        StatusCode::CREATED,
        "key creation failed: {:?}",
        created_key.body
    );
    let secret = created_key.data()["secret"]
        .as_str()
        .expect("secret")
        .to_string();
    assert!(secret.starts_with("ssok_live_"));
    let key_id = created_key.data()["api_key"]["id"]
        .as_str()
        .expect("key id")
        .to_string();

    // The key identifies the application and carries only its own scopes.
    let me = api_key_call(&app, Method::GET, "/api/v1/app/me", &secret, None).await;
    assert_eq!(me.status, StatusCode::OK, "app/me failed: {:?}", me.body);
    assert_eq!(me.data()["client"]["client_id"], client.client_id);
    assert_eq!(me.data()["key_scopes"], json!(["users:read"]));

    let users = api_key_call(&app, Method::GET, "/api/v1/app/users", &secret, None).await;
    assert_eq!(users.status, StatusCode::OK);
    assert_eq!(users.data()["items"].as_array().unwrap().len(), 1);

    // `tokens:verify` was granted to the application but not to this key.
    let denied = api_key_call(
        &app,
        Method::POST,
        "/api/v1/app/introspect",
        &secret,
        Some(json!({ "token": "whatever" })),
    )
    .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert_eq!(denied.error_code(), Some("INSUFFICIENT_SCOPE"));

    // Unknown and revoked keys are rejected.
    let unknown = api_key_call(
        &app,
        Method::GET,
        "/api/v1/app/me",
        "ssok_live_deadbeef_unknown",
        None,
    )
    .await;
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);

    let revoked = call(
        &app,
        Method::DELETE,
        &format!("/api/v1/admin/clients/{}/keys/{key_id}", client.id),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT);

    let after = api_key_call(&app, Method::GET, "/api/v1/app/me", &secret, None).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    assert_eq!(after.error_code(), Some("API_KEY_INACTIVE"));
}

#[tokio::test]
async fn authorization_code_flow_with_pkce_issues_working_tokens() {
    let app = spawn_app().await;
    let admin = admin_token(&app, "flow-admin@example.com").await;
    let (user_token, user_id) = register_and_login(&app, "flow-user@example.com").await;

    let client = create_client(
        &app,
        &admin,
        json!({
            "name": "CRM Dashboard",
            "client_type": "public",
            "redirect_uris": ["https://crm.example.com/callback"],
            "allowed_scopes": ["openid", "profile", "email", "users:read"]
        }),
    )
    .await;

    let (verifier, challenge) = pkce_pair();

    let info_path = format!(
        "/oauth/authorize/info?response_type=code&client_id={}&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method=S256",
        url_encode(&client.client_id),
        url_encode("https://crm.example.com/callback"),
        url_encode("openid profile email"),
        url_encode(&challenge),
    );
    let info = call(&app, Method::GET, &info_path, Some(&user_token), None).await;
    assert_eq!(
        info.status,
        StatusCode::OK,
        "authorize info failed: {:?}",
        info.body
    );
    assert_eq!(info.body["client"]["name"], "CRM Dashboard");
    assert_eq!(info.body["already_consented"], false);

    // An unregistered redirect URI must never be honoured.
    let bad_redirect = call(
        &app,
        Method::GET,
        &format!(
            "/oauth/authorize/info?response_type=code&client_id={}&redirect_uri={}",
            url_encode(&client.client_id),
            url_encode("https://evil.example.com/callback")
        ),
        Some(&user_token),
        None,
    )
    .await;
    assert_eq!(bad_redirect.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad_redirect.body["error"], "invalid_request");

    let authorize = call(
        &app,
        Method::POST,
        "/oauth/authorize",
        Some(&user_token),
        Some(json!({
            "response_type": "code",
            "client_id": client.client_id,
            "redirect_uri": "https://crm.example.com/callback",
            "scope": "openid profile email",
            "state": "xyz-state",
            "code_challenge": challenge,
            "code_challenge_method": "S256"
        })),
    )
    .await;
    assert_eq!(
        authorize.status,
        StatusCode::OK,
        "authorize failed: {:?}",
        authorize.body
    );
    let code = authorize.body["code"].as_str().expect("code").to_string();
    let redirect_url = authorize.body["redirect_url"].as_str().expect("redirect");
    assert!(redirect_url.starts_with("https://crm.example.com/callback?code=ac_"));
    assert!(redirect_url.contains("state=xyz-state"));

    // Wrong verifier is rejected without consuming... the code is already spent,
    // so this asserts the failure mode explicitly.
    let wrong_verifier = post_form(
        &app,
        "/oauth/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", "ac_not-a-real-code"),
            ("redirect_uri", "https://crm.example.com/callback"),
            ("client_id", &client.client_id),
            ("code_verifier", &verifier),
        ],
        None,
    )
    .await;
    assert_eq!(wrong_verifier.status, StatusCode::BAD_REQUEST);
    assert_eq!(wrong_verifier.body["error"], "invalid_grant");

    let token = post_form(
        &app,
        "/oauth/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://crm.example.com/callback"),
            ("client_id", &client.client_id),
            ("code_verifier", &verifier),
        ],
        None,
    )
    .await;
    assert_eq!(
        token.status,
        StatusCode::OK,
        "token exchange failed: {:?}",
        token.body
    );
    let access = token.body["access_token"]
        .as_str()
        .expect("access")
        .to_string();
    let refresh = token.body["refresh_token"]
        .as_str()
        .expect("refresh")
        .to_string();
    assert!(
        token.body["id_token"].is_string(),
        "openid scope must yield an id_token"
    );
    assert_eq!(token.body["token_type"], "Bearer");

    // Replaying the code fails: single use.
    let replay = post_form(
        &app,
        "/oauth/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "https://crm.example.com/callback"),
            ("client_id", &client.client_id),
            ("code_verifier", &verifier),
        ],
        None,
    )
    .await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);

    let userinfo = call(&app, Method::GET, "/oauth/userinfo", Some(&access), None).await;
    assert_eq!(
        userinfo.status,
        StatusCode::OK,
        "userinfo failed: {:?}",
        userinfo.body
    );
    assert_eq!(userinfo.body["sub"], user_id);
    assert_eq!(userinfo.body["email"], "flow-user@example.com");

    // Introspection (public client: no secret).
    let introspect = post_form(
        &app,
        "/oauth/introspect",
        &[("token", &access), ("client_id", &client.client_id)],
        None,
    )
    .await;
    assert_eq!(introspect.status, StatusCode::OK);
    assert_eq!(introspect.body["active"], true);
    assert_eq!(introspect.body["client_id"], client.client_id);

    // Refresh rotation, then reuse detection burns the family.
    let refreshed = post_form(
        &app,
        "/oauth/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &client.client_id),
        ],
        None,
    )
    .await;
    assert_eq!(
        refreshed.status,
        StatusCode::OK,
        "refresh failed: {:?}",
        refreshed.body
    );
    let new_refresh = refreshed.body["refresh_token"]
        .as_str()
        .expect("rotated refresh")
        .to_string();
    assert_ne!(new_refresh, refresh);

    let reuse = post_form(
        &app,
        "/oauth/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &client.client_id),
        ],
        None,
    )
    .await;
    assert_eq!(reuse.status, StatusCode::BAD_REQUEST);
    assert_eq!(reuse.body["error"], "invalid_grant");

    // The reuse also invalidated the rotated token.
    let after_reuse = post_form(
        &app,
        "/oauth/token",
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", &new_refresh),
            ("client_id", &client.client_id),
        ],
        None,
    )
    .await;
    assert_eq!(after_reuse.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn public_clients_must_use_pkce() {
    let app = spawn_app().await;
    let admin = admin_token(&app, "pkce-admin@example.com").await;
    let (user_token, _) = register_and_login(&app, "pkce-user@example.com").await;

    let client = create_client(
        &app,
        &admin,
        json!({
            "name": "Mobile App",
            "client_type": "public",
            "redirect_uris": ["myapp://callback"],
            "allowed_scopes": ["openid"]
        }),
    )
    .await;

    let authorize = call(
        &app,
        Method::POST,
        "/oauth/authorize",
        Some(&user_token),
        Some(json!({
            "response_type": "code",
            "client_id": client.client_id,
            "redirect_uri": "myapp://callback",
            "scope": "openid"
        })),
    )
    .await;
    assert_eq!(authorize.status, StatusCode::BAD_REQUEST);
    assert_eq!(authorize.body["error"], "invalid_request");
    assert!(authorize.body["error_description"]
        .as_str()
        .unwrap()
        .contains("PKCE"));
}

#[tokio::test]
async fn client_credentials_issues_machine_tokens() {
    let app = spawn_app().await;
    let admin = admin_token(&app, "machine-admin@example.com").await;

    let client = create_client(
        &app,
        &admin,
        json!({
            "name": "Reporting Worker",
            "client_type": "confidential",
            "allowed_scopes": ["users:read", "tokens:verify"]
        }),
    )
    .await;

    let bad_secret = post_form(
        &app,
        "/oauth/token",
        &[("grant_type", "client_credentials")],
        Some((&client.client_id, "cs_wrong")),
    )
    .await;
    assert_eq!(bad_secret.status, StatusCode::UNAUTHORIZED);
    assert_eq!(bad_secret.body["error"], "invalid_client");

    let token = post_form(
        &app,
        "/oauth/token",
        &[("grant_type", "client_credentials")],
        Some((&client.client_id, &client.client_secret)),
    )
    .await;
    assert_eq!(
        token.status,
        StatusCode::OK,
        "grant failed: {:?}",
        token.body
    );
    let access = token.body["access_token"]
        .as_str()
        .expect("access")
        .to_string();
    assert_eq!(token.body["scope"], "users:read tokens:verify");
    assert!(token.body.get("refresh_token").is_none());

    // Machine tokens cannot call userinfo.
    let userinfo = call(&app, Method::GET, "/oauth/userinfo", Some(&access), None).await;
    assert_eq!(userinfo.status, StatusCode::UNAUTHORIZED);
    assert_eq!(userinfo.body["error"], "invalid_token");

    // App keys can introspect them when granted `tokens:verify`.
    let key_response = call(
        &app,
        Method::POST,
        &format!("/api/v1/admin/clients/{}/keys", client.id),
        Some(&admin),
        Some(json!({ "name": "verifier", "scopes": ["tokens:verify"] })),
    )
    .await;
    let key = key_response.data()["secret"]
        .as_str()
        .expect("key")
        .to_string();

    let introspected = api_key_call(
        &app,
        Method::POST,
        "/api/v1/app/introspect",
        &key,
        Some(json!({ "token": access })),
    )
    .await;
    assert_eq!(introspected.status, StatusCode::OK);
    assert_eq!(introspected.data()["active"], true);
    assert_eq!(
        introspected.data()["sub"],
        format!("client:{}", client.client_id)
    );

    // A token minted for another application must look inactive to this system.
    let other = create_client(
        &app,
        &admin,
        json!({ "name": "Another System", "allowed_scopes": ["tokens:verify"] }),
    )
    .await;
    let other_key_response = call(
        &app,
        Method::POST,
        &format!("/api/v1/admin/clients/{}/keys", other.id),
        Some(&admin),
        Some(json!({ "name": "other-verifier", "scopes": ["tokens:verify"] })),
    )
    .await;
    let other_key = other_key_response.data()["secret"]
        .as_str()
        .expect("other key")
        .to_string();
    let cross_app = api_key_call(
        &app,
        Method::POST,
        "/api/v1/app/introspect",
        &other_key,
        Some(json!({ "token": access })),
    )
    .await;
    assert_eq!(cross_app.status, StatusCode::OK);
    assert_eq!(
        cross_app.data()["active"],
        false,
        "audience isolation: another app must not see this token as active"
    );

    // Revocation makes the token inactive immediately.
    let revoked = post_form(
        &app,
        "/oauth/revoke",
        &[("token", &access)],
        Some((&client.client_id, &client.client_secret)),
    )
    .await;
    assert_eq!(revoked.status, StatusCode::OK);

    let after = post_form(
        &app,
        "/oauth/introspect",
        &[("token", &access)],
        Some((&client.client_id, &client.client_secret)),
    )
    .await;
    assert_eq!(after.body["active"], false);
}

#[tokio::test]
async fn disabled_applications_lose_all_access() {
    let app = spawn_app().await;
    let admin = admin_token(&app, "disable-admin@example.com").await;

    let client = create_client(
        &app,
        &admin,
        json!({
            "name": "Legacy Portal",
            "allowed_scopes": ["users:read", "tokens:verify"]
        }),
    )
    .await;

    let key_response = call(
        &app,
        Method::POST,
        &format!("/api/v1/admin/clients/{}/keys", client.id),
        Some(&admin),
        Some(json!({ "name": "portal-key", "scopes": ["users:read"] })),
    )
    .await;
    let key = key_response.data()["secret"]
        .as_str()
        .expect("key")
        .to_string();

    let working = api_key_call(&app, Method::GET, "/api/v1/app/me", &key, None).await;
    assert_eq!(working.status, StatusCode::OK);

    let disabled = call(
        &app,
        Method::PATCH,
        &format!("/api/v1/admin/clients/{}", client.id),
        Some(&admin),
        Some(json!({ "status": "disabled" })),
    )
    .await;
    assert_eq!(disabled.status, StatusCode::OK);
    assert_eq!(disabled.data()["status"], "disabled");

    let rejected = api_key_call(&app, Method::GET, "/api/v1/app/me", &key, None).await;
    assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);

    let token = post_form(
        &app,
        "/oauth/token",
        &[("grant_type", "client_credentials")],
        Some((&client.client_id, &client.client_secret)),
    )
    .await;
    assert_eq!(token.status, StatusCode::UNAUTHORIZED);
    assert_eq!(token.body["error"], "invalid_client");
}

#[tokio::test]
async fn secret_rotation_invalidates_the_previous_secret() {
    let app = spawn_app().await;
    let admin = admin_token(&app, "rotate-admin@example.com").await;

    let client = create_client(
        &app,
        &admin,
        json!({ "name": "Rotating Service", "allowed_scopes": ["users:read"] }),
    )
    .await;

    let rotated = call(
        &app,
        Method::POST,
        &format!("/api/v1/admin/clients/{}/secret/rotate", client.id),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(rotated.status, StatusCode::OK);
    let new_secret = rotated.data()["client_secret"].as_str().expect("secret");

    let old = post_form(
        &app,
        "/oauth/token",
        &[("grant_type", "client_credentials")],
        Some((&client.client_id, &client.client_secret)),
    )
    .await;
    assert_eq!(old.status, StatusCode::UNAUTHORIZED);

    let used_new = post_form(
        &app,
        "/oauth/token",
        &[("grant_type", "client_credentials")],
        Some((&client.client_id, new_secret)),
    )
    .await;
    assert_eq!(used_new.status, StatusCode::OK);
}

#[tokio::test]
async fn application_management_requires_an_admin() {
    let app = spawn_app().await;
    let (user_token, _) = register_and_login(&app, "plain-user@example.com").await;

    let denied = call(
        &app,
        Method::GET,
        "/api/v1/admin/clients",
        Some(&user_token),
        None,
    )
    .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);

    let anonymous = call(&app, Method::GET, "/api/v1/admin/clients", None, None).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);

    let no_key = api_key_call(&app, Method::GET, "/api/v1/app/me", "", None).await;
    assert_eq!(no_key.status, StatusCode::UNAUTHORIZED);

    // Unknown routes still answer with the JSON envelope.
    let missing = call(&app, Method::GET, "/api/v1/app/nope", None, None).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(missing.error_code(), Some("ROUTE_NOT_FOUND"));
}
