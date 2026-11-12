//! JWT issuing/validation (HS256 access tokens + short lived MFA challenge tokens).

use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    config::JwtConfig,
    db::users::{Role, UserRow},
    error::ApiError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    /// Full access token; only these are accepted by the auth extractor.
    Access,
    /// Short lived token that may only be exchanged for a real token pair after
    /// a successful second factor.
    Mfa,
}

impl TokenType {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenType::Access => "access",
            TokenType::Mfa => "mfa",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Claims {
    /// User id.
    pub sub: String,
    /// Session (refresh-token family member) id. Empty for MFA tokens.
    pub sid: String,
    pub role: Role,
    pub typ: String,
    pub iss: String,
    pub aud: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Clone)]
pub struct JwtService {
    encoding: EncodingKey,
    decoding: DecodingKey,
    config: JwtConfig,
}

impl JwtService {
    pub fn new(config: &JwtConfig) -> Self {
        JwtService {
            encoding: EncodingKey::from_secret(config.secret.as_bytes()),
            decoding: DecodingKey::from_secret(config.secret.as_bytes()),
            config: config.clone(),
        }
    }

    pub fn config(&self) -> &JwtConfig {
        &self.config
    }

    /// Issues an access token bound to a specific session.
    pub fn issue_access(
        &self,
        user_id: &str,
        role: Role,
        session_id: &str,
    ) -> Result<(String, i64), ApiError> {
        self.sign(
            user_id,
            role,
            session_id,
            TokenType::Access,
            self.config.access_ttl.as_secs() as i64,
        )
    }

    pub fn issue_mfa_challenge(&self, user: &UserRow) -> Result<(String, i64), ApiError> {
        self.sign(
            &user.id,
            user.role,
            "",
            TokenType::Mfa,
            self.config.mfa_ttl.as_secs() as i64,
        )
    }

    fn sign(
        &self,
        user_id: &str,
        role: Role,
        session_id: &str,
        typ: TokenType,
        ttl_seconds: i64,
    ) -> Result<(String, i64), ApiError> {
        let now = Utc::now().timestamp();
        let expires_at = now + ttl_seconds;
        let claims = Claims {
            sub: user_id.to_string(),
            sid: session_id.to_string(),
            role,
            typ: typ.as_str().to_string(),
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            jti: Uuid::new_v4().to_string(),
            iat: now,
            exp: expires_at,
        };
        let token = encode(&Header::new(Algorithm::HS256), &claims, &self.encoding)
            .map_err(ApiError::from)?;
        Ok((token, expires_at))
    }

    /// Validates signature, issuer, audience and expiry.
    pub fn decode(&self, token: &str) -> Result<Claims, ApiError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.leeway = self.config.leeway;
        validation.set_audience(&[self.config.audience.as_str()]);
        validation.set_issuer(&[self.config.issuer.as_str()]);

        decode::<Claims>(token, &self.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|err| match err.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => ApiError::token_expired(),
                _ => ApiError::unauthenticated("The token is invalid"),
            })
    }

    /// Decodes and asserts the token is an access token.
    pub fn decode_access(&self, token: &str) -> Result<Claims, ApiError> {
        let claims = self.decode(token)?;
        if claims.typ != TokenType::Access.as_str() {
            return Err(ApiError::unauthenticated(
                "This token cannot be used as an access token",
            ));
        }
        Ok(claims)
    }

    /// Decodes and asserts the token is an MFA challenge token.
    pub fn decode_mfa(&self, token: &str) -> Result<Claims, ApiError> {
        let claims = self.decode(token)?;
        if claims.typ != TokenType::Mfa.as_str() {
            return Err(ApiError::unauthenticated(
                "Invalid two-factor challenge token",
            ));
        }
        Ok(claims)
    }
}
