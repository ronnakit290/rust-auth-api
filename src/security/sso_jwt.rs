//! RS256 signing keys for SSO tokens, plus the JWKS document other systems use
//! to verify our tokens without sharing a secret.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{
    decode, encode,
    jwk::{
        AlgorithmParameters, CommonParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse,
        RSAKeyParameters, RSAKeyType,
    },
    Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use rand::rngs::OsRng;
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    traits::PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{config::SsoConfig, error::ApiError, security::tokens::sha256_hex};

/// Claims of an SSO access token. `sub` is a user id for user tokens and
/// `client:<client_id>` for machine tokens.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SsoClaims {
    pub iss: String,
    pub sub: String,
    /// Audience: the registered client id.
    pub aud: String,
    /// Authorized party (same as `aud` for now).
    pub azp: String,
    /// Space separated scopes.
    pub scope: String,
    pub typ: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

impl SsoClaims {
    pub fn scopes(&self) -> Vec<String> {
        self.scope
            .split_whitespace()
            .map(|scope| scope.to_string())
            .collect()
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scope.split_whitespace().any(|item| item == scope)
    }

    pub fn is_machine_token(&self) -> bool {
        self.sub.starts_with("client:")
    }
}

pub struct SsoKeys {
    encoding: EncodingKey,
    decoding: DecodingKey,
    kid: String,
    jwks: JwkSet,
    issuer: String,
}

impl SsoKeys {
    pub fn from_config(config: &SsoConfig) -> Result<Self> {
        let (private_pem, public_pem, generated) = match config.private_key_pem.as_deref() {
            Some(raw) => {
                let pem = raw.replace("\\n", "\n");
                let key = RsaPrivateKey::from_pkcs8_pem(&pem)
                    .context("SSO_RSA_PRIVATE_KEY is not a valid PKCS#8 PEM")?;
                let public = RsaPublicKey::from(&key)
                    .to_public_key_pem(LineEnding::LF)
                    .context("cannot encode the SSO public key")?;
                (pem, public, false)
            }
            None => {
                let key = RsaPrivateKey::new(&mut OsRng, 2048)
                    .context("RSA key generation failed")?;
                let private = key
                    .to_pkcs8_pem(LineEnding::LF)
                    .context("cannot encode the generated SSO key")?
                    .to_string();
                let public = RsaPublicKey::from(&key)
                    .to_public_key_pem(LineEnding::LF)
                    .context("cannot encode the generated SSO public key")?;
                (private, public, true)
            }
        };

        if generated {
            tracing::warn!(
                "SSO_RSA_PRIVATE_KEY not set: generated an ephemeral RSA key. \
                 Every restart invalidates previously issued SSO tokens."
            );
        }

        let encoding = EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .map_err(|error| anyhow!("invalid SSO private key: {error}"))?;
        let decoding = DecodingKey::from_rsa_pem(public_pem.as_bytes())
            .map_err(|error| anyhow!("invalid SSO public key: {error}"))?;

        let public_key = RsaPublicKey::from_public_key_pem(&public_pem)
            .map_err(|error| anyhow!("cannot parse SSO public key: {error}"))?;
        let kid = sha256_hex(&public_pem).chars().take(16).collect::<String>();

        let jwk = Jwk {
            common: CommonParameters {
                public_key_use: Some(PublicKeyUse::Signature),
                key_operations: None,
                key_algorithm: Some(KeyAlgorithm::RS256),
                key_id: Some(kid.clone()),
                x509_url: None,
                x509_chain: None,
                x509_sha1_fingerprint: None,
                x509_sha256_fingerprint: None,
            },
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: RSAKeyType::RSA,
                n: URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
                e: URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
            }),
        };

        Ok(SsoKeys {
            encoding,
            decoding,
            kid,
            jwks: JwkSet { keys: vec![jwk] },
            issuer: config.issuer.clone(),
        })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn jwks(&self) -> &JwkSet {
        &self.jwks
    }

    pub fn public_jwks_json(&self) -> serde_json::Value {
        serde_json::to_value(&self.jwks).unwrap_or_else(|_| serde_json::json!({ "keys": [] }))
    }

    pub fn sign(&self, claims: &SsoClaims) -> Result<String, ApiError> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        header.typ = Some("JWT".to_string());
        encode(&header, claims, &self.encoding).map_err(ApiError::from)
    }

    /// Verifies signature, issuer and expiry. Audience is checked by the
    /// caller because it is the client id, which varies per request.
    pub fn verify(&self, token: &str) -> Result<SsoClaims, ApiError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.validate_aud = false;
        validation.leeway = 30;

        let claims = decode::<SsoClaims>(token, &self.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|error| match error.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => ApiError::token_expired(),
                _ => ApiError::unauthenticated("The SSO token is invalid"),
            })?;

        if claims.typ != "sso" {
            return Err(ApiError::unauthenticated(
                "This token was not issued by the SSO token endpoint",
            ));
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> SsoKeys {
        SsoKeys::from_config(&SsoConfig {
            enabled: true,
            issuer: "http://localhost:8080".to_string(),
            access_ttl: std::time::Duration::from_secs(600),
            code_ttl: std::time::Duration::from_secs(300),
            refresh_ttl: std::time::Duration::from_secs(600),
            private_key_pem: None,
            app_key_prefix: "ssok".to_string(),
            default_scopes: vec!["openid".to_string()],
        })
        .expect("keys")
    }

    #[test]
    fn tokens_roundtrip_and_expose_jwks() {
        let keys = test_keys();
        let claims = SsoClaims {
            iss: keys.issuer().to_string(),
            sub: "user-1".to_string(),
            aud: "client-1".to_string(),
            azp: "client-1".to_string(),
            scope: "openid profile".to_string(),
            typ: "sso".to_string(),
            jti: uuid::Uuid::new_v4().to_string(),
            iat: chrono::Utc::now().timestamp(),
            exp: chrono::Utc::now().timestamp() + 300,
            email: Some("user@example.com".to_string()),
            name: None,
            role: Some("user".to_string()),
        };
        let token = keys.sign(&claims).expect("sign");
        let decoded = keys.verify(&token).expect("verify");
        assert_eq!(decoded.sub, "user-1");
        assert!(decoded.has_scope("profile"));

        let jwks = keys.public_jwks_json();
        assert_eq!(jwks["keys"][0]["alg"], "RS256");
        assert_eq!(jwks["keys"][0]["kid"], keys.kid());
        assert!(jwks["keys"][0]["n"].as_str().unwrap().len() > 100);
    }
}
