#![cfg_attr(all(feature = "hydrate", not(feature = "ssr")), allow(dead_code))]

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OAuthProvider {
    Google,
    Apple,
    Microsoft,
    Facebook,
}

impl OAuthProvider {
    pub fn parse(input: &str) -> Result<Self, String> {
        match input.trim().to_lowercase().as_str() {
            "google" => Ok(Self::Google),
            "apple" => Ok(Self::Apple),
            "microsoft" | "ms" | "azure" => Ok(Self::Microsoft),
            "facebook" | "meta" => Ok(Self::Facebook),
            other => Err(format!("Unsupported OAuth provider: {other}")),
        }
    }

    pub fn slug(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Apple => "apple",
            Self::Microsoft => "microsoft",
            Self::Facebook => "facebook",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Google => "Google",
            Self::Apple => "Apple",
            Self::Microsoft => "Microsoft",
            Self::Facebook => "Facebook",
        }
    }

    pub fn env_prefix(self) -> &'static str {
        match self {
            Self::Google => "GOOGLE",
            Self::Apple => "APPLE",
            Self::Microsoft => "MICROSOFT",
            Self::Facebook => "FACEBOOK",
        }
    }

    fn override_prefix(self) -> &'static str {
        match self {
            Self::Google => "OAUTH_GOOGLE",
            Self::Apple => "OAUTH_APPLE",
            Self::Microsoft => "OAUTH_MICROSOFT",
            Self::Facebook => "OAUTH_FACEBOOK",
        }
    }

    fn default_auth_url(self) -> &'static str {
        match self {
            Self::Google => "https://accounts.google.com/o/oauth2/v2/auth",
            Self::Apple => "https://appleid.apple.com/auth/authorize",
            Self::Microsoft => "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            Self::Facebook => "https://www.facebook.com/v18.0/dialog/oauth",
        }
    }

    fn default_token_url(self) -> &'static str {
        match self {
            Self::Google => "https://oauth2.googleapis.com/token",
            Self::Apple => "https://appleid.apple.com/auth/token",
            Self::Microsoft => "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            Self::Facebook => "https://graph.facebook.com/v18.0/oauth/access_token",
        }
    }

    fn default_jwks_url(self) -> Option<&'static str> {
        match self {
            Self::Google => Some("https://www.googleapis.com/oauth2/v3/certs"),
            Self::Apple => Some("https://appleid.apple.com/auth/keys"),
            Self::Microsoft => Some("https://login.microsoftonline.com/common/discovery/v2.0/keys"),
            Self::Facebook => None,
        }
    }

    fn default_profile_url(self) -> Option<&'static str> {
        match self {
            Self::Microsoft => Some("https://graph.microsoft.com/v1.0/me"),
            Self::Facebook => Some("https://graph.facebook.com/me?fields=id,email,name"),
            _ => None,
        }
    }

    fn default_issuer(self) -> Option<&'static str> {
        match self {
            Self::Google => Some("https://accounts.google.com"),
            Self::Apple => Some("https://appleid.apple.com"),
            Self::Microsoft => Some("https://login.microsoftonline.com/{tenantid}/v2.0"),
            Self::Facebook => None,
        }
    }

    fn default_scopes(self) -> &'static str {
        match self {
            Self::Google => "openid email profile",
            Self::Apple => "name email",
            Self::Microsoft => "openid email profile User.Read",
            Self::Facebook => "email",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OAuthProviderConfig {
    pub provider: OAuthProvider,
    pub auth_url: String,
    pub token_url: String,
    pub jwks_url: Option<String>,
    pub profile_url: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: String,
    pub issuer: Option<String>,
    pub audience: String,
}

impl OAuthProviderConfig {
    pub fn from_env(provider: OAuthProvider) -> Result<Self, String> {
        let client_id_key = format!("{}_CLIENT_ID", provider.env_prefix());
        let client_id = required_env(&client_id_key)?;
        let client_secret = if provider == OAuthProvider::Apple {
            None
        } else {
            Some(required_env(&format!(
                "{}_CLIENT_SECRET",
                provider.env_prefix()
            ))?)
        };
        Ok(Self {
            provider,
            auth_url: env_or_default(
                &format!("{}_AUTH_URL", provider.override_prefix()),
                provider.default_auth_url(),
            ),
            token_url: env_or_default(
                &format!("{}_TOKEN_URL", provider.override_prefix()),
                provider.default_token_url(),
            ),
            jwks_url: optional_env(&format!("{}_JWKS_URL", provider.override_prefix()))
                .or_else(|| provider.default_jwks_url().map(str::to_string)),
            profile_url: optional_env(&format!("{}_PROFILE_URL", provider.override_prefix()))
                .or_else(|| provider.default_profile_url().map(str::to_string)),
            client_id: client_id.clone(),
            client_secret,
            scopes: env_or_default(
                &format!("{}_SCOPES", provider.override_prefix()),
                provider.default_scopes(),
            ),
            issuer: optional_env(&format!("{}_ISSUER", provider.override_prefix()))
                .or_else(|| provider.default_issuer().map(str::to_string)),
            audience: client_id,
        })
    }

    pub fn redirect_uri(&self, redirect_base: &str) -> String {
        format!(
            "{}/api/auth/callback/{}",
            redirect_base.trim_end_matches('/'),
            self.provider.slug()
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OAuthStateRecord {
    pub provider: OAuthProvider,
    pub state: String,
    pub nonce: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub linking_user_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
}

impl OAuthStateRecord {
    pub fn new(
        provider: OAuthProvider,
        redirect_uri: String,
        linking_user_id: Option<Uuid>,
    ) -> Self {
        Self {
            provider,
            state: random_url_safe(32),
            nonce: random_url_safe(32),
            code_verifier: random_url_safe(64),
            redirect_uri,
            linking_user_id,
            expires_at: Utc::now() + ChronoDuration::minutes(10),
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at <= Utc::now()
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    pub fn code_challenge(&self) -> String {
        pkce_challenge(&self.code_verifier)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OAuthStartResponse {
    pub auth_url: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VerifiedOAuthProfile {
    pub provider: OAuthProvider,
    pub provider_user_id: String,
    pub email: String,
    pub email_verified: bool,
    pub display_name: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct OidcTokenClaims {
    pub email: Option<String>,
    pub email_verified: Option<Value>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub tid: Option<String>,
}

pub fn build_authorization_url(config: &OAuthProviderConfig, state: &OAuthStateRecord) -> String {
    let code_challenge = state.code_challenge();
    let mut params = vec![
        ("client_id", config.client_id.as_str()),
        ("redirect_uri", state.redirect_uri.as_str()),
        ("response_type", "code"),
        ("scope", config.scopes.as_str()),
        ("state", state.state.as_str()),
        ("nonce", state.nonce.as_str()),
        ("code_challenge", code_challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];

    if config.provider == OAuthProvider::Apple {
        params.push(("response_mode", "query"));
    }

    format!("{}?{}", config.auth_url, encode_params(&params))
}

pub fn consume_oauth_state(
    states: &mut HashMap<String, OAuthStateRecord>,
    provider: OAuthProvider,
    state: &str,
) -> Result<OAuthStateRecord, String> {
    consume_oauth_state_at(states, provider, state, Utc::now())
}

pub fn consume_oauth_state_at(
    states: &mut HashMap<String, OAuthStateRecord>,
    provider: OAuthProvider,
    state: &str,
    now: DateTime<Utc>,
) -> Result<OAuthStateRecord, String> {
    states.retain(|key, record| !record.is_expired_at(now) || key == state);

    let record = states
        .remove(state)
        .ok_or_else(|| "OAuth state is invalid or expired".to_string())?;
    if record.provider != provider {
        return Err("OAuth state provider mismatch".to_string());
    }
    if record.is_expired_at(now) {
        return Err("OAuth state has expired".to_string());
    }
    Ok(record)
}

pub fn build_code_exchange_body(
    config: &OAuthProviderConfig,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
    client_secret: Option<&str>,
) -> String {
    let mut params = vec![
        ("code", code),
        ("client_id", config.client_id.as_str()),
        ("redirect_uri", redirect_uri),
        ("grant_type", "authorization_code"),
        ("code_verifier", code_verifier),
    ];
    if let Some(secret) = client_secret.or(config.client_secret.as_deref()) {
        params.push(("client_secret", secret));
    }
    encode_params(&params)
}

pub fn random_url_safe(byte_len: usize) -> String {
    let mut bytes = vec![0u8; byte_len];
    OsRng.fill_bytes(&mut bytes);
    base64_url_encode(&bytes)
}

pub fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64_url_encode(&digest)
}

pub fn base64_url_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn base64_url_decode(value: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| format!("Invalid base64url value: {e}"))
}

pub fn select_rs256_key_from_jwks(
    jwks: &Value,
    required_kid: Option<&str>,
) -> Result<jwt_simple::prelude::RS256PublicKey, String> {
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| "JWKS is missing keys array".to_string())?;

    for jwk in keys {
        let kid_matches = match required_kid {
            Some(required) => jwk.get("kid").and_then(Value::as_str) == Some(required),
            None => true,
        };
        if !kid_matches {
            continue;
        }
        if jwk.get("kty").and_then(Value::as_str) != Some("RSA") {
            continue;
        }
        if let Some(alg) = jwk.get("alg").and_then(Value::as_str) {
            if alg != "RS256" {
                continue;
            }
        }
        let n = jwk
            .get("n")
            .and_then(Value::as_str)
            .ok_or_else(|| "JWKS RSA key missing n".to_string())
            .and_then(base64_url_decode)?;
        let e = jwk
            .get("e")
            .and_then(Value::as_str)
            .ok_or_else(|| "JWKS RSA key missing e".to_string())
            .and_then(base64_url_decode)?;
        let key = jwt_simple::prelude::RS256PublicKey::from_components(&n, &e)
            .map_err(|e| format!("Invalid RS256 public key components: {e}"))?;
        return Ok(match jwk.get("kid").and_then(Value::as_str) {
            Some(kid) => key.with_key_id(kid),
            None => key,
        });
    }

    Err(match required_kid {
        Some(kid) => format!("JWKS did not contain RS256 key with kid {kid}"),
        None => "JWKS did not contain an RS256 key".to_string(),
    })
}

pub fn verify_oidc_id_token(
    config: &OAuthProviderConfig,
    state: &OAuthStateRecord,
    id_token: &str,
    jwks: &Value,
) -> Result<VerifiedOAuthProfile, String> {
    use jwt_simple::prelude::*;
    use std::collections::HashSet;

    let metadata =
        Token::decode_metadata(id_token).map_err(|e| format!("Invalid JWT header: {e}"))?;
    if metadata.algorithm() != "RS256" {
        return Err(format!(
            "Unsupported OAuth id_token algorithm: {}",
            metadata.algorithm()
        ));
    }
    let key = select_rs256_key_from_jwks(jwks, metadata.key_id())?;

    let mut audiences = HashSet::new();
    audiences.insert(config.audience.clone());

    let mut options = VerificationOptions {
        allowed_audiences: Some(audiences),
        required_nonce: Some(state.nonce.clone()),
        required_key_id: metadata.key_id().map(str::to_string),
        max_validity: Some(jwt_simple::prelude::Duration::from_hours(24)),
        ..Default::default()
    };

    if config.provider != OAuthProvider::Microsoft {
        if let Some(issuer) = &config.issuer {
            let mut issuers = HashSet::new();
            issuers.insert(issuer.clone());
            options.allowed_issuers = Some(issuers);
        }
    }

    let claims = key
        .verify_token::<OidcTokenClaims>(id_token, Some(options))
        .map_err(|e| format!("id_token verification failed: {e}"))?;

    validate_issuer(config, &claims)?;

    let provider_user_id = claims
        .subject
        .clone()
        .ok_or_else(|| "id_token missing sub".to_string())?;
    let email = claims
        .custom
        .email
        .clone()
        .or_else(|| claims.custom.preferred_username.clone())
        .ok_or_else(|| "id_token missing email".to_string())?
        .trim()
        .to_lowercase();
    if email.is_empty() {
        return Err("id_token email is empty".to_string());
    }

    let email_verified = email_verified(&claims.custom.email_verified)
        .unwrap_or(config.provider == OAuthProvider::Microsoft);
    if !email_verified && config.provider != OAuthProvider::Microsoft {
        return Err("OAuth provider did not verify this email address".to_string());
    }

    Ok(VerifiedOAuthProfile {
        provider: config.provider,
        provider_user_id,
        email,
        email_verified,
        display_name: claims.custom.name.clone(),
    })
}

pub fn facebook_profile_from_response(profile: &Value) -> Result<VerifiedOAuthProfile, String> {
    let provider_user_id = profile
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| "Facebook profile missing id".to_string())?
        .to_string();
    let email = profile
        .get("email")
        .and_then(Value::as_str)
        .ok_or_else(|| "Facebook profile missing email".to_string())?
        .trim()
        .to_lowercase();
    if email.is_empty() {
        return Err("Facebook profile email is empty".to_string());
    }
    Ok(VerifiedOAuthProfile {
        provider: OAuthProvider::Facebook,
        provider_user_id,
        email,
        email_verified: true,
        display_name: profile
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

#[cfg(feature = "ssr")]
pub fn generate_apple_client_secret(config: &OAuthProviderConfig) -> Result<String, String> {
    use jwt_simple::prelude::*;
    use std::time::Duration;

    let team_id =
        std::env::var("APPLE_TEAM_ID").map_err(|_| "APPLE_TEAM_ID env var not set".to_string())?;
    let key_id =
        std::env::var("APPLE_KEY_ID").map_err(|_| "APPLE_KEY_ID env var not set".to_string())?;
    let private_key_pem = std::env::var("APPLE_PRIVATE_KEY_PEM")
        .map_err(|_| "APPLE_PRIVATE_KEY_PEM env var not set".to_string())?
        .replace("\\n", "\n");

    let claims = Claims::create(Duration::from_hours(24).into())
        .with_issuer(team_id)
        .with_audience("https://appleid.apple.com")
        .with_subject(config.client_id.clone());

    ES256KeyPair::from_pem(&private_key_pem)
        .map_err(|e| format!("Failed to parse Apple private key PEM: {e:?}"))?
        .with_key_id(&key_id)
        .sign(claims)
        .map_err(|e| format!("Failed to sign Apple client secret: {e:?}"))
}

#[cfg(feature = "ssr")]
pub async fn post_form_json(url: &str, body: String) -> Result<Value, String> {
    use bytes::Bytes;
    use http::{Method, Request};
    use http_body_util::Full;

    let req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| format!("Failed to build OAuth POST request: {e}"))?;

    send_json_request(req).await
}

#[cfg(feature = "ssr")]
pub async fn get_json(url: &str, bearer_token: Option<&str>) -> Result<Value, String> {
    use bytes::Bytes;
    use http::{Method, Request};
    use http_body_util::Full;

    let mut req_builder = Request::builder().method(Method::GET).uri(url);
    if let Some(token) = bearer_token {
        req_builder = req_builder.header("Authorization", format!("Bearer {token}"));
    }
    let req = req_builder
        .body(Full::new(Bytes::new()))
        .map_err(|e| format!("Failed to build OAuth GET request: {e}"))?;

    send_json_request(req).await
}

#[cfg(feature = "ssr")]
async fn send_json_request(
    req: http::Request<http_body_util::Full<bytes::Bytes>>,
) -> Result<Value, String> {
    let wasi_req = wasip3::http_compat::http_into_wasi_request(req)
        .map_err(|e| format!("WASI translation failed: {e:?}"))?;
    let wasi_res = wasip3::http::client::send(wasi_req)
        .await
        .map_err(|e| format!("Outbound OAuth request failed: {e:?}"))?;
    let res = wasip3::http_compat::http_from_wasi_response(wasi_res)
        .map_err(|e| format!("WASI response conversion failed: {e:?}"))?;

    let (parts, body) = res.into_parts();
    let bytes = http_body_util::BodyExt::collect(body)
        .await
        .map_err(|e| format!("Failed to read OAuth response body: {e}"))?
        .to_bytes();

    if !parts.status.is_success() {
        return Err(format!(
            "OAuth endpoint returned status {}: {}",
            parts.status,
            String::from_utf8_lossy(&bytes)
        ));
    }

    serde_json::from_slice(&bytes).map_err(|e| format!("Failed to parse OAuth JSON response: {e}"))
}

fn required_env(name: &str) -> Result<String, String> {
    std::env::var(name)
        .map(|value| value.trim().to_string())
        .map_err(|_| format!("{name} is not configured"))
        .and_then(|value| {
            if value.is_empty() {
                Err(format!("{name} is empty"))
            } else {
                Ok(value)
            }
        })
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_or_default(name: &str, default: &str) -> String {
    optional_env(name).unwrap_or_else(|| default.to_string())
}

fn encode_params(params: &[(&str, &str)]) -> String {
    params
        .iter()
        .map(|(key, value)| format!("{}={}", key, urlencoding::encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn validate_issuer(
    config: &OAuthProviderConfig,
    claims: &jwt_simple::prelude::JWTClaims<OidcTokenClaims>,
) -> Result<(), String> {
    let expected = match &config.issuer {
        Some(value) => value,
        None => return Ok(()),
    };
    let actual = claims
        .issuer
        .as_ref()
        .ok_or_else(|| "id_token missing iss".to_string())?;

    if expected.contains("{tenantid}") {
        let tid = claims
            .custom
            .tid
            .as_ref()
            .ok_or_else(|| "Microsoft id_token missing tid".to_string())?;
        let expanded = expected.replace("{tenantid}", tid);
        if actual == &expanded {
            Ok(())
        } else {
            Err(format!("Unexpected id_token issuer: {actual}"))
        }
    } else if actual == expected {
        Ok(())
    } else {
        Err(format!("Unexpected id_token issuer: {actual}"))
    }
}

fn email_verified(value: &Option<Value>) -> Option<bool> {
    match value {
        Some(Value::Bool(value)) => Some(*value),
        Some(Value::String(value)) => match value.as_str() {
            "true" | "1" => Some(true),
            "false" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jwt_simple::prelude::*;
    use serde_json::json;

    fn fake_config() -> OAuthProviderConfig {
        OAuthProviderConfig {
            provider: OAuthProvider::Google,
            auth_url: "http://127.0.0.1:9001/authorize".to_string(),
            token_url: "http://127.0.0.1:9001/token".to_string(),
            jwks_url: Some("http://127.0.0.1:9001/jwks".to_string()),
            profile_url: None,
            client_id: "test-client".to_string(),
            client_secret: Some("test-secret".to_string()),
            scopes: "openid email profile".to_string(),
            issuer: Some("http://127.0.0.1:9001".to_string()),
            audience: "test-client".to_string(),
        }
    }

    fn fake_config_for(provider: OAuthProvider, issuer: &str) -> OAuthProviderConfig {
        OAuthProviderConfig {
            provider,
            auth_url: format!("http://127.0.0.1:9001/{}/authorize", provider.slug()),
            token_url: format!("http://127.0.0.1:9001/{}/token", provider.slug()),
            jwks_url: Some(format!("http://127.0.0.1:9001/{}/jwks", provider.slug())),
            profile_url: match provider {
                OAuthProvider::Facebook => {
                    Some("http://127.0.0.1:9001/facebook/me?fields=id,email,name".to_string())
                }
                _ => None,
            },
            client_id: format!("{}-client", provider.slug()),
            client_secret: match provider {
                OAuthProvider::Apple => None,
                _ => Some(format!("{}-secret", provider.slug())),
            },
            scopes: provider.default_scopes().to_string(),
            issuer: match provider {
                OAuthProvider::Facebook => None,
                _ => Some(issuer.to_string()),
            },
            audience: format!("{}-client", provider.slug()),
        }
    }

    fn fake_state() -> OAuthStateRecord {
        OAuthStateRecord {
            provider: OAuthProvider::Google,
            state: "state-1".to_string(),
            nonce: "nonce-1".to_string(),
            code_verifier: "verifier-1".to_string(),
            redirect_uri: "http://localhost:3000/api/auth/callback/google".to_string(),
            linking_user_id: None,
            expires_at: Utc::now() + ChronoDuration::minutes(10),
        }
    }

    fn verified_custom_claims() -> OidcTokenClaims {
        OidcTokenClaims {
            email: Some("USER@example.com".to_string()),
            email_verified: Some(Value::Bool(true)),
            name: Some("Test User".to_string()),
            preferred_username: None,
            tid: None,
        }
    }

    fn fake_jwks(key_pair: &RS256KeyPair) -> Value {
        let components = key_pair.public_key().to_components();
        json!({
            "keys": [{
                "kty": "RSA",
                "kid": "kid-1",
                "alg": "RS256",
                "n": base64_url_encode(&components.n),
                "e": base64_url_encode(&components.e)
            }]
        })
    }

    fn sign_fake_token(
        key_pair: &RS256KeyPair,
        issuer: &str,
        audience: &str,
        subject: Option<&str>,
        nonce: Option<&str>,
    ) -> String {
        let mut claims = Claims::with_custom_claims(
            verified_custom_claims(),
            jwt_simple::prelude::Duration::from_mins(10),
        )
        .with_issuer(issuer)
        .with_audience(audience);
        if let Some(subject) = subject {
            claims = claims.with_subject(subject);
        }
        if let Some(nonce) = nonce {
            claims = claims.with_nonce(nonce);
        }
        key_pair.sign(claims).unwrap()
    }

    struct FakeOidcProvider {
        key_pair: RS256KeyPair,
        issuer: String,
    }

    impl FakeOidcProvider {
        fn new(provider: OAuthProvider) -> Self {
            Self {
                key_pair: RS256KeyPair::generate(2048).unwrap().with_key_id("kid-1"),
                issuer: format!("http://127.0.0.1:9001/{}", provider.slug()),
            }
        }

        fn authorize(&self, config: &OAuthProviderConfig, state: &OAuthStateRecord) -> String {
            build_authorization_url(config, state)
        }

        fn token(&self, config: &OAuthProviderConfig, state: &OAuthStateRecord) -> Value {
            json!({
                "token_type": "Bearer",
                "expires_in": 600,
                "id_token": sign_fake_token(
                    &self.key_pair,
                    &self.issuer,
                    &config.audience,
                    Some("provider-user-1"),
                    Some(&state.nonce),
                )
            })
        }

        fn jwks(&self) -> Value {
            fake_jwks(&self.key_pair)
        }
    }

    struct FakeFacebookProvider;

    impl FakeFacebookProvider {
        fn authorize(config: &OAuthProviderConfig, state: &OAuthStateRecord) -> String {
            build_authorization_url(config, state)
        }

        fn token() -> Value {
            json!({
                "token_type": "Bearer",
                "expires_in": 600,
                "access_token": "fake-facebook-access-token"
            })
        }

        fn me() -> Value {
            json!({
                "id": "facebook-user-1",
                "email": "FACEBOOK@example.com",
                "name": "Facebook User"
            })
        }
    }

    #[test]
    fn parses_provider_aliases() {
        assert_eq!(
            OAuthProvider::parse("google").unwrap(),
            OAuthProvider::Google
        );
        assert_eq!(
            OAuthProvider::parse("azure").unwrap(),
            OAuthProvider::Microsoft
        );
        assert!(OAuthProvider::parse("github").is_err());
    }

    #[test]
    fn builds_authorization_url_with_nonce_and_pkce() {
        let config = fake_config();
        let state = fake_state();
        let url = build_authorization_url(&config, &state);
        assert!(url.starts_with("http://127.0.0.1:9001/authorize?"));
        assert!(url.contains("state=state-1"));
        assert!(url.contains("nonce=nonce-1"));
        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains(
            "redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fcallback%2Fgoogle"
        ));
    }

    #[test]
    fn consumes_oauth_state_once_when_valid() {
        let now = Utc::now();
        let state = fake_state();
        let state_key = state.state.clone();
        let mut states = HashMap::from([(state_key.clone(), state)]);

        let consumed =
            consume_oauth_state_at(&mut states, OAuthProvider::Google, &state_key, now).unwrap();

        assert_eq!(consumed.state, state_key);
        assert!(states.is_empty());
    }

    #[test]
    fn rejects_replayed_oauth_state() {
        let now = Utc::now();
        let state = fake_state();
        let state_key = state.state.clone();
        let mut states = HashMap::from([(state_key.clone(), state)]);
        consume_oauth_state_at(&mut states, OAuthProvider::Google, &state_key, now).unwrap();

        let err = consume_oauth_state_at(&mut states, OAuthProvider::Google, &state_key, now)
            .unwrap_err();

        assert!(err.contains("invalid or expired"));
    }

    #[test]
    fn rejects_wrong_provider_oauth_state() {
        let now = Utc::now();
        let state = fake_state();
        let state_key = state.state.clone();
        let mut states = HashMap::from([(state_key.clone(), state)]);

        let err =
            consume_oauth_state_at(&mut states, OAuthProvider::Apple, &state_key, now).unwrap_err();

        assert_eq!(err, "OAuth state provider mismatch");
        assert!(states.is_empty());
    }

    #[test]
    fn rejects_expired_oauth_state() {
        let now = Utc::now();
        let mut state = fake_state();
        state.expires_at = now - ChronoDuration::seconds(1);
        let state_key = state.state.clone();
        let mut states = HashMap::from([(state_key.clone(), state)]);

        let err = consume_oauth_state_at(&mut states, OAuthProvider::Google, &state_key, now)
            .unwrap_err();

        assert_eq!(err, "OAuth state has expired");
        assert!(states.is_empty());
    }

    #[test]
    fn rejects_missing_oauth_state() {
        let mut states = HashMap::new();

        let err = consume_oauth_state_at(
            &mut states,
            OAuthProvider::Google,
            "missing-state",
            Utc::now(),
        )
        .unwrap_err();

        assert!(err.contains("invalid or expired"));
    }

    #[test]
    fn selects_jwks_key_by_kid() {
        let key_pair = RS256KeyPair::generate(2048).unwrap().with_key_id("kid-1");
        let jwks = fake_jwks(&key_pair);
        assert!(select_rs256_key_from_jwks(&jwks, Some("kid-1")).is_ok());
        assert!(select_rs256_key_from_jwks(&jwks, Some("kid-2")).is_err());
    }

    #[test]
    fn verifies_fake_oidc_token() {
        let config = fake_config();
        let state = fake_state();
        let key_pair = RS256KeyPair::generate(2048).unwrap().with_key_id("kid-1");
        let jwks = fake_jwks(&key_pair);
        let token = sign_fake_token(
            &key_pair,
            "http://127.0.0.1:9001",
            "test-client",
            Some("provider-user-1"),
            Some("nonce-1"),
        );

        let profile = verify_oidc_id_token(&config, &state, &token, &jwks).unwrap();
        assert_eq!(profile.provider_user_id, "provider-user-1");
        assert_eq!(profile.email, "user@example.com");
        assert!(profile.email_verified);
    }

    #[test]
    fn fake_oidc_provider_flow_verifies_google_apple_and_microsoft_profiles() {
        for provider in [
            OAuthProvider::Google,
            OAuthProvider::Apple,
            OAuthProvider::Microsoft,
        ] {
            let fake_provider = FakeOidcProvider::new(provider);
            let config = fake_config_for(provider, &fake_provider.issuer);
            let mut state = fake_state();
            state.provider = provider;
            state.redirect_uri = config.redirect_uri("http://localhost:3000");

            let auth_url = fake_provider.authorize(&config, &state);
            let token_response = fake_provider.token(&config, &state);
            let id_token = token_response
                .get("id_token")
                .and_then(Value::as_str)
                .unwrap();
            let profile =
                verify_oidc_id_token(&config, &state, id_token, &fake_provider.jwks()).unwrap();

            assert!(auth_url.contains(&format!("/{}/authorize?", provider.slug())));
            assert_eq!(profile.provider, provider);
            assert_eq!(profile.email, "user@example.com");
        }
    }

    #[test]
    fn rejects_fake_oidc_token_with_wrong_nonce() {
        let config = fake_config();
        let state = fake_state();
        let key_pair = RS256KeyPair::generate(2048).unwrap().with_key_id("kid-1");
        let jwks = fake_jwks(&key_pair);
        let token = sign_fake_token(
            &key_pair,
            "http://127.0.0.1:9001",
            "test-client",
            Some("provider-user-1"),
            Some("wrong-nonce"),
        );

        assert!(verify_oidc_id_token(&config, &state, &token, &jwks).is_err());
    }

    #[test]
    fn rejects_fake_oidc_token_with_bad_signature() {
        let config = fake_config();
        let state = fake_state();
        let signing_key = RS256KeyPair::generate(2048).unwrap().with_key_id("kid-1");
        let jwks_key = RS256KeyPair::generate(2048).unwrap().with_key_id("kid-1");
        let jwks = fake_jwks(&jwks_key);
        let token = sign_fake_token(
            &signing_key,
            "http://127.0.0.1:9001",
            "test-client",
            Some("provider-user-1"),
            Some("nonce-1"),
        );

        assert!(verify_oidc_id_token(&config, &state, &token, &jwks).is_err());
    }

    #[test]
    fn rejects_fake_oidc_token_with_wrong_issuer() {
        let config = fake_config();
        let state = fake_state();
        let key_pair = RS256KeyPair::generate(2048).unwrap().with_key_id("kid-1");
        let jwks = fake_jwks(&key_pair);
        let token = sign_fake_token(
            &key_pair,
            "http://127.0.0.1:9001/wrong",
            "test-client",
            Some("provider-user-1"),
            Some("nonce-1"),
        );

        assert!(verify_oidc_id_token(&config, &state, &token, &jwks).is_err());
    }

    #[test]
    fn rejects_fake_oidc_token_with_wrong_audience() {
        let config = fake_config();
        let state = fake_state();
        let key_pair = RS256KeyPair::generate(2048).unwrap().with_key_id("kid-1");
        let jwks = fake_jwks(&key_pair);
        let token = sign_fake_token(
            &key_pair,
            "http://127.0.0.1:9001",
            "wrong-client",
            Some("provider-user-1"),
            Some("nonce-1"),
        );

        assert!(verify_oidc_id_token(&config, &state, &token, &jwks).is_err());
    }

    #[test]
    fn rejects_fake_oidc_token_without_nonce() {
        let config = fake_config();
        let state = fake_state();
        let key_pair = RS256KeyPair::generate(2048).unwrap().with_key_id("kid-1");
        let jwks = fake_jwks(&key_pair);
        let token = sign_fake_token(
            &key_pair,
            "http://127.0.0.1:9001",
            "test-client",
            Some("provider-user-1"),
            None,
        );

        assert!(verify_oidc_id_token(&config, &state, &token, &jwks).is_err());
    }

    #[test]
    fn rejects_fake_oidc_token_without_subject() {
        let config = fake_config();
        let state = fake_state();
        let key_pair = RS256KeyPair::generate(2048).unwrap().with_key_id("kid-1");
        let jwks = fake_jwks(&key_pair);
        let token = sign_fake_token(
            &key_pair,
            "http://127.0.0.1:9001",
            "test-client",
            None,
            Some("nonce-1"),
        );

        assert!(verify_oidc_id_token(&config, &state, &token, &jwks).is_err());
    }

    #[test]
    fn maps_facebook_profile_response() {
        let profile = facebook_profile_from_response(&json!({
            "id": "fb-1",
            "email": "FACEBOOK@example.com",
            "name": "Facebook User"
        }))
        .unwrap();
        assert_eq!(profile.provider, OAuthProvider::Facebook);
        assert_eq!(profile.provider_user_id, "fb-1");
        assert_eq!(profile.email, "facebook@example.com");
        assert!(profile.email_verified);
    }

    #[test]
    fn fake_facebook_provider_flow_maps_graph_profile() {
        let config = fake_config_for(OAuthProvider::Facebook, "http://127.0.0.1:9001/facebook");
        let mut state = fake_state();
        state.provider = OAuthProvider::Facebook;
        state.redirect_uri = config.redirect_uri("http://localhost:3000");

        let auth_url = FakeFacebookProvider::authorize(&config, &state);
        let token_response = FakeFacebookProvider::token();
        let access_token = token_response
            .get("access_token")
            .and_then(Value::as_str)
            .unwrap();
        let profile = facebook_profile_from_response(&FakeFacebookProvider::me()).unwrap();

        assert!(auth_url.contains("/facebook/authorize?"));
        assert_eq!(access_token, "fake-facebook-access-token");
        assert_eq!(profile.provider, OAuthProvider::Facebook);
        assert_eq!(profile.provider_user_id, "facebook-user-1");
    }
}
