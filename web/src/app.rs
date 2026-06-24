use leptos::prelude::*;
use leptos_meta::*;
use leptos_router::components::{Route, Router, Routes};
use leptos_router::hooks::use_query_map;
use leptos_router::path;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(feature = "ssr")]
use chrono::Utc;

#[cfg(feature = "hydrate")]
use wasm_bindgen::prelude::*;

// ----------------------------------------------------------------------------
// Custom WebAuthn Models (to avoid native openssl dependencies under WASI)
// ----------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Rp {
    pub name: String,
    pub id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WebauthnUser {
    pub id: String,
    pub name: String,
    pub displayName: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PubKeyCredParam {
    pub alg: i32,
    #[serde(rename = "type")]
    pub cred_type: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CredentialDescriptor {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuthenticatorSelection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticatorAttachment: Option<String>,
    pub requireResidentKey: bool,
    pub userVerification: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicKeyCredentialCreationOptions {
    pub challenge: String,
    pub rp: Rp,
    pub user: WebauthnUser,
    pub pubKeyCredParams: Vec<PubKeyCredParam>,
    pub timeout: u64,
    pub excludeCredentials: Vec<CredentialDescriptor>,
    pub authenticatorSelection: AuthenticatorSelection,
    pub attestation: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CreationChallengeResponse {
    #[serde(rename = "publicKey")]
    pub public_key: PublicKeyCredentialCreationOptions,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicKeyCredentialRequestOptions {
    pub challenge: String,
    pub timeout: u64,
    pub rpId: String,
    pub allowCredentials: Vec<CredentialDescriptor>,
    pub userVerification: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RequestChallengeResponse {
    #[serde(rename = "publicKey")]
    pub public_key: PublicKeyCredentialRequestOptions,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegisterPublicKeyCredential {
    pub id: String,
    pub rawId: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub response: AuthenticatorAttestationResponse,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuthenticatorAttestationResponse {
    pub attestationObject: String,
    pub clientDataJSON: String,
    pub transports: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicKeyCredential {
    pub id: String,
    pub rawId: String,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub response: AuthenticatorAssertionResponse,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuthenticatorAssertionResponse {
    pub authenticatorData: String,
    pub clientDataJSON: String,
    pub signature: String,
    pub userHandle: Option<String>,
}

// ----------------------------------------------------------------------------
// Client-Side WebAuthn JS Bindings
// ----------------------------------------------------------------------------

#[cfg(feature = "hydrate")]
#[wasm_bindgen(inline_js = r#"
export async function registerPasskey(challengeJson) {
    const challenge = JSON.parse(challengeJson);
    
    challenge.publicKey.challenge = base64ToArrayBuffer(challenge.publicKey.challenge);
    challenge.publicKey.user.id = base64ToArrayBuffer(challenge.publicKey.user.id);
    if (challenge.publicKey.excludeCredentials) {
        for (let cred of challenge.publicKey.excludeCredentials) {
            cred.id = base64ToArrayBuffer(cred.id);
        }
    }
    
    const credential = await navigator.credentials.create({
        publicKey: challenge.publicKey
    });
    
    return JSON.stringify({
        id: credential.id,
        rawId: arrayBufferToBase64(credential.rawId),
        type: credential.type,
        response: {
            attestationObject: arrayBufferToBase64(credential.response.attestationObject),
            clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
            transports: credential.response.getTransports ? credential.response.getTransports() : []
        }
    });
}

export async function loginPasskey(challengeJson) {
    const challenge = JSON.parse(challengeJson);
    
    challenge.publicKey.challenge = base64ToArrayBuffer(challenge.publicKey.challenge);
    if (challenge.publicKey.allowCredentials) {
        for (let cred of challenge.publicKey.allowCredentials) {
            cred.id = base64ToArrayBuffer(cred.id);
        }
    }
    
    const credential = await navigator.credentials.get({
        publicKey: challenge.publicKey
    });
    
    return JSON.stringify({
        id: credential.id,
        rawId: arrayBufferToBase64(credential.rawId),
        type: credential.type,
        response: {
            authenticatorData: arrayBufferToBase64(credential.response.authenticatorData),
            clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
            signature: arrayBufferToBase64(credential.response.signature),
            userHandle: credential.response.userHandle ? arrayBufferToBase64(credential.response.userHandle) : null
        }
    });
}

function base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}
"#)]
extern "C" {
    #[wasm_bindgen(catch)]
    pub async fn registerPasskey(challenge_json: &str) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch)]
    pub async fn loginPasskey(challenge_json: &str) -> Result<JsValue, JsValue>;
}

// ----------------------------------------------------------------------------
// Shared Context Data Structs
// ----------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct UserInfo {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub role: String,
    #[serde(default)]
    pub has_passkey: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SessionInfo {
    pub id: Uuid,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: String,
    pub last_active_at: String,
    pub is_current: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FlushlineInfo {
    pub id: Uuid,
    pub owner: String,
    pub tier: String,
    pub current_pts: i32,
    pub cycle_count: i32,
    pub graduated: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MatrixSlotInfo {
    pub slot_number: i32,
    pub username: String,
    pub is_user: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MatrixInfo {
    pub id: Uuid,
    pub status: String,
    pub slots: Vec<MatrixSlotInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DashboardStatus {
    pub user: Option<UserInfo>,
    pub flushline: Option<FlushlineInfo>,
    pub matrix: Option<MatrixInfo>,
    pub sponsor_id: Option<Uuid>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AwardResponse {
    pub account_id: Uuid,
    pub current_pts: i32,
    pub cycle_count: i32,
    pub graduated: bool,
    pub new_spawned_account: Option<Uuid>,
}

// ----------------------------------------------------------------------------
// Leptos Server Functions
// ----------------------------------------------------------------------------

#[cfg(feature = "ssr")]
mod ssr_helpers {
    use super::*;
    use crate::rfn_store::{RfnState, User as DbUser};
    use chrono::Utc;

    pub fn check_rate_limit() -> Result<(), ServerFnError<String>> {
        use governor::{Quota, RateLimiter};
        use std::net::IpAddr;
        use std::num::NonZeroU32;
        use std::sync::OnceLock;

        static IP_LIMITER: OnceLock<governor::DefaultKeyedRateLimiter<IpAddr>> = OnceLock::new();

        let parts = use_context::<http::request::Parts>()
            .ok_or_else(|| ServerFnError::ServerError("Request context not found".to_string()))?;

        let client_ip = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));

        let limiter = IP_LIMITER.get_or_init(|| {
            let quota = Quota::per_second(NonZeroU32::new(100).unwrap()) // generous limit for local demo
                .allow_burst(NonZeroU32::new(200).unwrap());
            RateLimiter::keyed(quota)
        });

        if limiter.check_key(&client_ip).is_err() {
            return Err(ServerFnError::ServerError(
                "Too many requests. Please try again later.".to_string(),
            ));
        }

        Ok(())
    }

    pub fn authenticate_request(state: &RfnState) -> Result<DbUser, ServerFnError<String>> {
        let parts = use_context::<http::request::Parts>()
            .ok_or_else(|| ServerFnError::ServerError("Request context not found".to_string()))?;

        let cookie_header = parts
            .headers
            .get(http::header::COOKIE)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| {
                ServerFnError::ServerError("Authentication required (missing cookies)".to_string())
            })?;

        let mut token = None;
        for cookie_part in cookie_header.split(';') {
            let trimmed = cookie_part.trim();
            if let Some(t) = trimmed.strip_prefix("session_token=") {
                token = Some(t.to_string());
                break;
            }
        }

        let token = token.ok_or_else(|| {
            ServerFnError::ServerError(
                "Authentication required (missing session token)".to_string(),
            )
        })?;

        let session = state
            .sessions
            .get(&token)
            .ok_or_else(|| ServerFnError::ServerError("Invalid or expired session".to_string()))?;

        if session.expires_at < Utc::now() {
            return Err(ServerFnError::ServerError(
                "Session has expired".to_string(),
            ));
        }

        let user = state
            .users
            .get(&session.user_id)
            .ok_or_else(|| ServerFnError::ServerError("User not found".to_string()))?;

        Ok(user.clone())
    }

    pub fn resolve_sponsor_id(parts: &http::request::Parts) -> Option<Uuid> {
        let cookie_header = parts
            .headers
            .get(http::header::COOKIE)
            .and_then(|h| h.to_str().ok())?;

        for cookie_part in cookie_header.split(';') {
            let trimmed = cookie_part.trim();
            if let Some(s) = trimmed.strip_prefix("sponsor_id=") {
                if let Ok(id) = Uuid::parse_str(s) {
                    return Some(id);
                }
            }
        }
        None
    }
}

#[server(prefix = "/api")]
pub async fn request_magic_link(
    email: String,
    username: Option<String>,
) -> Result<String, ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::{MagicLinkRecord, get_state, save_state};
        use chrono::Duration;
        use rand::{Rng, distributions::Alphanumeric};

        ssr_helpers::check_rate_limit()?;

        let email = email.trim().to_lowercase();
        if email.is_empty() {
            return Err(ServerFnError::ServerError(
                "Email cannot be empty".to_string(),
            ));
        }

        let state_store = get_state();
        let mut state = state_store.write().unwrap();

        // 1. Verify or create user structure
        let _user_id = state
            .users
            .iter()
            .find(|(_, u)| u.email == email)
            .map(|(id, _)| *id)
            .unwrap_or_else(|| {
                let id = Uuid::new_v4();
                let display_username = username
                    .clone()
                    .unwrap_or_else(|| email.split('@').next().unwrap_or("user").to_string());

                state.users.insert(
                    id,
                    crate::rfn_store::User {
                        id,
                        email: email.clone(),
                        username: display_username,
                        role: "user".to_string(),
                        created_at: Utc::now(),
                        password_hash: None,
                    },
                );
                id
            });

        // 2. Generate secure token
        let token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let expires_at = Utc::now() + Duration::minutes(15);
        state.magic_links.insert(
            token.clone(),
            MagicLinkRecord {
                token: token.clone(),
                email,
                expires_at,
                used: false,
            },
        );

        save_state(&state);

        let parts = use_context::<http::request::Parts>();
        let host = parts
            .as_ref()
            .and_then(|p| p.headers.get(http::header::HOST))
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost:4000");

        println!(
            "MOCK EMAIL: Magic link requested. URL: http://{}/?token={}",
            host, token
        );
        Ok(token)
    }
    #[cfg(not(feature = "ssr"))]
    {
        let _ = (email, username);
        Err(ServerFnError::ServerError(
            "SSR feature not enabled".to_string(),
        ))
    }
}

#[server(prefix = "/api")]
pub async fn login_via_magic_link(token: String) -> Result<UserInfo, ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::{FlushlineAccount, Matrix, SessionRecord, get_state, save_state};
        use chrono::Duration;
        use http::HeaderValue;
        use leptos_wasi::response::ResponseOptions;
        use rand::{Rng, distributions::Alphanumeric};

        ssr_helpers::check_rate_limit()?;

        let state_store = get_state();
        let mut state = state_store.write().unwrap();

        let email = {
            let record = state
                .magic_links
                .get_mut(&token)
                .ok_or_else(|| ServerFnError::ServerError("Invalid token".to_string()))?;

            if record.used || record.expires_at < Utc::now() {
                return Err(ServerFnError::ServerError(
                    "Token has expired or already been used".to_string(),
                ));
            }

            record.used = true;
            record.email.clone()
        };

        // Retrieve user
        let user = state
            .users
            .iter()
            .find(|(_, u)| u.email == email)
            .map(|(_, u)| u.clone())
            .ok_or_else(|| ServerFnError::ServerError("User not found".to_string()))?;

        // Initialize Flushline Account and matrix tree if first time login
        let flushline_exists = state.flushline_accounts.contains_key(&user.id);
        if !flushline_exists {
            state.flushline_accounts.insert(
                user.id,
                FlushlineAccount {
                    id: user.id,
                    owner: user.username.clone(),
                    tier: "Ten".to_string(),
                    current_pts: 0,
                    cycle_count: 0,
                    graduated: false,
                },
            );

            // Map user account
            state.pot_bonus_registrations.insert(user.id, user.id);

            // Create personal matrix
            let matrix_id = Uuid::new_v4();
            state.matrices.insert(
                matrix_id,
                Matrix {
                    id: matrix_id,
                    owner_id: user.id,
                    status: "Filling".to_string(),
                },
            );
            state.matrix_slots.push(crate::rfn_store::MatrixSlot {
                matrix_id,
                slot_number: 1,
                account_id: user.id,
            });

            // Read referral sponsor cookie
            let parts = use_context::<http::request::Parts>();
            let mut sponsor_id = parts.as_ref().and_then(ssr_helpers::resolve_sponsor_id);

            // Fallback: If no sponsor_id in cookie, use the default seeded sponsor from pool
            if sponsor_id.is_none() && !state.sponsor_pool.is_empty() {
                sponsor_id = Some(state.sponsor_pool[0]);
            }

            if let Some(sp_id) = sponsor_id {
                let _ = crate::rfn_store::SagaCoordinator::place_in_matrix(
                    &mut state,
                    user.id,
                    sp_id,
                    &user.username,
                );
            }
        }

        // Generate Session
        let session_token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        let session_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::days(7);

        // Fetch User-Agent and IP from request parts
        let parts = use_context::<http::request::Parts>();
        let user_agent = parts
            .as_ref()
            .and_then(|p| p.headers.get(http::header::USER_AGENT))
            .and_then(|h| h.to_str().ok().map(|s| s.to_string()));
        let ip_address = parts
            .as_ref()
            .and_then(|p| p.headers.get("x-forwarded-for"))
            .and_then(|h| h.to_str().ok().map(|s| s.to_string()));

        state.sessions.insert(
            session_token.clone(),
            SessionRecord {
                id: session_id,
                user_id: user.id,
                session_token: session_token.clone(),
                user_agent,
                ip_address,
                expires_at,
                created_at: Utc::now(),
                last_active_at: Utc::now(),
            },
        );

        save_state(&state);

        // Set secure cookie
        if let Some(res_opts) = use_context::<ResponseOptions>() {
            let cookie_str = format!(
                "session_token={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800",
                session_token
            );
            res_opts.insert_header(
                http::header::SET_COOKIE,
                HeaderValue::from_str(&cookie_str).unwrap(),
            );
        }

        let has_passkey = state.passkeys.iter().any(|pk| pk.user_id == user.id);

        Ok(UserInfo {
            id: user.id,
            email: user.email,
            username: user.username,
            role: user.role,
            has_passkey,
        })
    }
    #[cfg(not(feature = "ssr"))]
    {
        let _ = token;
        Err(ServerFnError::ServerError(
            "SSR feature not enabled".to_string(),
        ))
    }
}

#[server(prefix = "/api")]
pub async fn check_local_testing_enabled() -> Result<bool, ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        Ok(std::env::var("SHOW_LOCAL_TESTING_LINKS")
            .map(|val| val == "true" || val == "1")
            .unwrap_or(false))
    }
    #[cfg(not(feature = "ssr"))]
    {
        Err(ServerFnError::ServerError(
            "SSR feature not enabled".to_string(),
        ))
    }
}

#[server(prefix = "/api")]
pub async fn register_with_password(
    email: String,
    username: String,
    password: String,
) -> Result<UserInfo, ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::{
            FlushlineAccount, Matrix, SessionRecord, User, get_state, save_state,
        };
        use chrono::Duration;
        use http::HeaderValue;
        use leptos_wasi::response::ResponseOptions;
        use rand::{Rng, distributions::Alphanumeric};

        ssr_helpers::check_rate_limit()?;

        let email = email.trim().to_lowercase();
        if email.is_empty() {
            return Err(ServerFnError::ServerError(
                "Email cannot be empty".to_string(),
            ));
        }
        if password.len() < 8 {
            return Err(ServerFnError::ServerError(
                "Password must be at least 8 characters".to_string(),
            ));
        }

        let state_store = get_state();
        let mut state = state_store.write().unwrap();

        // Check if user already exists
        if state.users.values().any(|u| u.email == email) {
            return Err(ServerFnError::ServerError(
                "This email is already registered. Please log in.".to_string(),
            ));
        }

        // Hash password
        let password_hash = bcrypt::hash(&password, bcrypt::DEFAULT_COST)
            .map_err(|e| ServerFnError::ServerError(format!("Password hashing failed: {e}")))?;

        let user_id = Uuid::new_v4();
        let display_username = if username.trim().is_empty() {
            email.split('@').next().unwrap_or("user").to_string()
        } else {
            username.trim().to_string()
        };

        let user = User {
            id: user_id,
            email: email.clone(),
            username: display_username,
            role: "user".to_string(),
            created_at: Utc::now(),
            password_hash: Some(password_hash),
        };
        state.users.insert(user_id, user.clone());

        // Initialize Flushline Account and matrix tree
        state.flushline_accounts.insert(
            user_id,
            FlushlineAccount {
                id: user_id,
                owner: user.username.clone(),
                tier: "Ten".to_string(),
                current_pts: 0,
                cycle_count: 0,
                graduated: false,
            },
        );

        // Map user account
        state.pot_bonus_registrations.insert(user_id, user_id);

        // Create personal matrix
        let matrix_id = Uuid::new_v4();
        state.matrices.insert(
            matrix_id,
            Matrix {
                id: matrix_id,
                owner_id: user_id,
                status: "Filling".to_string(),
            },
        );
        state.matrix_slots.push(crate::rfn_store::MatrixSlot {
            matrix_id,
            slot_number: 1,
            account_id: user_id,
        });

        // Read referral sponsor cookie
        let parts = use_context::<http::request::Parts>();
        let mut sponsor_id = parts.as_ref().and_then(ssr_helpers::resolve_sponsor_id);

        // Fallback: If no sponsor_id in cookie, use the default seeded sponsor from pool
        if sponsor_id.is_none() && !state.sponsor_pool.is_empty() {
            sponsor_id = Some(state.sponsor_pool[0]);
        }

        if let Some(sp_id) = sponsor_id {
            let _ = crate::rfn_store::SagaCoordinator::place_in_matrix(
                &mut state,
                user_id,
                sp_id,
                &user.username,
            );
        }

        // Generate Session
        let session_token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        let session_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::days(7);

        let user_agent = parts
            .as_ref()
            .and_then(|p| p.headers.get(http::header::USER_AGENT))
            .and_then(|h| h.to_str().ok().map(|s| s.to_string()));
        let ip_address = parts
            .as_ref()
            .and_then(|p| p.headers.get("x-forwarded-for"))
            .and_then(|h| h.to_str().ok().map(|s| s.to_string()));

        state.sessions.insert(
            session_token.clone(),
            SessionRecord {
                id: session_id,
                user_id,
                session_token: session_token.clone(),
                user_agent,
                ip_address,
                expires_at,
                created_at: Utc::now(),
                last_active_at: Utc::now(),
            },
        );

        save_state(&state);

        // Set secure cookie
        if let Some(res_opts) = use_context::<ResponseOptions>() {
            let cookie_str = format!(
                "session_token={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800",
                session_token
            );
            res_opts.insert_header(
                http::header::SET_COOKIE,
                HeaderValue::from_str(&cookie_str).unwrap(),
            );
        }

        let has_passkey = state.passkeys.iter().any(|pk| pk.user_id == user.id);

        Ok(UserInfo {
            id: user.id,
            email: user.email,
            username: user.username,
            role: user.role,
            has_passkey,
        })
    }
    #[cfg(not(feature = "ssr"))]
    {
        let _ = (email, username, password);
        Err(ServerFnError::ServerError(
            "SSR feature not enabled".to_string(),
        ))
    }
}

#[server(prefix = "/api")]
pub async fn login_with_password(
    email: String,
    password: String,
) -> Result<UserInfo, ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::{SessionRecord, get_state, save_state};
        use chrono::Duration;
        use http::HeaderValue;
        use leptos_wasi::response::ResponseOptions;
        use rand::{Rng, distributions::Alphanumeric};

        ssr_helpers::check_rate_limit()?;

        let email = email.trim().to_lowercase();
        if email.is_empty() {
            return Err(ServerFnError::ServerError(
                "Email cannot be empty".to_string(),
            ));
        }

        let state_store = get_state();
        let state = state_store.read().unwrap();

        // Retrieve user
        let user = state
            .users
            .values()
            .find(|u| u.email == email)
            .cloned()
            .ok_or_else(|| ServerFnError::ServerError("Invalid email or password".to_string()))?;

        let password_hash = user.password_hash.as_ref()
            .ok_or_else(|| ServerFnError::ServerError("This account does not have a password configured. Please log in using Magic Link or Passkey.".to_string()))?;

        let valid = bcrypt::verify(&password, password_hash).map_err(|e| {
            ServerFnError::ServerError(format!("Password verification failed: {e}"))
        })?;

        if !valid {
            return Err(ServerFnError::ServerError(
                "Invalid email or password".to_string(),
            ));
        }

        drop(state);
        let mut state = state_store.write().unwrap();

        // Generate Session
        let session_token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        let session_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::days(7);

        let parts = use_context::<http::request::Parts>();
        let user_agent = parts
            .as_ref()
            .and_then(|p| p.headers.get(http::header::USER_AGENT))
            .and_then(|h| h.to_str().ok().map(|s| s.to_string()));
        let ip_address = parts
            .as_ref()
            .and_then(|p| p.headers.get("x-forwarded-for"))
            .and_then(|h| h.to_str().ok().map(|s| s.to_string()));

        state.sessions.insert(
            session_token.clone(),
            SessionRecord {
                id: session_id,
                user_id: user.id,
                session_token: session_token.clone(),
                user_agent,
                ip_address,
                expires_at,
                created_at: Utc::now(),
                last_active_at: Utc::now(),
            },
        );

        save_state(&state);

        // Set secure cookie
        if let Some(res_opts) = use_context::<ResponseOptions>() {
            let cookie_str = format!(
                "session_token={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800",
                session_token
            );
            res_opts.insert_header(
                http::header::SET_COOKIE,
                HeaderValue::from_str(&cookie_str).unwrap(),
            );
        }

        let has_passkey = state.passkeys.iter().any(|pk| pk.user_id == user.id);

        Ok(UserInfo {
            id: user.id,
            email: user.email,
            username: user.username,
            role: user.role,
            has_passkey,
        })
    }
    #[cfg(not(feature = "ssr"))]
    {
        let _ = (email, password);
        Err(ServerFnError::ServerError(
            "SSR feature not enabled".to_string(),
        ))
    }
}

#[server(prefix = "/api")]
pub async fn set_referral_cookie_ssr(sponsor_id: Uuid) -> Result<(), ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use http::HeaderValue;
        use leptos_wasi::response::ResponseOptions;

        ssr_helpers::check_rate_limit()?;

        if let Some(res_opts) = use_context::<ResponseOptions>() {
            let cookie_str = format!(
                "sponsor_id={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000",
                sponsor_id
            );
            res_opts.insert_header(
                http::header::SET_COOKIE,
                HeaderValue::from_str(&cookie_str).unwrap(),
            );
        }
        Ok(())
    }
    #[cfg(not(feature = "ssr"))]
    {
        let _ = sponsor_id;
        Err(ServerFnError::ServerError(
            "SSR feature not enabled".to_string(),
        ))
    }
}

#[server(prefix = "/api")]
pub async fn logout() -> Result<(), ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::{get_state, save_state};
        use http::HeaderValue;
        use leptos_wasi::response::ResponseOptions;

        ssr_helpers::check_rate_limit()?;

        let state_store = get_state();
        let mut state = state_store.write().unwrap();

        // Find session from cookie
        if let Some(parts) = use_context::<http::request::Parts>() {
            if let Some(cookie_header) = parts
                .headers
                .get(http::header::COOKIE)
                .and_then(|h| h.to_str().ok())
            {
                let mut token = None;
                for cookie_part in cookie_header.split(';') {
                    let trimmed = cookie_part.trim();
                    if let Some(t) = trimmed.strip_prefix("session_token=") {
                        token = Some(t.to_string());
                        break;
                    }
                }

                if let Some(t) = token {
                    state.sessions.remove(&t);
                    save_state(&state);
                }
            }
        }

        // Unset cookie
        if let Some(res_opts) = use_context::<ResponseOptions>() {
            res_opts.insert_header(
                http::header::SET_COOKIE,
                HeaderValue::from_static(
                    "session_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                ),
            );
        }

        Ok(())
    }
    #[cfg(not(feature = "ssr"))]
    {
        Err(ServerFnError::ServerError(
            "SSR feature not enabled".to_string(),
        ))
    }
}

#[server(prefix = "/api")]
pub async fn get_user_dashboard_status() -> Result<DashboardStatus, ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::get_state;

        ssr_helpers::check_rate_limit()?;
        let state_store = get_state();
        let state = state_store.read().unwrap();

        // 1. Authenticate user
        let user = match ssr_helpers::authenticate_request(&state) {
            Ok(u) => u,
            Err(_) => return Ok(DashboardStatus::default()), // Not logged in
        };

        // 2. Fetch Flushline Info
        let flushline = state
            .flushline_accounts
            .get(&user.id)
            .map(|fa| FlushlineInfo {
                id: fa.id,
                owner: fa.owner.clone(),
                tier: fa.tier.clone(),
                current_pts: fa.current_pts,
                cycle_count: fa.cycle_count,
                graduated: fa.graduated,
            });

        // 3. Fetch Matrix Info
        let matrix = state
            .matrices
            .iter()
            .find(|(_, m)| m.owner_id == user.id && m.status == "Filling")
            .map(|(id, m)| {
                // Load slots for this matrix
                let mut slot_infos = Vec::new();
                for slot in &state.matrix_slots {
                    if slot.matrix_id == *id {
                        let username = state
                            .flushline_accounts
                            .get(&slot.account_id)
                            .map(|a| a.owner.clone())
                            .unwrap_or_else(|| "Empty".to_string());

                        slot_infos.push(MatrixSlotInfo {
                            slot_number: slot.slot_number,
                            username,
                            is_user: slot.account_id == user.id,
                        });
                    }
                }

                // Add empty placeholders
                for slot in 1..=7 {
                    if !slot_infos.iter().any(|si| si.slot_number == slot) {
                        slot_infos.push(MatrixSlotInfo {
                            slot_number: slot,
                            username: "Empty".to_string(),
                            is_user: false,
                        });
                    }
                }
                slot_infos.sort_by_key(|s| s.slot_number);

                MatrixInfo {
                    id: *id,
                    status: m.status.clone(),
                    slots: slot_infos,
                }
            });

        // 4. Resolve sponsor ID from cookie or state
        let parts = use_context::<http::request::Parts>();
        let sponsor_id = parts
            .as_ref()
            .and_then(ssr_helpers::resolve_sponsor_id)
            .or_else(|| {
                // fallback to first sponsor in state pool
                state.sponsor_pool.first().cloned()
            });

        let has_passkey = state.passkeys.iter().any(|pk| pk.user_id == user.id);

        Ok(DashboardStatus {
            user: Some(UserInfo {
                id: user.id,
                email: user.email,
                username: user.username,
                role: user.role,
                has_passkey,
            }),
            flushline,
            matrix,
            sponsor_id,
        })
    }
    #[cfg(not(feature = "ssr"))]
    {
        Err(ServerFnError::ServerError("SSR not enabled".to_string()))
    }
}

#[server(prefix = "/api")]
pub async fn get_active_sessions() -> Result<Vec<SessionInfo>, ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::get_state;

        ssr_helpers::check_rate_limit()?;
        let state_store = get_state();
        let state = state_store.read().unwrap();
        let user = ssr_helpers::authenticate_request(&state)?;

        // Find current token from cookies
        let parts = use_context::<http::request::Parts>().unwrap();
        let cookie_header = parts
            .headers
            .get(http::header::COOKIE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let mut current_token = "";
        for cookie_part in cookie_header.split(';') {
            let trimmed = cookie_part.trim();
            if let Some(t) = trimmed.strip_prefix("session_token=") {
                current_token = t;
                break;
            }
        }

        let sessions: Vec<SessionInfo> = state
            .sessions
            .values()
            .filter(|s| s.user_id == user.id && s.expires_at > Utc::now())
            .map(|s| SessionInfo {
                id: s.id,
                user_agent: s.user_agent.clone(),
                ip_address: s.ip_address.clone(),
                created_at: s.created_at.to_rfc3339(),
                last_active_at: s.last_active_at.to_rfc3339(),
                is_current: s.session_token == current_token,
            })
            .collect();

        Ok(sessions)
    }
    #[cfg(not(feature = "ssr"))]
    {
        Err(ServerFnError::ServerError("SSR not enabled".to_string()))
    }
}

#[server(prefix = "/api")]
pub async fn revoke_session(session_id: Uuid) -> Result<(), ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::{get_state, save_state};

        ssr_helpers::check_rate_limit()?;
        let state_store = get_state();
        let mut state = state_store.write().unwrap();
        let user = ssr_helpers::authenticate_request(&state)?;

        // Remove matching session if owned by user
        let mut token_to_remove = None;
        for (token, session) in &state.sessions {
            if session.id == session_id && session.user_id == user.id {
                token_to_remove = Some(token.clone());
                break;
            }
        }

        if let Some(t) = token_to_remove {
            state.sessions.remove(&t);
            save_state(&state);
            Ok(())
        } else {
            Err(ServerFnError::ServerError(
                "Session not found or permission denied".to_string(),
            ))
        }
    }
    #[cfg(not(feature = "ssr"))]
    {
        let _ = session_id;
        Err(ServerFnError::ServerError("SSR not enabled".to_string()))
    }
}

#[server(prefix = "/api")]
pub async fn revoke_other_sessions() -> Result<(), ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::{get_state, save_state};

        ssr_helpers::check_rate_limit()?;
        let state_store = get_state();
        let mut state = state_store.write().unwrap();
        let user = ssr_helpers::authenticate_request(&state)?;

        // Find current token from cookies
        let parts = use_context::<http::request::Parts>().unwrap();
        let cookie_header = parts
            .headers
            .get(http::header::COOKIE)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let mut current_token = String::new();
        for cookie_part in cookie_header.split(';') {
            let trimmed = cookie_part.trim();
            if let Some(t) = trimmed.strip_prefix("session_token=") {
                current_token = t.to_string();
                break;
            }
        }

        state
            .sessions
            .retain(|token, s| s.user_id != user.id || *token == current_token);

        save_state(&state);
        Ok(())
    }
    #[cfg(not(feature = "ssr"))]
    {
        Err(ServerFnError::ServerError("SSR not enabled".to_string()))
    }
}

#[server(prefix = "/api")]
pub async fn award_points(points: u32) -> Result<AwardResponse, ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::{SagaCoordinator, get_state};

        ssr_helpers::check_rate_limit()?;
        let state_store = get_state();
        let mut state = state_store.write().unwrap();
        let user = ssr_helpers::authenticate_request(&state)?;

        // Award points transactionally using our sync coordinator
        SagaCoordinator::award_points(&mut state, user.id, points)
            .map_err(|e| ServerFnError::ServerError(e))?;

        let account = state.flushline_accounts.get(&user.id).unwrap();
        let coord = state.coordination_states.get(&user.id);

        let new_spawned_account = if let Some(c) = coord {
            if c.new_account_spawned {
                // Retrieve the newly spawned free account owned by this user
                state
                    .flushline_accounts
                    .values()
                    .find(|a| {
                        a.owner.starts_with("FreeAccount_")
                            && state.pot_bonus_registrations.get(&a.id) == Some(&user.id)
                    })
                    .map(|a| a.id)
            } else {
                None
            }
        } else {
            None
        };

        Ok(AwardResponse {
            account_id: account.id,
            current_pts: account.current_pts,
            cycle_count: account.cycle_count,
            graduated: account.graduated,
            new_spawned_account,
        })
    }
    #[cfg(not(feature = "ssr"))]
    {
        let _ = points;
        Err(ServerFnError::ServerError("SSR not enabled".to_string()))
    }
}

// ----------------------------------------------------------------------------
// WebAuthn Passkey Handshakes Server Functions
// ----------------------------------------------------------------------------

#[server(prefix = "/api")]
pub async fn register_passkey_start() -> Result<String, ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::{ChallengeRecord, get_state, save_state};
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use chrono::Duration;

        ssr_helpers::check_rate_limit()?;
        let state_store = get_state();
        let mut state = state_store.write().unwrap();
        let user = ssr_helpers::authenticate_request(&state)?;

        let challenge_bytes: [u8; 32] = rand::random();
        let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge_bytes);

        let user_id_b64 = URL_SAFE_NO_PAD.encode(user.id.as_bytes());

        let challenge_response = CreationChallengeResponse {
            public_key: PublicKeyCredentialCreationOptions {
                challenge: challenge_b64,
                rp: Rp {
                    name: "MaxPayout".to_string(),
                    id: "localhost".to_string(),
                },
                user: WebauthnUser {
                    id: user_id_b64,
                    name: user.username.clone(),
                    displayName: user.username.clone(),
                },
                pubKeyCredParams: vec![
                    PubKeyCredParam {
                        alg: -7,
                        cred_type: "public-key".to_string(),
                    }, // ES256
                    PubKeyCredParam {
                        alg: -257,
                        cred_type: "public-key".to_string(),
                    }, // RS256
                ],
                timeout: 60000,
                excludeCredentials: vec![],
                authenticatorSelection: AuthenticatorSelection {
                    authenticatorAttachment: None,
                    requireResidentKey: true,
                    userVerification: "preferred".to_string(),
                },
                attestation: "none".to_string(),
            },
        };

        let challenge_id = Uuid::new_v4();
        let challenge_json = serde_json::to_value(&challenge_response).unwrap();

        state.challenges.insert(
            challenge_id,
            ChallengeRecord {
                challenge_id,
                user_id: Some(user.id),
                challenge_json,
                expires_at: Utc::now() + Duration::minutes(10),
                email: Some(user.email.clone()),
            },
        );

        save_state(&state);

        Ok(serde_json::to_string(&challenge_response).unwrap())
    }
    #[cfg(not(feature = "ssr"))]
    {
        Err(ServerFnError::ServerError("SSR not enabled".to_string()))
    }
}

#[server(prefix = "/api")]
pub async fn register_passkey_finish(credential_json: String) -> Result<(), ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::{PasskeyRecord, get_state, save_state};
        use base64::Engine;

        ssr_helpers::check_rate_limit()?;
        let state_store = get_state();
        let mut state = state_store.write().unwrap();
        let user = ssr_helpers::authenticate_request(&state)?;

        let credential: RegisterPublicKeyCredential = serde_json::from_str(&credential_json)
            .map_err(|e| ServerFnError::ServerError(format!("Failed to parse credential: {e}")))?;

        // Find active challenge for user
        let challenge_id = state
            .challenges
            .iter()
            .find(|(_, c)| c.user_id == Some(user.id) && c.expires_at > Utc::now())
            .map(|(id, _)| *id)
            .ok_or_else(|| {
                ServerFnError::ServerError("Challenge expired or not found".to_string())
            })?;

        state.challenges.remove(&challenge_id);

        let cred_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&credential.id)
            .unwrap_or_else(|_| credential.id.as_bytes().to_vec());

        state.passkeys.push(PasskeyRecord {
            user_id: user.id,
            credential_id: cred_id,
            passkey_json: serde_json::to_value(&credential).unwrap(),
        });

        save_state(&state);
        Ok(())
    }
    #[cfg(not(feature = "ssr"))]
    {
        let _ = credential_json;
        Err(ServerFnError::ServerError("SSR not enabled".to_string()))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum PasskeyStartResponse {
    Login {
        challenge_id: Uuid,
        challenge_json: String,
    },
    Register {
        challenge_id: Uuid,
        challenge_json: String,
        email: String,
    },
}

#[server(prefix = "/api")]
pub async fn login_passkey_start(
    email: String,
) -> Result<PasskeyStartResponse, ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::{ChallengeRecord, get_state, save_state};
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use chrono::Duration;

        ssr_helpers::check_rate_limit()?;
        let email = email.trim().to_lowercase();
        let state_store = get_state();

        let challenge_bytes: [u8; 32] = rand::random();
        let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge_bytes);

        if email.is_empty() {
            // Discoverable credentials challenge
            let challenge_response = RequestChallengeResponse {
                public_key: PublicKeyCredentialRequestOptions {
                    challenge: challenge_b64,
                    timeout: 60000,
                    rpId: "localhost".to_string(),
                    allowCredentials: vec![],
                    userVerification: "preferred".to_string(),
                },
            };

            let mut state = state_store.write().unwrap();
            let challenge_id = Uuid::new_v4();
            let challenge_json = serde_json::to_value(&challenge_response).unwrap();

            state.challenges.insert(
                challenge_id,
                ChallengeRecord {
                    challenge_id,
                    user_id: None,
                    challenge_json,
                    expires_at: Utc::now() + Duration::minutes(10),
                    email: None,
                },
            );

            save_state(&state);

            let challenge_str = serde_json::to_string(&challenge_response).unwrap();
            return Ok(PasskeyStartResponse::Login {
                challenge_id,
                challenge_json: challenge_str,
            });
        }

        let state = state_store.read().unwrap();
        let user_opt = state.users.values().find(|u| u.email == email).cloned();

        match user_opt {
            Some(user) => {
                // Find registered credentials
                let user_passkeys: Vec<crate::rfn_store::PasskeyRecord> = state
                    .passkeys
                    .iter()
                    .filter(|pk| pk.user_id == user.id)
                    .cloned()
                    .collect();

                if user_passkeys.is_empty() {
                    return Err(ServerFnError::ServerError("This account exists but has no passkeys registered. Please log in using a Magic Link first, then enroll your device under Settings.".to_string()));
                }

                let allow_credentials = user_passkeys
                    .iter()
                    .map(|pk| {
                        let cred_id_b64 = URL_SAFE_NO_PAD.encode(&pk.credential_id);
                        CredentialDescriptor {
                            cred_type: "public-key".to_string(),
                            id: cred_id_b64,
                            transports: None,
                        }
                    })
                    .collect();

                let challenge_response = RequestChallengeResponse {
                    public_key: PublicKeyCredentialRequestOptions {
                        challenge: challenge_b64,
                        timeout: 60000,
                        rpId: "localhost".to_string(),
                        allowCredentials: allow_credentials,
                        userVerification: "preferred".to_string(),
                    },
                };

                drop(state);
                let mut state = state_store.write().unwrap();

                let challenge_id = Uuid::new_v4();
                let challenge_json = serde_json::to_value(&challenge_response).unwrap();

                state.challenges.insert(
                    challenge_id,
                    ChallengeRecord {
                        challenge_id,
                        user_id: Some(user.id),
                        challenge_json,
                        expires_at: Utc::now() + Duration::minutes(10),
                        email: Some(user.email.clone()),
                    },
                );

                save_state(&state);

                let challenge_str = serde_json::to_string(&challenge_response).unwrap();

                Ok(PasskeyStartResponse::Login {
                    challenge_id,
                    challenge_json: challenge_str,
                })
            }
            None => {
                // User does not exist - trigger a passwordless registration challenge!
                let new_user_id = Uuid::new_v4();
                let user_id_b64 = URL_SAFE_NO_PAD.encode(new_user_id.as_bytes());
                let display_username = email.split('@').next().unwrap_or("user").to_string();

                let challenge_response = CreationChallengeResponse {
                    public_key: PublicKeyCredentialCreationOptions {
                        challenge: challenge_b64,
                        rp: Rp {
                            name: "MaxPayout".to_string(),
                            id: "localhost".to_string(),
                        },
                        user: WebauthnUser {
                            id: user_id_b64,
                            name: display_username.clone(),
                            displayName: display_username.clone(),
                        },
                        pubKeyCredParams: vec![
                            PubKeyCredParam {
                                alg: -7,
                                cred_type: "public-key".to_string(),
                            }, // ES256
                            PubKeyCredParam {
                                alg: -257,
                                cred_type: "public-key".to_string(),
                            }, // RS256
                        ],
                        timeout: 60000,
                        excludeCredentials: vec![],
                        authenticatorSelection: AuthenticatorSelection {
                            authenticatorAttachment: None,
                            requireResidentKey: true,
                            userVerification: "preferred".to_string(),
                        },
                        attestation: "none".to_string(),
                    },
                };

                drop(state);
                let mut state = state_store.write().unwrap();

                let challenge_id = Uuid::new_v4();
                let challenge_json = serde_json::to_value(&challenge_response).unwrap();

                state.challenges.insert(
                    challenge_id,
                    ChallengeRecord {
                        challenge_id,
                        user_id: Some(new_user_id),
                        challenge_json,
                        expires_at: Utc::now() + Duration::minutes(10),
                        email: Some(email.clone()),
                    },
                );

                save_state(&state);

                let challenge_str = serde_json::to_string(&challenge_response).unwrap();

                Ok(PasskeyStartResponse::Register {
                    challenge_id,
                    challenge_json: challenge_str,
                    email,
                })
            }
        }
    }
    #[cfg(not(feature = "ssr"))]
    {
        let _ = email;
        Err(ServerFnError::ServerError("SSR not enabled".to_string()))
    }
}

#[server(prefix = "/api")]
pub async fn login_passkey_finish(
    challenge_id: Uuid,
    credential_json: String,
) -> Result<UserInfo, ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::{SessionRecord, get_state, save_state};
        use base64::Engine;
        use chrono::Duration;
        use http::HeaderValue;
        use leptos_wasi::response::ResponseOptions;
        use rand::{Rng, distributions::Alphanumeric};

        ssr_helpers::check_rate_limit()?;
        let state_store = get_state();
        let mut state = state_store.write().unwrap();

        let record = state.challenges.remove(&challenge_id).ok_or_else(|| {
            ServerFnError::ServerError("Challenge expired or not found".to_string())
        })?;

        let credential: PublicKeyCredential = serde_json::from_str(&credential_json)
            .map_err(|e| ServerFnError::ServerError(format!("Invalid credential format: {e}")))?;

        let user_id = match record.user_id {
            Some(uid) => uid,
            None => {
                // Discoverable login: look up credential.id/rawId
                let incoming_cred_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(&credential.id)
                    .unwrap_or_else(|_| credential.id.as_bytes().to_vec());

                state
                    .passkeys
                    .iter()
                    .find(|pk| pk.credential_id == incoming_cred_id)
                    .map(|pk| pk.user_id)
                    .ok_or_else(|| {
                        ServerFnError::ServerError(
                            "No registered user found matching this passkey".to_string(),
                        )
                    })?
            }
        };

        // Retrieve user
        let user = state
            .users
            .get(&user_id)
            .ok_or_else(|| ServerFnError::ServerError("User not found".to_string()))?
            .clone();

        // Create active session
        let session_token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        let session_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::days(7);

        // Fetch headers
        let parts = use_context::<http::request::Parts>();
        let user_agent = parts
            .as_ref()
            .and_then(|p| p.headers.get(http::header::USER_AGENT))
            .and_then(|h| h.to_str().ok().map(|s| s.to_string()));
        let ip_address = parts
            .as_ref()
            .and_then(|p| p.headers.get("x-forwarded-for"))
            .and_then(|h| h.to_str().ok().map(|s| s.to_string()));

        state.sessions.insert(
            session_token.clone(),
            SessionRecord {
                id: session_id,
                user_id: user.id,
                session_token: session_token.clone(),
                user_agent,
                ip_address,
                expires_at,
                created_at: Utc::now(),
                last_active_at: Utc::now(),
            },
        );

        save_state(&state);

        // Set secure cookie
        if let Some(res_opts) = use_context::<ResponseOptions>() {
            let cookie_str = format!(
                "session_token={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800",
                session_token
            );
            res_opts.insert_header(
                http::header::SET_COOKIE,
                HeaderValue::from_str(&cookie_str).unwrap(),
            );
        }

        let has_passkey = state.passkeys.iter().any(|pk| pk.user_id == user.id);

        Ok(UserInfo {
            id: user.id,
            email: user.email,
            username: user.username,
            role: user.role,
            has_passkey,
        })
    }
    #[cfg(not(feature = "ssr"))]
    {
        let _ = (challenge_id, credential_json);
        Err(ServerFnError::ServerError("SSR not enabled".to_string()))
    }
}

#[server(prefix = "/api")]
pub async fn register_passkey_finish_signup(
    challenge_id: Uuid,
    credential_json: String,
) -> Result<UserInfo, ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::{
            FlushlineAccount, Matrix, PasskeyRecord, SagaCoordinator, SessionRecord, get_state,
            save_state,
        };
        use base64::Engine;
        use chrono::Duration;
        use http::HeaderValue;
        use leptos_wasi::response::ResponseOptions;
        use rand::{Rng, distributions::Alphanumeric};

        ssr_helpers::check_rate_limit()?;
        let state_store = get_state();
        let mut state = state_store.write().unwrap();

        let record = state.challenges.remove(&challenge_id).ok_or_else(|| {
            ServerFnError::ServerError("Challenge expired or not found".to_string())
        })?;

        let user_id = record
            .user_id
            .ok_or_else(|| ServerFnError::ServerError("Invalid challenge record".to_string()))?;
        let email = record.email.ok_or_else(|| {
            ServerFnError::ServerError("Email not associated with this challenge".to_string())
        })?;

        // 1. Double check if email already registered
        if state.users.values().any(|u| u.email == email) {
            return Err(ServerFnError::ServerError(
                "This email is already registered.".to_string(),
            ));
        }

        let username = email.split('@').next().unwrap_or("user").to_string();

        // 2. Create the user
        let user = crate::rfn_store::User {
            id: user_id,
            email: email.clone(),
            username: username.clone(),
            role: "user".to_string(),
            created_at: Utc::now(),
            password_hash: None,
        };
        state.users.insert(user_id, user.clone());

        // 3. Register the passkey
        let credential: RegisterPublicKeyCredential = serde_json::from_str(&credential_json)
            .map_err(|e| ServerFnError::ServerError(format!("Failed to parse credential: {e}")))?;

        let cred_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&credential.id)
            .unwrap_or_else(|_| credential.id.as_bytes().to_vec());

        state.passkeys.push(PasskeyRecord {
            user_id,
            credential_id: cred_id,
            passkey_json: serde_json::to_value(&credential).unwrap(),
        });

        // 4. Initialize Flushline Account and matrix tree (same as magic link signup)
        state.flushline_accounts.insert(
            user_id,
            FlushlineAccount {
                id: user_id,
                owner: username.clone(),
                tier: "Ten".to_string(),
                current_pts: 0,
                cycle_count: 0,
                graduated: false,
            },
        );

        state.pot_bonus_registrations.insert(user_id, user_id);

        let matrix_id = Uuid::new_v4();
        state.matrices.insert(
            matrix_id,
            Matrix {
                id: matrix_id,
                owner_id: user_id,
                status: "Filling".to_string(),
            },
        );
        state.matrix_slots.push(crate::rfn_store::MatrixSlot {
            matrix_id,
            slot_number: 1,
            account_id: user_id,
        });

        // Read referral sponsor cookie
        let parts = use_context::<http::request::Parts>();
        let mut sponsor_id = parts.as_ref().and_then(ssr_helpers::resolve_sponsor_id);

        if sponsor_id.is_none() && !state.sponsor_pool.is_empty() {
            sponsor_id = Some(state.sponsor_pool[0]);
        }

        if let Some(sp_id) = sponsor_id {
            let _ = SagaCoordinator::place_in_matrix(&mut state, user_id, sp_id, &username);
        }

        // 5. Generate Session
        let session_token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        let session_id = Uuid::new_v4();
        let expires_at = Utc::now() + Duration::days(7);

        let user_agent = parts
            .as_ref()
            .and_then(|p| p.headers.get(http::header::USER_AGENT))
            .and_then(|h| h.to_str().ok().map(|s| s.to_string()));
        let ip_address = parts
            .as_ref()
            .and_then(|p| p.headers.get("x-forwarded-for"))
            .and_then(|h| h.to_str().ok().map(|s| s.to_string()));

        state.sessions.insert(
            session_token.clone(),
            SessionRecord {
                id: session_id,
                user_id,
                session_token: session_token.clone(),
                user_agent,
                ip_address,
                expires_at,
                created_at: Utc::now(),
                last_active_at: Utc::now(),
            },
        );

        save_state(&state);

        // Set secure cookie
        if let Some(res_opts) = use_context::<ResponseOptions>() {
            let cookie_str = format!(
                "session_token={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800",
                session_token
            );
            res_opts.insert_header(
                http::header::SET_COOKIE,
                HeaderValue::from_str(&cookie_str).unwrap(),
            );
        }

        let has_passkey = state.passkeys.iter().any(|pk| pk.user_id == user.id);

        Ok(UserInfo {
            id: user.id,
            email: user.email,
            username: user.username,
            role: user.role,
            has_passkey,
        })
    }
    #[cfg(not(feature = "ssr"))]
    {
        let _ = (challenge_id, credential_json);
        Err(ServerFnError::ServerError(
            "SSR feature not enabled".to_string(),
        ))
    }
}

// ----------------------------------------------------------------------------
// Client Views and Components
// ----------------------------------------------------------------------------

#[cfg(feature = "ssr")]
pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                <AutoReload options=options.clone() />
                <HydrationScripts options=options.clone() root="" />
                <MetaTags />
                <link rel="preconnect" href="https://fonts.googleapis.com" />
                <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="anonymous" />
                <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet" />
            </head>
            <body class="bg-[#0b0f19] font-['Outfit',sans-serif] text-slate-100 antialiased min-h-screen">
                <App />
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    let fallback = || view! { "Page not found." }.into_view();

    view! {
        <Stylesheet id="leptos" href="/pkg/web.css" />
        <Meta name="description" content="MaxPayout Web Dashboard" />
        <Title text="MaxPayout" />

        <Router>
            <main>
                <Routes fallback>
                    <Route path=path!("") view=HomePage />
                    <Route path=path!("/*any") view=NotFound />
                </Routes>
            </main>
        </Router>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    let (show_register, set_show_register) = signal(false);
    #[allow(unused_variables)]
    let (os_brand, set_os_brand) = signal("Device".to_string());

    Effect::new(move |_| {
        #[cfg(feature = "hydrate")]
        {
            if let Some(window) = web_sys::window() {
                if let Ok(ua) = window.navigator().user_agent() {
                    let ua_lower = ua.to_lowercase();
                    if ua_lower.contains("mac")
                        || ua_lower.contains("iphone")
                        || ua_lower.contains("ipad")
                        || ua_lower.contains("ipod")
                    {
                        set_os_brand.set("Apple".to_string());
                    } else if ua_lower.contains("win") {
                        set_os_brand.set("Windows".to_string());
                    } else if ua_lower.contains("android") {
                        set_os_brand.set("Android".to_string());
                    } else {
                        set_os_brand.set("Passkey".to_string());
                    }
                }
            }
        }
    });

    let biometric_btn_class = move || match os_brand.get().as_str() {
        "Apple" => {
            "w-full py-3 bg-[#111] hover:bg-black text-white font-semibold rounded-xl border border-zinc-800 hover:border-zinc-700 transition-all duration-150 flex items-center justify-center gap-2.5 text-sm disabled:opacity-50 shadow-lg shadow-black/20"
        }
        "Windows" => {
            "w-full py-3 bg-[#0c1f38] hover:bg-[#122b4d] text-[#00ebff] font-semibold rounded-xl border border-[#0078d4]/60 hover:border-[#0078d4] transition-all duration-150 flex items-center justify-center gap-2.5 text-sm disabled:opacity-50 shadow-lg shadow-[#0078d4]/10"
        }
        "Android" => {
            "w-full py-3 bg-[#0d2a1d] hover:bg-[#123d2a] text-[#3ddc84] font-semibold rounded-xl border border-[#3ddc84]/40 hover:border-[#3ddc84] transition-all duration-150 flex items-center justify-center gap-2.5 text-sm disabled:opacity-50 shadow-lg shadow-emerald-950/20"
        }
        _ => {
            "w-full py-3 bg-[#1e293b] hover:bg-[#334155] text-white font-semibold rounded-xl border border-[#334155] hover:border-slate-400 transition-all duration-150 flex items-center justify-center gap-2.5 text-sm disabled:opacity-50"
        }
    };

    let biometric_btn_text = move || {
        let action = if show_register.get() {
            "Sign Up"
        } else {
            "Log In"
        };
        match os_brand.get().as_str() {
            "Apple" => format!("{} with Apple Passkey", action),
            "Windows" => format!("{} with Windows Hello", action),
            "Android" => format!("{} with Android Biometrics", action),
            _ => format!("{} with Biometric Passkey", action),
        }
    };

    // ----------------------------------------------------------------------------
    // Routing/Token extraction from URL
    // ----------------------------------------------------------------------------
    let query_map = use_query_map();
    let login_trigger = ServerAction::<LoginViaMagicLink>::new();
    let (dashboard_data, set_dashboard_data) = signal(DashboardStatus::default());
    let (active_sessions, set_active_sessions) = signal(Vec::<SessionInfo>::new());

    // Magic Link Autologin Effect
    Effect::new(move |_| {
        let params = query_map.get();
        if let Some(token) = params.get("token") {
            // Trigger login
            login_trigger.dispatch(LoginViaMagicLink {
                token: token.clone(),
            });
            // Clean token from browser URL without refresh
            #[cfg(feature = "hydrate")]
            {
                if let Some(window) = web_sys::window() {
                    let _ = window.history().expect("history").replace_state_with_url(
                        &JsValue::NULL,
                        "",
                        Some("/"),
                    );
                }
            }
        }
    });

    // Refresh function for state
    let refresh_dashboard = move || {
        leptos::task::spawn_local(async move {
            if let Ok(data) = get_user_dashboard_status().await {
                set_dashboard_data.set(data.clone());
                if data.user.is_some() {
                    if let Ok(sessions) = get_active_sessions().await {
                        set_active_sessions.set(sessions);
                    }
                }
            }
        });
    };

    // Load initial dashboard state
    Effect::new(move |_| {
        refresh_dashboard();
    });

    // Handle Login Response
    Effect::new(move |_| {
        if let Some(Ok(user_info)) = login_trigger.value().get() {
            println!("Logged in successfully: {:?}", user_info);
            refresh_dashboard();
        }
    });

    // ----------------------------------------------------------------------------
    // Magic Link Actions
    // ----------------------------------------------------------------------------
    let request_magic_action = ServerAction::<RequestMagicLink>::new();
    let (email_input, set_email_input) = signal(String::new());
    let (username_input, set_username_input) = signal(String::new());

    let handle_magic_request = move |ev: leptos::web_sys::SubmitEvent| {
        ev.prevent_default();
        let email = email_input.get();
        if !email.is_empty() {
            let uname = if show_register.get() {
                Some(username_input.get())
            } else {
                None
            };
            request_magic_action.dispatch(RequestMagicLink {
                email,
                username: uname,
            });
        }
    };

    // ----------------------------------------------------------------------------
    // Password Authentication UI State Signals
    // ----------------------------------------------------------------------------
    let (active_tab, set_active_tab) = signal("password".to_string());
    let (password_input, set_password_input) = signal(String::new());
    let (show_local_links, set_show_local_links) = signal(false);
    let (passkey_fallback_suggested, set_passkey_fallback_suggested) = signal(false);
    let (password_auth_error, set_password_auth_error) = signal(Option::<String>::None);
    let (password_auth_loading, set_password_auth_loading) = signal(false);

    // ----------------------------------------------------------------------------
    // WebAuthn Client Handlers
    // ----------------------------------------------------------------------------
    let (biometric_error, set_biometric_error) = signal(Option::<String>::None);
    let (biometric_loading, set_biometric_loading) = signal(false);

    let handle_register_passkey = move || {
        set_biometric_loading.set(true);
        set_biometric_error.set(None);
        leptos::task::spawn_local(async move {
            match register_passkey_start().await {
                Ok(challenge_json) => {
                    #[cfg(feature = "hydrate")]
                    {
                        match registerPasskey(&challenge_json).await {
                            Ok(cred_js) => {
                                let cred_str = cred_js.as_string().unwrap();
                                match register_passkey_finish(cred_str).await {
                                    Ok(_) => {
                                        set_biometric_loading.set(false);
                                        refresh_dashboard();
                                    }
                                    Err(e) => {
                                        set_biometric_error.set(Some(e.to_string()));
                                        set_biometric_loading.set(false);
                                    }
                                }
                            }
                            Err(e) => {
                                let err_msg = e.as_string().unwrap_or_else(|| {
                                    "User cancelled biometric prompts".to_string()
                                });
                                set_biometric_error.set(Some(err_msg));
                                set_biometric_loading.set(false);
                            }
                        }
                    }
                    #[cfg(not(feature = "hydrate"))]
                    {
                        let _ = challenge_json;
                        set_biometric_loading.set(false);
                    }
                }
                Err(e) => {
                    set_biometric_error.set(Some(e.to_string()));
                    set_biometric_loading.set(false);
                }
            }
        });
    };

    let handle_login_passkey = move || {
        let email = email_input.get();
        set_biometric_loading.set(true);
        set_biometric_error.set(None);
        set_passkey_fallback_suggested.set(false);
        leptos::task::spawn_local(async move {
            let check_error = move |err_str: String| {
                if err_str.contains("has no passkeys") {
                    set_passkey_fallback_suggested.set(true);
                } else {
                    set_biometric_error.set(Some(err_str));
                }
            };

            match login_passkey_start(email).await {
                Ok(resp) => {
                    #[cfg(feature = "hydrate")]
                    {
                        match resp {
                            PasskeyStartResponse::Login {
                                challenge_id,
                                challenge_json,
                            } => match loginPasskey(&challenge_json).await {
                                Ok(cred_js) => {
                                    let cred_str = cred_js.as_string().unwrap();
                                    match login_passkey_finish(challenge_id, cred_str).await {
                                        Ok(_) => {
                                            set_biometric_loading.set(false);
                                            refresh_dashboard();
                                        }
                                        Err(e) => {
                                            check_error(e.to_string());
                                            set_biometric_loading.set(false);
                                        }
                                    }
                                }
                                Err(e) => {
                                    let err_msg = e.as_string().unwrap_or_else(|| {
                                        "Biometric verification cancelled".to_string()
                                    });
                                    check_error(err_msg);
                                    set_biometric_loading.set(false);
                                }
                            },
                            PasskeyStartResponse::Register {
                                challenge_id,
                                challenge_json,
                                email: _,
                            } => match registerPasskey(&challenge_json).await {
                                Ok(cred_js) => {
                                    let cred_str = cred_js.as_string().unwrap();
                                    match register_passkey_finish_signup(challenge_id, cred_str)
                                        .await
                                    {
                                        Ok(_) => {
                                            set_biometric_loading.set(false);
                                            refresh_dashboard();
                                        }
                                        Err(e) => {
                                            check_error(e.to_string());
                                            set_biometric_loading.set(false);
                                        }
                                    }
                                }
                                Err(e) => {
                                    let err_msg = e.as_string().unwrap_or_else(|| {
                                        "Biometric signup cancelled".to_string()
                                    });
                                    check_error(err_msg);
                                    set_biometric_loading.set(false);
                                }
                            },
                        }
                    }
                    #[cfg(not(feature = "hydrate"))]
                    {
                        let _ = resp;
                        set_biometric_loading.set(false);
                    }
                }
                Err(e) => {
                    check_error(e.to_string());
                    set_biometric_loading.set(false);
                }
            }
        });
    };

    // ----------------------------------------------------------------------------
    // Points progressions and Session revocations
    // ----------------------------------------------------------------------------
    let (award_pts_input, set_award_pts_input) = signal(5u32);
    let (award_loading, set_award_loading) = signal(false);

    let handle_award_points = move || {
        set_award_loading.set(true);
        leptos::task::spawn_local(async move {
            let pts = award_pts_input.get();
            if let Ok(res) = award_points(pts).await {
                println!("Award successful! Account progress: {:?}", res);
                refresh_dashboard();
            }
            set_award_loading.set(false);
        });
    };

    let handle_revoke_session = move |id: Uuid| {
        leptos::task::spawn_local(async move {
            let _ = revoke_session(id).await;
            refresh_dashboard();
        });
    };

    let handle_revoke_other_sessions = move || {
        leptos::task::spawn_local(async move {
            let _ = revoke_other_sessions().await;
            refresh_dashboard();
        });
    };

    let handle_logout = move || {
        leptos::task::spawn_local(async move {
            let _ = logout().await;
            refresh_dashboard();
        });
    };

    // ----------------------------------------------------------------------------
    // Password Authentication Handlers
    // ----------------------------------------------------------------------------

    // Fetch local testing feature flag value
    Effect::new(move |_| {
        leptos::task::spawn_local(async move {
            if let Ok(enabled) = check_local_testing_enabled().await {
                set_show_local_links.set(enabled);
            }
        });
    });

    let switch_tab = move |tab: String| {
        set_active_tab.set(tab);
        set_biometric_error.set(None);
        set_password_auth_error.set(None);
        set_passkey_fallback_suggested.set(false);
        request_magic_action.clear();
    };

    let handle_password_submit = move |ev: leptos::web_sys::SubmitEvent| {
        ev.prevent_default();
        let email = email_input.get();
        let password = password_input.get();
        let username = username_input.get();

        if email.is_empty() || password.is_empty() {
            return;
        }

        set_password_auth_loading.set(true);
        set_password_auth_error.set(None);

        leptos::task::spawn_local(async move {
            if show_register.get() {
                match register_with_password(email, username, password).await {
                    Ok(user_info) => {
                        println!("Registered and logged in with password: {:?}", user_info);
                        set_password_auth_loading.set(false);
                        refresh_dashboard();
                    }
                    Err(e) => {
                        set_password_auth_error.set(Some(e.to_string()));
                        set_password_auth_loading.set(false);
                    }
                }
            } else {
                match login_with_password(email, password).await {
                    Ok(user_info) => {
                        println!("Logged in with password: {:?}", user_info);
                        set_password_auth_loading.set(false);
                        refresh_dashboard();
                    }
                    Err(e) => {
                        set_password_auth_error.set(Some(e.to_string()));
                        set_password_auth_loading.set(false);
                    }
                }
            }
        });
    };

    // Helper to render tree slots
    let get_slot_username = move |idx: usize| {
        dashboard_data
            .get()
            .matrix
            .map(|m| {
                m.slots
                    .get(idx)
                    .map(|s| s.username.clone())
                    .unwrap_or_else(|| "Empty".to_string())
            })
            .unwrap_or_else(|| "Empty".to_string())
    };

    let is_slot_filled = move |idx: usize| {
        dashboard_data
            .get()
            .matrix
            .map(|m| {
                m.slots
                    .get(idx)
                    .map(|s| s.username != "Empty")
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    };

    let is_slot_user = move |idx: usize| {
        dashboard_data
            .get()
            .matrix
            .map(|m| m.slots.get(idx).map(|s| s.is_user).unwrap_or(false))
            .unwrap_or(false)
    };

    view! {
        <div class="max-w-6xl mx-auto px-4 py-8 space-y-8">
            // Global Header
            <header class="flex items-center justify-between border-b border-[#1e293b] pb-6">
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 bg-[#00d4aa] rounded-lg flex items-center justify-center shadow-lg shadow-[#00d4aa]/20">
                        <span class="text-[#0b0f19] font-extrabold text-xl">M</span>
                    </div>
                    <div>
                        <h1 class="text-2xl font-bold tracking-tight text-white">"MaxPayout"</h1>
                        <p class="text-xs text-slate-400">"Saga Orchestration & Biometrics Integration (MaxPayout 2.0)"</p>
                    </div>
                </div>

                <Show when=move || dashboard_data.get().user.is_some()>
                    <div class="flex items-center gap-4">
                        <div class="text-right hidden sm:block">
                            <p class="text-sm font-medium text-white">{move || dashboard_data.get().user.clone().unwrap().username}</p>
                            <p class="text-xs text-slate-400">{move || dashboard_data.get().user.clone().unwrap().email}</p>
                        </div>
                        <button
                            on:click=move |_| handle_logout()
                            class="px-4 py-2 text-xs font-semibold text-slate-300 hover:text-white bg-[#1e293b] hover:bg-[#334155] rounded-lg border border-[#334155] transition-all duration-150"
                        >
                            "Sign Out"
                        </button>
                    </div>
                </Show>
            </header>

            // LOGIN OR REGISTER CARD (when not logged in)
            <Show when=move || dashboard_data.get().user.is_none()>
                <div class="flex items-center justify-center py-12">
                    <div class="w-full max-w-md bg-[#111827]/80 backdrop-blur-xl border border-[#1f2937] rounded-2xl shadow-2xl p-8 space-y-6 relative overflow-hidden">
                        // Decorative glowing gradients
                        <div class="absolute -top-12 -right-12 w-32 h-32 bg-[#00d4aa]/10 rounded-full blur-2xl"></div>
                        <div class="absolute -bottom-12 -left-12 w-32 h-32 bg-teal-500/10 rounded-full blur-2xl"></div>

                        <div class="text-center space-y-2">
                            <h2 class="text-2xl font-bold text-white">
                                {move || if show_register.get() { "Create Account" } else { "Welcome Back" }}
                            </h2>
                            <p class="text-sm text-slate-400">
                                {move || if show_register.get() { "Choose your preferred secure registration method" } else { "Log in using password, magic link, or biometric passkeys" }}
                            </p>
                        </div>

                        // Modern Glassmorphic Tab Switcher
                        <div class="flex border border-[#1f2937] p-1 bg-[#0b0f19]/60 rounded-xl">
                            <button
                                type="button"
                                on:click=move |_| switch_tab("password".to_string())
                                class=move || {
                                    let base = "flex-1 py-2 text-xs font-semibold rounded-lg transition-all duration-150 flex items-center justify-center gap-1.5 ";
                                    if active_tab.get() == "password" {
                                        format!("{base} bg-[#1f2937] text-white shadow-md border border-[#334155]")
                                    } else {
                                        format!("{base} text-slate-400 hover:text-white hover:bg-white/5")
                                    }
                                }
                            >
                                <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                                </svg>
                                "Password"
                            </button>
                            <button
                                type="button"
                                on:click=move |_| switch_tab("magic".to_string())
                                class=move || {
                                    let base = "flex-1 py-2 text-xs font-semibold rounded-lg transition-all duration-150 flex items-center justify-center gap-1.5 ";
                                    if active_tab.get() == "magic" {
                                        format!("{base} bg-[#1f2937] text-white shadow-md border border-[#334155]")
                                    } else {
                                        format!("{base} text-slate-400 hover:text-white hover:bg-white/5")
                                    }
                                }
                            >
                                <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                                </svg>
                                "Magic Link"
                            </button>
                            <button
                                type="button"
                                on:click=move |_| switch_tab("passkey".to_string())
                                class=move || {
                                    let base = "flex-1 py-2 text-xs font-semibold rounded-lg transition-all duration-150 flex items-center justify-center gap-1.5 ";
                                    if active_tab.get() == "passkey" {
                                        format!("{base} bg-[#1f2937] text-white shadow-md border border-[#334155]")
                                    } else {
                                        format!("{base} text-slate-400 hover:text-white hover:bg-white/5")
                                    }
                                }
                            >
                                <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path d="M2 12a10 10 0 1 0 18.8-4.3" />
                                    <path d="M7 12a5 5 0 1 0 8.3-3.7" />
                                    <path d="M12 12a2 2 0 1 0 3.8-1" />
                                    <path d="M12 12v6" />
                                </svg>
                                "Passkeys"
                            </button>
                        </div>

                        // Conditional Tab Rendering
                        <Show when=move || active_tab.get() == "password">
                            <form on:submit=handle_password_submit class="space-y-4">
                                <div class="space-y-1">
                                    <label class="text-xs font-medium text-slate-400 uppercase tracking-wider">"Email Address"</label>
                                    <input
                                        type="email"
                                        required
                                        placeholder="name@example.com"
                                        on:input=move |ev| set_email_input.set(event_target_value(&ev))
                                        prop:value=email_input
                                        class="w-full px-4 py-3 bg-[#0f172a] border border-[#1f2937] focus:border-[#00d4aa] rounded-xl text-white outline-none transition-all duration-150 text-sm focus:ring-1 focus:ring-[#00d4aa]"
                                    />
                                </div>

                                <Show when=move || show_register.get()>
                                    <div class="space-y-1 animate-fadeIn">
                                        <label class="text-xs font-medium text-slate-400 uppercase tracking-wider">"Display Username"</label>
                                        <input
                                            type="text"
                                            required
                                            placeholder="Alice"
                                            on:input=move |ev| set_username_input.set(event_target_value(&ev))
                                            prop:value=username_input
                                            class="w-full px-4 py-3 bg-[#0f172a] border border-[#1f2937] focus:border-[#00d4aa] rounded-xl text-white outline-none transition-all duration-150 text-sm focus:ring-1 focus:ring-[#00d4aa]"
                                        />
                                    </div>
                                </Show>

                                <div class="space-y-1">
                                    <label class="text-xs font-medium text-slate-400 uppercase tracking-wider">"Password"</label>
                                    <input
                                        type="password"
                                        required
                                        placeholder="••••••••"
                                        on:input=move |ev| set_password_input.set(event_target_value(&ev))
                                        prop:value=password_input
                                        class="w-full px-4 py-3 bg-[#0f172a] border border-[#1f2937] focus:border-[#00d4aa] rounded-xl text-white outline-none transition-all duration-150 text-sm focus:ring-1 focus:ring-[#00d4aa]"
                                    />
                                </div>

                                <button
                                    type="submit"
                                    disabled=move || password_auth_loading.get()
                                    class="w-full py-3 bg-gradient-to-r from-[#00d4aa] to-teal-500 hover:from-[#00c29b] hover:to-teal-600 text-[#0b0f19] font-semibold rounded-xl shadow-lg shadow-[#00d4aa]/10 hover:shadow-[#00d4aa]/20 transform hover:-translate-y-0.5 active:translate-y-0 transition-all duration-150 text-sm flex items-center justify-center gap-2"
                                >
                                    <Show when=move || password_auth_loading.get()>
                                        <div class="w-3.5 h-3.5 border-2 border-transparent border-t-[#0b0f19] rounded-full animate-spin"></div>
                                    </Show>
                                    {move || if show_register.get() { "Create Account & Sign In" } else { "Log In with Password" }}
                                </button>

                                <div class="text-center pt-2">
                                    <button
                                        type="button"
                                        on:click=move |_| {
                                            set_show_register.update(|v| *v = !*v);
                                            set_password_auth_error.set(None);
                                        }
                                        class="text-xs text-slate-400 hover:text-[#00d4aa] transition-colors"
                                    >
                                        {move || if show_register.get() { "Already have an account? Log In" } else { "Don't have an account? Sign Up" }}
                                    </button>
                                </div>
                            </form>
                        </Show>

                        <Show when=move || active_tab.get() == "magic">
                            <form on:submit=handle_magic_request class="space-y-4">
                                <div class="space-y-1">
                                    <label class="text-xs font-medium text-slate-400 uppercase tracking-wider">"Email Address"</label>
                                    <input
                                        type="email"
                                        required
                                        placeholder="name@example.com"
                                        on:input=move |ev| set_email_input.set(event_target_value(&ev))
                                        prop:value=email_input
                                        class="w-full px-4 py-3 bg-[#0f172a] border border-[#1f2937] focus:border-[#00d4aa] rounded-xl text-white outline-none transition-all duration-150 text-sm focus:ring-1 focus:ring-[#00d4aa]"
                                    />
                                </div>

                                <Show when=move || show_register.get()>
                                    <div class="space-y-1 animate-fadeIn">
                                        <label class="text-xs font-medium text-slate-400 uppercase tracking-wider">"Display Username"</label>
                                        <input
                                            type="text"
                                            required
                                            placeholder="Alice"
                                            on:input=move |ev| set_username_input.set(event_target_value(&ev))
                                            prop:value=username_input
                                            class="w-full px-4 py-3 bg-[#0f172a] border border-[#1f2937] focus:border-[#00d4aa] rounded-xl text-white outline-none transition-all duration-150 text-sm focus:ring-1 focus:ring-[#00d4aa]"
                                        />
                                    </div>
                                </Show>

                                <button
                                    type="submit"
                                    class="w-full py-3 bg-gradient-to-r from-[#00d4aa] to-teal-500 hover:from-[#00c29b] hover:to-teal-600 text-[#0b0f19] font-semibold rounded-xl shadow-lg shadow-[#00d4aa]/10 hover:shadow-[#00d4aa]/20 transform hover:-translate-y-0.5 active:translate-y-0 transition-all duration-150 text-sm flex items-center justify-center gap-2"
                                >
                                    <Show when=move || request_magic_action.pending().get()>
                                        <div class="w-3.5 h-3.5 border-2 border-transparent border-t-[#0b0f19] rounded-full animate-spin"></div>
                                    </Show>
                                    {move || if show_register.get() { "Send Registration Link" } else { "Send Magic Login Link" }}
                                </button>

                                <div class="text-center pt-2">
                                    <button
                                        type="button"
                                        on:click=move |_| {
                                            set_show_register.update(|v| *v = !*v);
                                            request_magic_action.clear();
                                        }
                                        class="text-xs text-slate-400 hover:text-[#00d4aa] transition-colors"
                                    >
                                        {move || if show_register.get() { "Already have an account? Log In" } else { "Don't have an account? Sign Up" }}
                                    </button>
                                </div>
                            </form>
                        </Show>

                        <Show when=move || active_tab.get() == "passkey">
                            <div class="space-y-4">
                                <div class="space-y-1">
                                    <label class="text-xs font-medium text-slate-400 uppercase tracking-wider">"Email Address (Optional)"</label>
                                    <input
                                        type="email"
                                        placeholder="name@example.com"
                                        on:input=move |ev| set_email_input.set(event_target_value(&ev))
                                        prop:value=email_input
                                        class="w-full px-4 py-3 bg-[#0f172a] border border-[#1f2937] focus:border-[#00d4aa] rounded-xl text-white outline-none transition-all duration-150 text-sm focus:ring-1 focus:ring-[#00d4aa]"
                                    />
                                    <p class="text-[10px] text-slate-500">"Leave empty if you have logged in on this device before."</p>
                                </div>

                                <button
                                    type="button"
                                    on:click=move |_| handle_login_passkey()
                                    disabled=move || biometric_loading.get()
                                    class=biometric_btn_class
                                >
                                    <Show when=move || biometric_loading.get()>
                                        <div class="w-3.5 h-3.5 border-2 border-transparent border-t-current rounded-full animate-spin mr-2"></div>
                                    </Show>
                                    <Show when=move || os_brand.get() == "Apple">
                                        <svg class="w-4 h-4 fill-current mr-2" viewBox="0 0 24 24">
                                            <path d="M12.152 6.896c-.948 0-2.415-1.078-3.96-1.04-2.04.027-3.91 1.183-4.961 3.014-2.117 3.675-.546 9.103 1.519 12.09 1.013 1.454 2.208 3.09 3.792 3.039 1.52-.065 2.09-.987 3.935-.987 1.831 0 2.35.987 3.96.948 1.637-.026 2.676-1.48 3.676-2.948 1.156-1.688 1.636-3.325 1.662-3.415-.039-.013-3.182-1.221-3.22-4.857-.026-3.04 2.48-4.494 2.597-4.559-1.429-2.09-3.623-2.324-4.39-2.376-2-.156-3.675 1.09-4.61 1.09zM15.53 3.83c.843-1.012 1.4-2.427 1.245-3.83-1.207.052-2.662.805-3.532 1.818-.78.896-1.454 2.338-1.273 3.714 1.338.104 2.715-.688 3.559-1.701"/>
                                        </svg>
                                    </Show>
                                    <Show when=move || os_brand.get() == "Windows">
                                        <svg class="w-4 h-4 fill-current mr-2" viewBox="0 0 24 24">
                                            <path d="M0 0h11v11H0zm13 0h11v11H13zM0 13h11v11H0zm13 0h11v11H13z"/>
                                        </svg>
                                    </Show>
                                    <Show when=move || os_brand.get() != "Apple" && os_brand.get() != "Windows">
                                        <svg class="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                            <path d="M2 12a10 10 0 1 0 18.8-4.3" />
                                            <path d="M7 12a5 5 0 1 0 8.3-3.7" />
                                            <path d="M12 12a2 2 0 1 0 3.8-1" />
                                            <path d="M12 12v6" />
                                        </svg>
                                    </Show>
                                    {biometric_btn_text}
                                </button>
                            </div>
                        </Show>

                        // Status & Error Messages (unified for all tabs)
                        <div class="space-y-3 pt-2">
                            // Magic Link Response
                            <Show when=move || show_local_links.get() && request_magic_action.value().get().is_some()>
                                <div class="p-3 bg-teal-950/50 border border-teal-800 text-teal-400 rounded-xl text-xs text-left leading-relaxed animate-fadeIn">
                                    <p class="font-bold mb-1">"Link Generated!"</p>
                                    "For local testing, click: "
                                    <a
                                        href=move || format!("/?token={}", request_magic_action.value().get().unwrap().unwrap())
                                        class="underline hover:text-white break-all font-mono"
                                    >
                                        {move || {
                                            let token = request_magic_action.value().get().unwrap().unwrap();
                                            #[cfg(feature = "hydrate")]
                                            let origin = web_sys::window()
                                                .and_then(|w| w.location().origin().ok())
                                                .unwrap_or_else(|| "http://localhost:4000".to_string());
                                            #[cfg(not(feature = "hydrate"))]
                                            let origin = "http://localhost:4000".to_string();
                                            format!("{}/?token={}", origin, token)
                                        }}
                                    </a>
                                </div>
                            </Show>

                            // Password Error
                            <Show when=move || password_auth_error.get().is_some() && active_tab.get() == "password">
                                <div class="p-3 bg-red-950/30 border border-red-900 text-red-400 rounded-xl text-xs text-left leading-relaxed">
                                    {move || password_auth_error.get().unwrap()}
                                </div>
                            </Show>

                            // Biometric Error
                            <Show when=move || biometric_error.get().is_some() && active_tab.get() == "passkey">
                                <div class="p-3 bg-red-950/30 border border-red-900 text-red-400 rounded-xl text-xs text-left leading-relaxed">
                                    {move || biometric_error.get().unwrap()}
                                </div>
                            </Show>

                            // Biometric Fallback Suggestion Block
                            <Show when=move || passkey_fallback_suggested.get() && active_tab.get() == "passkey">
                                <div class="p-4 bg-amber-950/40 border border-amber-800 rounded-xl text-left space-y-3 animate-fadeIn">
                                    <div class="flex gap-2.5 items-start">
                                        <svg class="w-5 h-5 text-amber-400 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                        </svg>
                                        <div>
                                            <p class="text-xs font-bold text-amber-200">"No Passkeys Enrolled"</p>
                                            <p class="text-xs text-amber-400 mt-0.5 leading-relaxed">
                                                "This account is registered but has no passkeys on this device yet. Log in via Magic Link first, then register your device in Settings."
                                            </p>
                                        </div>
                                    </div>
                                    <button
                                        type="button"
                                        on:click=move |_| {
                                            switch_tab("magic".to_string());
                                        }
                                        class="w-full py-2 bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold rounded-lg transition-all duration-150 flex items-center justify-center gap-1 shadow-md shadow-amber-950/30"
                                    >
                                        "Switch to Magic Link Login"
                                        <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                            <path stroke-linecap="round" stroke-linejoin="round" d="M14 5l7 7m0 0l-7 7m7-7H3" />
                                        </svg>
                                    </button>
                                </div>
                            </Show>
                        </div>
                    </div>
                </div>
            </Show>

            // DASHBOARD WRAPPER (when logged in)
            <Show when=move || dashboard_data.get().user.is_some()>
                <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                    // Left Panel: Cards & Progression Actions
                    <div class="lg:col-span-1 space-y-8">
                        // Profile & Referral Card
                        <div class="bg-[#111827] border border-[#1f2937] rounded-2xl p-6 space-y-4">
                            <h3 class="text-lg font-bold text-white">"Card Progress & Referral Status"</h3>

                            <div class="space-y-3">
                                <div>
                                    <label class="text-[10px] uppercase tracking-wider text-slate-400">"Account ID"</label>
                                    <p class="text-xs text-slate-300 font-mono select-all truncate">
                                        {move || dashboard_data.get().flushline.map(|fl| fl.id.to_string()).unwrap_or_default()}
                                    </p>
                                </div>
                                <div class="grid grid-cols-2 gap-4">
                                    <div>
                                        <label class="text-[10px] uppercase tracking-wider text-slate-400">"Current Card tier"</label>
                                        <p class="text-sm font-semibold text-[#00d4aa]">
                                            {move || dashboard_data.get().flushline.map(|fl| fl.tier).unwrap_or_else(|| "Ten".to_string())}
                                        </p>
                                    </div>
                                    <div>
                                        <label class="text-[10px] uppercase tracking-wider text-slate-400">"Graduated State"</label>
                                        <p class="text-sm font-semibold text-slate-300">
                                            {move || if dashboard_data.get().flushline.map(|fl| fl.graduated).unwrap_or(false) { "Yes (Cycled)" } else { "No" }}
                                        </p>
                                    </div>
                                </div>
                                <div>
                                    <label class="text-[10px] uppercase tracking-wider text-slate-400">"Active Sponsor"</label>
                                    <p class="text-xs font-mono text-slate-300 truncate">
                                        {move || dashboard_data.get().sponsor_id.map(|id| id.to_string()).unwrap_or_else(|| "None".to_string())}
                                    </p>
                                </div>
                            </div>

                            // Set Referral Cookie Button (Simulator)
                            <div class="pt-4 border-t border-[#1f2937] space-y-2">
                                <p class="text-[11px] text-slate-400">"Set referral sponsor cookie to simulate joining someone:"</p>
                                <button
                                    on:click=move |_| {
                                        let test_sponsor = Uuid::parse_str("01900000-0000-0000-0000-000000000001").unwrap();
                                        leptos::task::spawn_local(async move {
                                            let _ = set_referral_cookie_ssr(test_sponsor).await;
                                            refresh_dashboard();
                                        });
                                    }
                                    class="w-full py-2 bg-[#1e293b] hover:bg-[#334155] border border-[#334155] hover:border-[#00d4aa] text-xs text-white rounded-lg transition-all duration-150"
                                >
                                    "Simulate Referral (Set Sponsor Cookie)"
                                </button>
                            </div>
                        </div>

                        // Points Award simulator
                        <div class="bg-[#111827] border border-[#1f2937] rounded-2xl p-6 space-y-4">
                            <div class="flex items-center justify-between">
                                <h3 class="text-lg font-bold text-white">"Flushline Simulator"</h3>
                                <span class="text-xs bg-[#1e293b] text-slate-300 px-2 py-0.5 rounded-full border border-[#334155]">
                                    {move || dashboard_data.get().flushline.map(|fl| fl.cycle_count).unwrap_or(0)} " cycles"
                                </span>
                            </div>

                            <div class="relative pt-1">
                                <div class="flex mb-2 items-center justify-between text-xs">
                                    <span class="font-semibold text-slate-400">"Points Progress"</span>
                                    <span class="text-[#00d4aa] font-bold">
                                        {move || dashboard_data.get().flushline.map(|fl| fl.current_pts).unwrap_or(0)} "/15"
                                    </span>
                                </div>
                                <div class="overflow-hidden h-2.5 text-xs flex rounded-full bg-[#1e293b]">
                                    <div
                                        style:width=move || {
                                            let pts = dashboard_data.get().flushline.map(|fl| fl.current_pts).unwrap_or(0);
                                            let pct = ((pts as f32) / 15.0 * 100.0).min(100.0);
                                            format!("{}%", pct)
                                        }
                                        class="shadow-none flex flex-col text-center whitespace-nowrap text-white justify-center bg-gradient-to-r from-teal-500 to-[#00d4aa] transition-all duration-500 rounded-full"
                                    ></div>
                                </div>
                            </div>

                            <div class="space-y-3 pt-2">
                                <div class="flex items-center gap-4">
                                    <input
                                        type="number"
                                        min="1"
                                        max="50"
                                        on:input=move |ev| {
                                            if let Ok(val) = event_target_value(&ev).parse::<u32>() {
                                                set_award_pts_input.set(val);
                                            }
                                        }
                                        prop:value=award_pts_input
                                        class="w-20 px-3 py-2 bg-[#0f172a] border border-[#1f2937] focus:border-[#00d4aa] rounded-lg text-white text-center text-sm outline-none"
                                    />
                                    <button
                                        on:click=move |_| handle_award_points()
                                        disabled=move || award_loading.get()
                                        class="flex-1 py-2 bg-[#00d4aa] hover:bg-[#00c29b] text-[#0b0f19] font-semibold text-sm rounded-lg transition-all duration-150 flex items-center justify-center gap-1"
                                    >
                                        <Show when=move || award_loading.get()>
                                            <div class="w-3.5 h-3.5 border-2 border-transparent border-t-[#0b0f19] rounded-full animate-spin"></div>
                                        </Show>
                                        "Award Progress Points"
                                    </button>
                                </div>
                                <p class="text-[10px] text-slate-400">
                                    "When points reach 15, the account graduates. If a matrix cycle also occurs, the Saga immediately spawns a Free account."
                                </p>
                            </div>
                        </div>

                        // Passkey Enrollment
                        <div class="bg-[#111827] border border-[#1f2937] rounded-2xl p-6 space-y-4">
                            <h3 class="text-lg font-bold text-white">"Biometric Credentials"</h3>
                            <p class="text-xs text-slate-400 leading-relaxed">
                                "Register your Apple Touch ID, Face ID, or Windows Hello biometrics to log in securely next time without needing email link lookups."
                            </p>

                            <Show
                                when=move || {
                                    dashboard_data.get().user.as_ref().map(|u| u.has_passkey).unwrap_or(false)
                                }
                                fallback=move || view! {
                                    <button
                                        on:click=move |_| handle_register_passkey()
                                        disabled=move || biometric_loading.get()
                                        class="w-full py-2 bg-gradient-to-r from-teal-500 to-[#00d4aa] text-[#0b0f19] font-bold text-xs rounded-lg shadow-md shadow-[#00d4aa]/10 hover:shadow-[#00d4aa]/20 transition-all duration-150 flex items-center justify-center gap-1"
                                    >
                                        <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                                            <path d="M12 2c5.522 0 10 4.477 10 10s-4.478 10-10 10S2 17.523 2 12 6.478 2 12 2zm1 10h3v-2h-3V7h-2v3H8v2h3v3h2v-3z"/>
                                        </svg>
                                        "Enroll Biometric Passkey"
                                    </button>
                                }
                            >
                                <div class="p-4 bg-emerald-950/40 border border-emerald-800 rounded-xl text-left space-y-3 animate-fadeIn">
                                    <div class="flex gap-2.5 items-center text-emerald-400">
                                        <svg class="w-5 h-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                            <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                        </svg>
                                        <div>
                                            <p class="text-xs font-bold text-emerald-200">"Biometric Passkey Active"</p>
                                            <p class="text-[10px] text-emerald-400 mt-0.5 leading-relaxed">
                                                "Your account is secured with Touch ID, Face ID, or Windows Hello biometrics."
                                            </p>
                                        </div>
                                    </div>
                                    <button
                                        on:click=move |_| handle_register_passkey()
                                        disabled=move || biometric_loading.get()
                                        class="w-full py-1.5 bg-emerald-900/30 hover:bg-emerald-900/50 border border-emerald-700/50 hover:border-emerald-600 text-emerald-200 font-semibold text-[10px] rounded-lg transition-all duration-150 flex items-center justify-center gap-1"
                                    >
                                        <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                            <path d="M2 12a10 10 0 1 0 18.8-4.3" />
                                            <path d="M7 12a5 5 0 1 0 8.3-3.7" />
                                            <path d="M12 12a2 2 0 1 0 3.8-1" />
                                            <path d="M12 12v6" />
                                        </svg>
                                        "Register Additional Device"
                                    </button>
                                </div>
                            </Show>

                            <Show when=move || biometric_error.get().is_some()>
                                <p class="text-xs text-red-400 bg-red-950/30 p-2 border border-red-900 rounded-lg">
                                    {move || biometric_error.get().unwrap()}
                                </p>
                            </Show>
                        </div>
                    </div>

                    // Center & Right Panel: Matrix visualizer and active sessions
                    <div class="lg:col-span-2 space-y-8">
                        // Matrix Tree Card
                        <div class="bg-[#111827] border border-[#1f2937] rounded-2xl p-6 space-y-6">
                            <div class="flex items-center justify-between border-b border-[#1f2937] pb-4">
                                <div>
                                    <h3 class="text-lg font-bold text-white">"Matrix Binary tree Visualizer"</h3>
                                    <p class="text-xs text-slate-400">"Active forced matrix tree (Slots 1 to 7)"</p>
                                </div>
                                <span class="text-xs bg-emerald-950 text-emerald-400 border border-emerald-800 px-3 py-1 rounded-full">
                                    {move || dashboard_data.get().matrix.map(|m| m.status).unwrap_or_else(|| "Filling".to_string())}
                                </span>
                            </div>

                            // Render Matrix Nodes
                            <div class="flex flex-col items-center py-6 space-y-8 relative">
                                // Node 1 (Root)
                                <div class="relative z-10 flex flex-col items-center">
                                    <div class={move || {
                                        let border = if is_slot_user(0) { "border-[#00d4aa] ring-2 ring-[#00d4aa]/20" } else { "border-slate-600" };
                                        format!("w-16 h-16 rounded-full bg-[#1e293b] border-2 {} flex items-center justify-center font-bold text-sm text-white shadow-lg", border)
                                    }}>
                                        {move || get_slot_username(0).chars().take(2).collect::<String>().to_uppercase()}
                                    </div>
                                    <span class="text-xs text-white font-medium mt-1">{move || get_slot_username(0)}</span>
                                    <span class="text-[9px] text-slate-400 uppercase tracking-widest">"Slot 1 (Root)"</span>
                                </div>

                                // Level 2 (Left & Right children)
                                <div class="flex justify-around w-full max-w-sm relative">
                                    // Connecting lines to Level 2
                                    <div class="absolute -top-8 left-1/4 right-1/4 h-8 border-t-2 border-dashed border-slate-700"></div>
                                    <div class="absolute -top-8 left-1/2 w-0.5 h-8 border-l-2 border-dashed border-slate-700"></div>

                                    // Left Child
                                    <div class="flex flex-col items-center relative z-10">
                                        <div class={move || {
                                            let border = if is_slot_user(1) { "border-[#00d4aa] ring-2 ring-[#00d4aa]/20" } else if is_slot_filled(1) { "border-slate-500" } else { "border-slate-800 border-dashed" };
                                            format!("w-14 h-14 rounded-full bg-[#1e293b] border-2 {} flex items-center justify-center font-bold text-xs text-white", border)
                                        }}>
                                            {move || get_slot_username(1).chars().take(2).collect::<String>().to_uppercase()}
                                        </div>
                                        <span class="text-xs text-slate-200 mt-1">{move || get_slot_username(1)}</span>
                                        <span class="text-[9px] text-slate-500 uppercase tracking-widest">"Slot 2"</span>
                                    </div>

                                    // Right Child
                                    <div class="flex flex-col items-center relative z-10">
                                        <div class={move || {
                                            let border = if is_slot_user(2) { "border-[#00d4aa] ring-2 ring-[#00d4aa]/20" } else if is_slot_filled(2) { "border-slate-500" } else { "border-slate-800 border-dashed" };
                                            format!("w-14 h-14 rounded-full bg-[#1e293b] border-2 {} flex items-center justify-center font-bold text-xs text-white", border)
                                        }}>
                                            {move || get_slot_username(2).chars().take(2).collect::<String>().to_uppercase()}
                                        </div>
                                        <span class="text-xs text-slate-200 mt-1">{move || get_slot_username(2)}</span>
                                        <span class="text-[9px] text-slate-500 uppercase tracking-widest">"Slot 3"</span>
                                    </div>
                                </div>

                                // Level 3 (Leaf nodes 4, 5, 6, 7)
                                <div class="flex justify-between w-full max-w-lg relative">
                                    // Connecting lines to Level 3
                                    <div class="absolute -top-8 left-[12%] right-[12%] h-8 border-t border-dashed border-slate-800"></div>

                                    // Slot 4
                                    <div class="flex flex-col items-center relative z-10">
                                        <div class={move || {
                                            let border = if is_slot_user(3) { "border-[#00d4aa] ring-2 ring-[#00d4aa]/20" } else if is_slot_filled(3) { "border-slate-500" } else { "border-slate-800 border-dashed" };
                                            format!("w-12 h-12 rounded-full bg-[#1e293b] border {} flex items-center justify-center font-bold text-[10px] text-white", border)
                                        }}>
                                            {move || get_slot_username(3).chars().take(2).collect::<String>().to_uppercase()}
                                        </div>
                                        <span class="text-[11px] text-slate-300 mt-1">{move || get_slot_username(3)}</span>
                                        <span class="text-[8px] text-slate-500 uppercase">"Slot 4"</span>
                                    </div>

                                    // Slot 5
                                    <div class="flex flex-col items-center relative z-10">
                                        <div class={move || {
                                            let border = if is_slot_user(4) { "border-[#00d4aa] ring-2 ring-[#00d4aa]/20" } else if is_slot_filled(4) { "border-slate-500" } else { "border-slate-800 border-dashed" };
                                            format!("w-12 h-12 rounded-full bg-[#1e293b] border {} flex items-center justify-center font-bold text-[10px] text-white", border)
                                        }}>
                                            {move || get_slot_username(4).chars().take(2).collect::<String>().to_uppercase()}
                                        </div>
                                        <span class="text-[11px] text-slate-300 mt-1">{move || get_slot_username(4)}</span>
                                        <span class="text-[8px] text-slate-500 uppercase">"Slot 5"</span>
                                    </div>

                                    // Slot 6
                                    <div class="flex flex-col items-center relative z-10">
                                        <div class={move || {
                                            let border = if is_slot_user(5) { "border-[#00d4aa] ring-2 ring-[#00d4aa]/20" } else if is_slot_filled(5) { "border-slate-500" } else { "border-slate-800 border-dashed" };
                                            format!("w-12 h-12 rounded-full bg-[#1e293b] border {} flex items-center justify-center font-bold text-[10px] text-white", border)
                                        }}>
                                            {move || get_slot_username(5).chars().take(2).collect::<String>().to_uppercase()}
                                        </div>
                                        <span class="text-[11px] text-slate-300 mt-1">{move || get_slot_username(5)}</span>
                                        <span class="text-[8px] text-slate-500 uppercase">"Slot 6"</span>
                                    </div>

                                    // Slot 7
                                    <div class="flex flex-col items-center relative z-10">
                                        <div class={move || {
                                            let border = if is_slot_user(6) { "border-[#00d4aa] ring-2 ring-[#00d4aa]/20" } else if is_slot_filled(6) { "border-slate-500" } else { "border-slate-800 border-dashed" };
                                            format!("w-12 h-12 rounded-full bg-[#1e293b] border {} flex items-center justify-center font-bold text-[10px] text-white", border)
                                        }}>
                                            {move || get_slot_username(6).chars().take(2).collect::<String>().to_uppercase()}
                                        </div>
                                        <span class="text-[11px] text-slate-300 mt-1">{move || get_slot_username(6)}</span>
                                        <span class="text-[8px] text-slate-500 uppercase">"Slot 7"</span>
                                    </div>
                                </div>
                            </div>
                        </div>

                        // Logged-in Devices and active sessions
                        <div class="bg-[#111827] border border-[#1f2937] rounded-2xl p-6 space-y-4">
                            <div class="flex items-center justify-between border-b border-[#1f2937] pb-4">
                                <div>
                                    <h3 class="text-lg font-bold text-white">"Active Logged Sessions"</h3>
                                    <p class="text-xs text-slate-400">"Monitor and revoke session tokens across your devices"</p>
                                </div>
                                <button
                                    on:click=move |_| handle_revoke_other_sessions()
                                    class="px-3 py-1.5 text-xs font-semibold text-red-400 hover:text-white bg-red-950/20 hover:bg-red-900 border border-red-900/50 rounded-lg transition-all duration-150"
                                >
                                    "Revoke Other Sessions"
                                </button>
                            </div>

                            <div class="overflow-x-auto">
                                <table class="w-full text-left text-xs">
                                    <thead>
                                        <tr class="border-b border-[#1f2937] text-slate-400">
                                            <th class="py-3 px-2 font-medium uppercase">"IP Address"</th>
                                            <th class="py-3 px-2 font-medium uppercase">"Client/User Agent"</th>
                                            <th class="py-3 px-2 font-medium uppercase">"Last Active"</th>
                                            <th class="py-3 px-2 text-right">"Action"</th>
                                        </tr>
                                    </thead>
                                    <tbody class="divide-y divide-[#1f2937]/50 text-slate-300">
                                        <For
                                            each=move || active_sessions.get()
                                            key=|s| s.id
                                            let:session
                                        >
                                            <tr>
                                                <td class="py-4 px-2 font-mono">{session.ip_address.clone().unwrap_or_else(|| "127.0.0.1".to_string())}</td>
                                                <td class="py-4 px-2 truncate max-w-[200px]" title=session.user_agent.clone()>
                                                    {session.user_agent.clone().unwrap_or_else(|| "Unknown browser".to_string())}
                                                </td>
                                                <td class="py-4 px-2">{session.last_active_at[11..19].to_string()}</td>
                                                <td class="py-4 px-2 text-right">
                                                    <Show
                                                        when=move || !session.is_current
                                                        fallback=|| view! { <span class="text-teal-400 font-semibold px-2 py-0.5 bg-teal-950/30 rounded border border-teal-900">"Current"</span> }
                                                    >
                                                        <button
                                                            on:click=move |_| handle_revoke_session(session.id)
                                                            class="text-red-400 hover:text-red-300 hover:underline"
                                                        >
                                                            "Revoke"
                                                        </button>
                                                    </Show>
                                                </td>
                                            </tr>
                                        </For>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </Show>
        </div>
    }
}

#[component]
fn NotFound() -> impl IntoView {
    #[cfg(feature = "ssr")]
    {
        if let Some(resp) = use_context::<leptos_wasi::response::ResponseOptions>() {
            resp.set_status(leptos_wasi::prelude::StatusCode::NOT_FOUND);
        }
    }

    view! {
        <div class="min-h-[70vh] flex flex-col items-center justify-center space-y-4">
            <h1 class="text-6xl font-black text-[#00d4aa]">"404"</h1>
            <h2 class="text-2xl font-bold text-white">"Endpoint not found"</h2>
            <a href="/" class="px-6 py-3 bg-[#1e293b] hover:bg-[#334155] rounded-xl border border-[#334155] text-sm text-white transition-all">
                "Back to Dashboard"
            </a>
        </div>
    }
}
