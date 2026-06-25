use leptos::prelude::*;
use leptos_meta::*;
use leptos_router::components::{Route, Router, Routes};
use leptos_router::hooks::use_query_map;
use leptos_router::path;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[cfg(feature = "ssr")]
use chrono::Utc as ChronoUtc;

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
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub is_whitelisted: bool,
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
    #[serde(default)]
    pub account_id: Option<Uuid>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MatrixInfo {
    pub id: Uuid,
    pub status: String,
    pub slots: Vec<MatrixSlotInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ReferralInfo {
    pub account_id: Uuid,
    pub username: String,
    pub tier: String,
    pub registered_at: String,
    pub active: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct CycleOption {
    pub cycle_num: u32,
    pub label: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AccountProgressInfo {
    pub id: Uuid,
    pub label: String,
    pub tier: String,
    pub current_pts: i32,
    pub cycle_count: i32,
    pub graduated: bool,
    pub queue_position: i32,
    pub queue_total: i32,
    pub is_pot_qualified: bool,
    pub tier_pts: i32,
    pub tier_threshold: i32,
    #[serde(default)]
    pub matrix_cycles: i32,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct AccountQueueInfo {
    pub account_id: Uuid,
    pub username: String,
    pub cycle_count: i32,
    pub last_cycle_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct GraduationEvent {
    pub id: Uuid,
    pub account_id: Uuid,
    pub username: String,
    pub tier: String,
    pub cycle_count: i32,
    pub timestamp: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PotBonusConfig {
    pub total_pot_pool: f64,
    pub selective_rule: String, // "SoloWinner" or "Top5"
    pub selective_min_shares: i32, // e.g. 2 cycles (30 pts)
}

impl Default for PotBonusConfig {
    fn default() -> Self {
        Self {
            total_pot_pool: 1000.0,
            selective_rule: "SoloWinner".to_string(),
            selective_min_shares: 2, // 2 cycles (30 pts)
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct TierQueueInfo {
    pub tier_name: String,
    pub top_card_owner: Option<String>,
    pub count: i32,
    pub top_50: Vec<AccountQueueInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DashboardStatus {
    pub user: Option<UserInfo>,
    pub flushline: Option<FlushlineInfo>,
    pub matrix: Option<MatrixInfo>,
    pub sponsor_id: Option<Uuid>,
    pub total_earnings: f64,
    pub total_payouts: f64,
    pub referrals_count: i32,
    pub pot_bonus_amount: f64,
    pub referrals: Vec<ReferralInfo>,
    pub user_device_is_whitelisted: bool,
    pub accounts: Vec<AccountProgressInfo>,
    
    // Pot Bonus Mechanics & Diagnostical Fields
    pub pot_bonus_config: PotBonusConfig,
    pub tier_queues: Vec<TierQueueInfo>,
    pub graduation_events: Vec<GraduationEvent>,
    pub total_system_shares: i32,
    pub user_total_shares: i32,
    pub user_shared_payout: f64,
    pub user_selective_payout: f64,
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
        use http_body_util::BodyExt;
        use rand::{Rng, distributions::Alphanumeric};

        ssr_helpers::check_rate_limit()?;

        let email = email.trim().to_lowercase();
        if email.is_empty() {
            return Err(ServerFnError::ServerError(
                "Email cannot be empty".to_string(),
            ));
        }

        let state_store = get_state();
        let token = {
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
                    email: email.clone(),
                    expires_at,
                    used: false,
                },
            );

            save_state(&state);
            token
        };

        let parts = use_context::<http::request::Parts>();
        let host = parts
            .as_ref()
            .and_then(|p| p.headers.get(http::header::HOST))
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost:4000");

        if let Ok(api_key) = std::env::var("RESEND_API_KEY") {
            if !api_key.trim().is_empty() {
                let sender = std::env::var("RESEND_SENDER")
                    .unwrap_or_else(|_| "onboarding@resend.dev".to_string());

                let magic_url = format!("http://{}/?token={}", host, token);

                let body_json = serde_json::json!({
                    "from": sender,
                    "to": [email.clone()],
                    "subject": "Log in to MaxPayout",
                    "html": format!(
                        "<p>Click the link below to log in to your MaxPayout account:</p><p><a href=\"{}\">Log In Now</a></p>",
                        magic_url
                    )
                });

                let body_str = body_json.to_string();

                let req = http::Request::builder()
                    .method("POST")
                    .uri("https://api.resend.com/emails")
                    .header("Authorization", format!("Bearer {}", api_key))
                    .header("Content-Type", "application/json")
                    .body(body_str)
                    .map_err(|e| {
                        ServerFnError::ServerError(format!("Failed to build request: {}", e))
                    })?;

                // Send the request using spin_sdk::http::send
                let resp = spin_sdk::http::send(req).await.map_err(|e| {
                    ServerFnError::ServerError(format!("Failed to send email via Resend: {:?}", e))
                })?;

                if resp.status().is_success() {
                    println!("Successfully sent magic link email to {} via Resend", email);
                } else {
                    let status = resp.status();
                    let body_collected = resp.into_body().collect().await.map_err(|e| {
                        ServerFnError::ServerError(format!(
                            "Failed to read response body from Resend: {:?}",
                            e
                        ))
                    })?;
                    let body_bytes = body_collected.to_bytes();
                    let body_str = String::from_utf8_lossy(&body_bytes).to_string();
                    eprintln!(
                        "Failed to send email via Resend (Status: {}): {}",
                        status, body_str
                    );
                    return Err(ServerFnError::ServerError(format!(
                        "Failed to send email via Resend (Status: {}): {}",
                        status, body_str
                    )));
                }
            } else {
                println!(
                    "MOCK EMAIL: Magic link requested. URL: http://{}/?token={}",
                    host, token
                );
            }
        } else {
            println!(
                "MOCK EMAIL: Magic link requested. URL: http://{}/?token={}",
                host, token
            );
        }
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
                    last_cycle_at: None,
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
                user_agent: user_agent.clone(),
                ip_address: ip_address.clone(),
                expires_at,
                created_at: Utc::now(),
                last_active_at: Utc::now(),
                device_id: Some(uuid::Uuid::now_v7().to_string()[..8].to_string()),
                device_name: Some(crate::rfn_store::derive_device_name(user_agent.as_deref())),
                is_whitelisted: true,
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
pub async fn check_magic_link_enabled() -> Result<bool, ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        let has_resend = std::env::var("RESEND_API_KEY")
            .map(|val| !val.trim().is_empty())
            .unwrap_or(false);
        let local_testing = std::env::var("SHOW_LOCAL_TESTING_LINKS")
            .map(|val| val == "true" || val == "1")
            .unwrap_or(false);
        Ok(has_resend || local_testing)
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
                last_cycle_at: None,
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
                user_agent: user_agent.clone(),
                ip_address: ip_address.clone(),
                expires_at,
                created_at: Utc::now(),
                last_active_at: Utc::now(),
                device_id: Some(uuid::Uuid::now_v7().to_string()[..8].to_string()),
                device_name: Some(crate::rfn_store::derive_device_name(user_agent.as_deref())),
                is_whitelisted: true,
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
                user_agent: user_agent.clone(),
                ip_address: ip_address.clone(),
                expires_at,
                created_at: Utc::now(),
                last_active_at: Utc::now(),
                device_id: Some(uuid::Uuid::now_v7().to_string()[..8].to_string()),
                device_name: Some(crate::rfn_store::derive_device_name(user_agent.as_deref())),
                is_whitelisted: true,
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
        let mut user_account_ids = std::collections::HashSet::new();
        user_account_ids.insert(user.id);
        for (&acc_id, &u_id) in &state.pot_bonus_registrations {
            if u_id == user.id {
                user_account_ids.insert(acc_id);
            }
        }

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
                            is_user: user_account_ids.contains(&slot.account_id),
                            account_id: Some(slot.account_id),
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
                            account_id: None,
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

        // Resolve current session token and whitelisted state
        let mut current_token = String::new();
        if let Some(p) = parts.as_ref() {
            let cookie_header = p
                .headers
                .get(http::header::COOKIE)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            for cookie_part in cookie_header.split(';') {
                let trimmed = cookie_part.trim();
                if let Some(t) = trimmed.strip_prefix("session_token=") {
                    current_token = t.to_string();
                    break;
                }
            }
        }

        let mut user_device_is_whitelisted = true;
        if !current_token.is_empty() {
            if let Some(session) = state.sessions.get(&current_token) {
                user_device_is_whitelisted = session.is_whitelisted;
            }
        }

        // 5. Gather Referrals
        let mut referrals = Vec::new();
        let user_matrix_ids: Vec<Uuid> = state
            .matrices
            .values()
            .filter(|m| m.owner_id == user.id)
            .map(|m| m.id)
            .collect();

        for slot in &state.matrix_slots {
            if user_matrix_ids.contains(&slot.matrix_id) && slot.account_id != user.id {
                if let Some(acc) = state.flushline_accounts.get(&slot.account_id) {
                    referrals.push(ReferralInfo {
                        account_id: slot.account_id,
                        username: acc.owner.clone(),
                        tier: acc.tier.clone(),
                        registered_at: "".to_string(),
                        active: !acc.graduated,
                    });
                }
            }
        }
        let referrals_count = referrals.len() as i32;

        // 5b. Fetch and Resolve Multi-Accounts
        let mut accounts_info = Vec::new();
        let mut primary_account_exists = false;

        for (&acc_id, &u_id) in &state.pot_bonus_registrations {
            if u_id == user.id {
                if let Some(fa) = state.flushline_accounts.get(&acc_id) {
                    let (tier_name, tier_pts, tier_threshold) = crate::rfn_store::resolve_tier_progress(fa.current_pts);
                    let (q_pos, q_tot) = crate::rfn_store::get_queue_stats(&state, fa.id, &tier_name);

                    let has_matrix_cycle = state.matrices.values()
                        .any(|m| m.owner_id == fa.id && m.status == "Cycled");
                    let is_pot_qualified = fa.graduated && has_matrix_cycle;

                    let m_cycles = state.matrices.values()
                        .filter(|m| m.owner_id == fa.id && m.status == "Cycled")
                        .count() as i32;

                    let label = if fa.id == user.id {
                        primary_account_exists = true;
                        "Primary Account".to_string()
                    } else {
                        format!("Free Account {}", &fa.id.to_string()[..6])
                    };

                    accounts_info.push(AccountProgressInfo {
                        id: fa.id,
                        label,
                        tier: tier_name,
                        current_pts: fa.current_pts,
                        cycle_count: fa.cycle_count,
                        graduated: fa.graduated,
                        queue_position: q_pos,
                        queue_total: q_tot,
                        is_pot_qualified,
                        tier_pts,
                        tier_threshold,
                        matrix_cycles: m_cycles,
                    });
                }
            }
        }

        if !primary_account_exists {
            if let Some(fa) = state.flushline_accounts.get(&user.id) {
                let (tier_name, tier_pts, tier_threshold) = crate::rfn_store::resolve_tier_progress(fa.current_pts);
                let (q_pos, q_tot) = crate::rfn_store::get_queue_stats(&state, fa.id, &tier_name);

                let has_matrix_cycle = state.matrices.values()
                    .any(|m| m.owner_id == fa.id && m.status == "Cycled");
                let is_pot_qualified = fa.graduated && has_matrix_cycle;

                let m_cycles = state.matrices.values()
                    .filter(|m| m.owner_id == fa.id && m.status == "Cycled")
                    .count() as i32;

                accounts_info.push(AccountProgressInfo {
                    id: fa.id,
                    label: "Primary Account".to_string(),
                    tier: tier_name,
                    current_pts: fa.current_pts,
                    cycle_count: fa.cycle_count,
                    graduated: fa.graduated,
                    queue_position: q_pos,
                    queue_total: q_tot,
                    is_pot_qualified,
                    tier_pts,
                    tier_threshold,
                    matrix_cycles: m_cycles,
                });
            }
        }

        // 6. Metrics & Multi-Account Aggregation
        let mut total_flushline_cycles = 0.0;
        let mut total_matrix_cycles = 0.0;

        for acc in &accounts_info {
            total_flushline_cycles += acc.cycle_count as f64;
            total_matrix_cycles += state.matrices.values()
                .filter(|m| m.owner_id == acc.id && m.status == "Cycled")
                .count() as f64;
        }

        let total_earnings = (total_flushline_cycles * 500.0) + (total_matrix_cycles * 1500.0);
        let total_payouts = total_earnings * 0.8;

        let has_passkey = state.passkeys.iter().any(|pk| pk.user_id == user.id);

        // -- Global Tier Queues Diagnostics --
        let mut tier_queues = Vec::new();
        for tier_name in &["Ten", "Jack", "Queen", "King", "Ace"] {
            let mut tier_accounts: Vec<&crate::rfn_store::FlushlineAccount> = state
                .flushline_accounts
                .values()
                .filter(|acc| !acc.graduated && crate::rfn_store::resolve_tier_progress(acc.current_pts).0 == *tier_name)
                .collect();
            
            // Sort by ID (same stable sort as get_queue_stats)
            tier_accounts.sort_by_key(|acc| acc.id);
            
            let count = tier_accounts.len() as i32;
            let top_card_owner = tier_accounts.first().map(|acc| acc.owner.clone());
            
            let top_50: Vec<AccountQueueInfo> = tier_accounts
                .iter()
                .take(50)
                .map(|acc| AccountQueueInfo {
                    account_id: acc.id,
                    username: acc.owner.clone(),
                    cycle_count: acc.cycle_count,
                    last_cycle_at: acc.last_cycle_at,
                })
                .collect();
                
            tier_queues.push(TierQueueInfo {
                tier_name: tier_name.to_string(),
                top_card_owner,
                count,
                top_50,
            });
        }

        // -- Graduation Events stream logs --
        let mut graduation_events = state.graduation_events.clone();
        graduation_events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // -- Pot Bonus Shares Calculations --
        // Total Pool Amount
        let total_pool = state.pot_bonus_config.total_pot_pool;

        // Shared 75% Liquidity Pool
        let total_system_shares: i32 = state
            .flushline_accounts
            .values()
            .filter(|acc| acc.graduated)
            .map(|acc| acc.cycle_count)
            .sum();

        let user_total_shares: i32 = state
            .flushline_accounts
            .values()
            .filter(|acc| acc.graduated && state.pot_bonus_registrations.get(&acc.id) == Some(&user.id))
            .map(|acc| acc.cycle_count)
            .sum();

        let user_shared_payout = if total_system_shares > 0 {
            (user_total_shares as f64) * (total_pool * 0.75 / (total_system_shares as f64))
        } else {
            0.0
        };

        // Selective 25% Pool
        let mut qualified_selective_accounts: Vec<&crate::rfn_store::FlushlineAccount> = state
            .flushline_accounts
            .values()
            .filter(|acc| acc.graduated && acc.cycle_count >= state.pot_bonus_config.selective_min_shares)
            .collect();

        // Sort: cycle_count DESC, then last_cycle_at ASC (earliest tie breaker)
        qualified_selective_accounts.sort_by(|a, b| {
            let cmp_cycles = b.cycle_count.cmp(&a.cycle_count);
            if cmp_cycles == std::cmp::Ordering::Equal {
                match (a.last_cycle_at, b.last_cycle_at) {
                    (Some(ta), Some(tb)) => ta.cmp(&tb),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                }
            } else {
                cmp_cycles
            }
        });

        let mut user_selective_payout = 0.0;
        let selective_pool = total_pool * 0.25;

        if state.pot_bonus_config.selective_rule == "SoloWinner" {
            if let Some(winner_acc) = qualified_selective_accounts.first() {
                if state.pot_bonus_registrations.get(&winner_acc.id) == Some(&user.id) {
                    user_selective_payout = selective_pool;
                }
            }
        } else if state.pot_bonus_config.selective_rule == "Top5" {
            // Split 40%, 30%, 20%, 10% among top 4 performers
            let splits = [0.40, 0.30, 0.20, 0.10];
            for (rank, acc) in qualified_selective_accounts.iter().take(4).enumerate() {
                if state.pot_bonus_registrations.get(&acc.id) == Some(&user.id) {
                    user_selective_payout += selective_pool * splits[rank];
                }
            }
        }

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
            total_earnings,
            total_payouts,
            referrals_count,
            pot_bonus_amount: total_pool,
            referrals,
            user_device_is_whitelisted,
            accounts: accounts_info,
            pot_bonus_config: state.pot_bonus_config.clone(),
            tier_queues,
            graduation_events,
            total_system_shares,
            user_total_shares,
            user_shared_payout,
            user_selective_payout,
        })
    }
    #[cfg(not(feature = "ssr"))]
    {
        Err(ServerFnError::ServerError("SSR not enabled".to_string()))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MatrixCyclesResponse {
    pub current_matrix: MatrixInfo,
    pub cycle_options: Vec<CycleOption>,
}

#[server(prefix = "/api")]
pub async fn get_matrix_for_account(
    account_id: Uuid,
    cycle_number: Option<i32>,
) -> Result<MatrixCyclesResponse, ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::get_state;
        let state_store = get_state();
        let state = state_store.read().unwrap();
        let user = ssr_helpers::authenticate_request(&state)?;

        // Find all matrices owned by this account
        let mut user_matrices: Vec<crate::rfn_store::Matrix> = state
            .matrices
            .values()
            .filter(|m| m.owner_id == account_id)
            .cloned()
            .collect();

        // Sort chronologically using slot insertion order
        user_matrices.sort_by_key(|m| {
            state.matrix_slots
                .iter()
                .position(|s| s.matrix_id == m.id)
                .unwrap_or(usize::MAX)
        });

        let mut cycle_options = Vec::new();
        for (index, m) in user_matrices.iter().enumerate() {
            let cycle_num = (index + 1) as u32;
            let label = if m.status == "Filling" {
                format!("#{} (current)", cycle_num)
            } else {
                format!("#{}", cycle_num)
            };
            cycle_options.push(CycleOption {
                cycle_num,
                label,
            });
        }

        let target_matrix = if let Some(num) = cycle_number {
            if num > 0 && (num as usize) <= user_matrices.len() {
                &user_matrices[(num - 1) as usize]
            } else {
                user_matrices.last().ok_or_else(|| "No matrices found for this account".to_string())?
            }
        } else {
            user_matrices.last().ok_or_else(|| "No matrices found for this account".to_string())?
        };

        let mut slot_infos = Vec::new();
        let mut user_account_ids = std::collections::HashSet::new();
        user_account_ids.insert(user.id);
        for (&acc_id, &u_id) in &state.pot_bonus_registrations {
            if u_id == user.id {
                user_account_ids.insert(acc_id);
            }
        }

        for slot in &state.matrix_slots {
            if slot.matrix_id == target_matrix.id {
                let username = state
                    .flushline_accounts
                    .get(&slot.account_id)
                    .map(|a| a.owner.clone())
                    .unwrap_or_else(|| "Empty".to_string());

                slot_infos.push(MatrixSlotInfo {
                    slot_number: slot.slot_number,
                    username,
                    is_user: user_account_ids.contains(&slot.account_id),
                    account_id: Some(slot.account_id),
                });
            }
        }

        for slot in 1..=7 {
            if !slot_infos.iter().any(|si| si.slot_number == slot) {
                slot_infos.push(MatrixSlotInfo {
                    slot_number: slot,
                    username: "Empty".to_string(),
                    is_user: false,
                    account_id: None,
                });
            }
        }
        slot_infos.sort_by_key(|s| s.slot_number);

        let current_matrix = MatrixInfo {
            id: target_matrix.id,
            status: target_matrix.status.clone(),
            slots: slot_infos,
        };

        Ok(MatrixCyclesResponse {
            current_matrix,
            cycle_options,
        })
    }
    #[cfg(not(feature = "ssr"))]
    {
        Err(ServerFnError::ServerError("SSR not enabled".to_string()))
    }
}

#[server(prefix = "/api")]
pub async fn create_downline_account(
    sponsor_id: Uuid,
    username: String,
) -> Result<(), ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::{FlushlineAccount, Matrix, SagaCoordinator, get_state, save_state};
        let state_store = get_state();
        let mut state = state_store.write().unwrap();

        let user = ssr_helpers::authenticate_request(&state)?;

        let new_id = uuid::Uuid::now_v7();
        let username_trimmed = username.trim().to_string();
        if username_trimmed.is_empty() {
            return Err(ServerFnError::ServerError("Username cannot be empty".to_string()));
        }

        // Register in flushline
        state.flushline_accounts.insert(
            new_id,
            FlushlineAccount {
                id: new_id,
                owner: username_trimmed.clone(),
                tier: "Ten".to_string(),
                current_pts: 0,
                cycle_count: 0,
                graduated: false,
                last_cycle_at: None,
            },
        );

        // Register in pot_bonus_registrations as owned by the logged-in user!
        state.pot_bonus_registrations.insert(new_id, user.id);

        // Register in matrices
        let matrix_id = uuid::Uuid::now_v7();
        state.matrices.insert(
            matrix_id,
            Matrix {
                id: matrix_id,
                owner_id: new_id,
                status: "Filling".to_string(),
            },
        );

        // Place in sponsor's matrix
        SagaCoordinator::place_in_matrix(&mut state, new_id, sponsor_id, &username_trimmed)
            .map_err(|e| ServerFnError::ServerError(e))?;

        save_state(&state);
        Ok(())
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
                device_id: s
                    .device_id
                    .clone()
                    .or_else(|| Some(s.id.to_string()[..8].to_string())),
                device_name: s.device_name.clone().or_else(|| {
                    Some(crate::rfn_store::derive_device_name(
                        s.user_agent.as_deref(),
                    ))
                }),
                is_whitelisted: s.is_whitelisted,
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
pub async fn toggle_session_whitelist(session_id: Uuid) -> Result<(), ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::get_state;
        let state_store = get_state();
        let mut state = state_store.write().unwrap();

        let _user = ssr_helpers::authenticate_request(&state)?;

        state.toggle_whitelist(session_id);
        crate::rfn_store::save_state(&state);
        Ok(())
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
pub async fn simulate_downline_signup() -> Result<(), ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::{FlushlineAccount, Matrix, SagaCoordinator, get_state, save_state};
        let state_store = get_state();
        let mut state = state_store.write().unwrap();

        let user = ssr_helpers::authenticate_request(&state)?;

        let new_id = uuid::Uuid::now_v7();
        let username = format!("Referral_{}", &new_id.to_string()[..6]);

        // Register in flushline
        state.flushline_accounts.insert(
            new_id,
            FlushlineAccount {
                id: new_id,
                owner: username.clone(),
                tier: "Ten".to_string(),
                current_pts: 0,
                cycle_count: 0,
                graduated: false,
                last_cycle_at: None,
            },
        );

        // Register in matrices
        let matrix_id = uuid::Uuid::now_v7();
        state.matrices.insert(
            matrix_id,
            Matrix {
                id: matrix_id,
                owner_id: new_id,
                status: "Filling".to_string(),
            },
        );

        // Place in sponsor's (the user's) matrix
        SagaCoordinator::place_in_matrix(&mut state, new_id, user.id, &username)
            .map_err(|e| ServerFnError::ServerError(e))?;

        save_state(&state);
        Ok(())
    }
    #[cfg(not(feature = "ssr"))]
    {
        Err(ServerFnError::ServerError("SSR not enabled".to_string()))
    }
}

#[server(prefix = "/api")]
pub async fn award_points(account_id: Uuid, points: u32) -> Result<AwardResponse, ServerFnError<String>> {
    #[cfg(feature = "ssr")]
    {
        use crate::rfn_store::{SagaCoordinator, get_state};

        ssr_helpers::check_rate_limit()?;
        let state_store = get_state();
        let mut state = state_store.write().unwrap();
        let user = ssr_helpers::authenticate_request(&state)?;

        // Award points transactionally using our sync coordinator
        SagaCoordinator::award_points(&mut state, account_id, points)
            .map_err(|e| ServerFnError::ServerError(e))?;

        let account = state.flushline_accounts.get(&account_id).unwrap();
        let coord = state.coordination_states.get(&account_id);

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
        let _ = account_id;
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
                user_agent: user_agent.clone(),
                ip_address: ip_address.clone(),
                expires_at,
                created_at: Utc::now(),
                last_active_at: Utc::now(),
                device_id: Some(uuid::Uuid::now_v7().to_string()[..8].to_string()),
                device_name: Some(crate::rfn_store::derive_device_name(user_agent.as_deref())),
                is_whitelisted: true,
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
                last_cycle_at: None,
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
                user_agent: user_agent.clone(),
                ip_address: ip_address.clone(),
                expires_at,
                created_at: Utc::now(),
                last_active_at: Utc::now(),
                device_id: Some(uuid::Uuid::now_v7().to_string()[..8].to_string()),
                device_name: Some(crate::rfn_store::derive_device_name(user_agent.as_deref())),
                is_whitelisted: true,
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

#[allow(dead_code)]
async fn sleep_delay(duration: std::time::Duration) {
    #[cfg(feature = "hydrate")]
    {
        use wasm_bindgen::prelude::*;
        let (tx, rx) = futures::channel::oneshot::channel();
        let closure = Closure::once_into_js(move || {
            let _ = tx.send(());
        });
        if let Some(window) = web_sys::window() {
            let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                closure.as_ref().unchecked_ref(),
                duration.as_millis() as i32,
            );
        }
        let _ = rx.await;
    }
    #[cfg(feature = "ssr")]
    {
        let _ = spin_sdk::time::sleep(duration).await;
    }
    #[cfg(all(not(feature = "hydrate"), not(feature = "ssr")))]
    {
        std::thread::sleep(duration);
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
                    <Route path=path!("dashboard") view=HomePage />
                    <Route path=path!("flushline") view=HomePage />
                    <Route path=path!("matrix") view=HomePage />
                    <Route path=path!("downlines") view=HomePage />
                    <Route path=path!("security") view=HomePage />
                    <Route path=path!("linked") view=HomePage />
                    <Route path=path!("settings") view=HomePage />
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
    let (selected_account_id, set_selected_account_id) = signal(Option::<Uuid>::None);
    let (active_sessions, set_active_sessions) = signal(Vec::<SessionInfo>::new());

    // Refresh function for state - defined early so it can be called by effects
    let refresh_dashboard = move || {
        leptos::task::spawn_local(async move {
            if let Ok(data) = get_user_dashboard_status().await {
                set_dashboard_data.set(data.clone());
                if data.user.is_some() {
                    if let Ok(sessions) = get_active_sessions().await {
                        set_active_sessions.set(sessions);
                    }
                }

                // Initialize or validate selected_account_id
                let cur_selected = selected_account_id.get();
                let exists = cur_selected.map(|sid| data.accounts.iter().any(|acc| acc.id == sid)).unwrap_or(false);
                if !exists {
                    if let Some(first_acc) = data.accounts.first() {
                        set_selected_account_id.set(Some(first_acc.id));
                    } else {
                        set_selected_account_id.set(None);
                    }
                }
            }
        });
    };

    // Searchable Combobox Signals & Handlers
    let (combobox_query, set_combobox_query) = signal(String::new());
    let (combobox_open, set_combobox_open) = signal(false);
    let (combobox_highlighted, set_combobox_highlighted) = signal(0_usize);

    // Reactive Weekly Countdown Signal
    let (time_left, set_time_left) = signal("48:12:05".to_string());

    #[cfg(feature = "hydrate")]
    {
        use wasm_bindgen::prelude::*;
        use chrono::Datelike;
        use chrono::Timelike;

        // Effect for Live Countdown
        Effect::new(move |_| {
            let handle = {
                let set_time_left = set_time_left.clone();
                let f = Closure::wrap(Box::new(move || {
                    let now = chrono::Local::now();
                    let weekday_num = now.weekday().num_days_from_monday() as i64; // Mon=0, Sun=6
                    let seconds_today = now.time().num_seconds_from_midnight() as i64;
                    let seconds_until_sunday = ((6 - weekday_num) * 86400) + (86400 - seconds_today) - 1;
                    
                    if seconds_until_sunday > 0 {
                        let hours = seconds_until_sunday / 3600;
                        let mins = (seconds_until_sunday % 3600) / 60;
                        let secs = seconds_until_sunday % 60;
                        set_time_left.set(format!("{:02}:{:02}:{:02}", hours, mins, secs));
                    } else {
                        set_time_left.set("00:00:00".to_string());
                    }
                }) as Box<dyn FnMut()>);
                
                let window = web_sys::window().unwrap();
                let id = window.set_interval_with_callback_and_timeout_and_arguments_0(
                    f.as_ref().unchecked_ref(),
                    1000,
                ).unwrap();
                f.forget();
                id
            };
            
            on_cleanup(move || {
                if let Some(window) = web_sys::window() {
                    let _ = window.clear_interval_with_handle(handle);
                }
            });
        });

        // Effect for Live Synchronization Loop (every 3 seconds)
        Effect::new(move |_| {
            let handle = {
                let f = Closure::wrap(Box::new(move || {
                    refresh_dashboard();
                }) as Box<dyn FnMut()>);
                
                let window = web_sys::window().unwrap();
                let id = window.set_interval_with_callback_and_timeout_and_arguments_0(
                    f.as_ref().unchecked_ref(),
                    3000,
                ).unwrap();
                f.forget();
                id
            };
            
            on_cleanup(move || {
                if let Some(window) = web_sys::window() {
                    let _ = window.clear_interval_with_handle(handle);
                }
            });
        });
    }

    // Synchronize query text with selected account when selected_account_id or accounts list changes
    Effect::new(move |_| {
        let accounts = dashboard_data.get().accounts;
        let selected_id = selected_account_id.get();
        if let Some(selected_id) = selected_id {
            if let Some(acc) = accounts.iter().find(|a| a.id == selected_id) {
                if !combobox_open.get() {
                    set_combobox_query.set(acc.label.clone());
                }
            }
        } else {
            set_combobox_query.set(String::new());
        }
    });

    let filtered_accounts = move || {
        let accounts = dashboard_data.get().accounts;
        let query = combobox_query.get().trim().to_lowercase();
        
        let is_selected_acc_label = selected_account_id.get()
            .and_then(|sid| accounts.iter().find(|a| a.id == sid))
            .map(|a| a.label.to_lowercase() == query)
            .unwrap_or(false);

        if query.is_empty() || is_selected_acc_label {
            accounts
        } else {
            accounts
                .into_iter()
                .filter(|acc| acc.label.to_lowercase().contains(&query))
                .collect::<Vec<_>>()
        }
    };

    let handle_combobox_keydown = move |ev: leptos::web_sys::KeyboardEvent| {
        let list = filtered_accounts();
        if list.is_empty() {
            return;
        }
        let max_idx = list.len() - 1;
        let current_highlighted = combobox_highlighted.get();

        match ev.key().as_str() {
            "ArrowDown" => {
                ev.prevent_default();
                if !combobox_open.get() {
                    set_combobox_open.set(true);
                    set_combobox_highlighted.set(0);
                } else {
                    let next = if current_highlighted >= max_idx { 0 } else { current_highlighted + 1 };
                    set_combobox_highlighted.set(next);
                }
            }
            "ArrowUp" => {
                ev.prevent_default();
                if !combobox_open.get() {
                    set_combobox_open.set(true);
                    set_combobox_highlighted.set(max_idx);
                } else {
                    let prev = if current_highlighted == 0 { max_idx } else { current_highlighted - 1 };
                    set_combobox_highlighted.set(prev);
                }
            }
            "Enter" => {
                if combobox_open.get() {
                    ev.prevent_default();
                    if let Some(target_acc) = list.get(current_highlighted) {
                        set_selected_account_id.set(Some(target_acc.id));
                        set_combobox_query.set(target_acc.label.clone());
                        set_combobox_open.set(false);
                    }
                }
            }
            "Escape" => {
                ev.prevent_default();
                set_combobox_open.set(false);
            }
            _ => {
                if !combobox_open.get() {
                    set_combobox_open.set(true);
                    set_combobox_highlighted.set(0);
                }
            }
        }
    };

    let handle_option_select = move |acc_id: Uuid, label: String| {
        set_selected_account_id.set(Some(acc_id));
        set_combobox_query.set(label);
        set_combobox_open.set(false);
    };

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
                                    Err(ServerFnError::ServerError(msg)) => {
                                        set_biometric_error.set(Some(msg));
                                        set_biometric_loading.set(false);
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
                Err(ServerFnError::ServerError(msg)) => {
                    set_biometric_error.set(Some(msg));
                    set_biometric_loading.set(false);
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
                                        Err(ServerFnError::ServerError(msg)) => {
                                            check_error(msg);
                                            set_biometric_loading.set(false);
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
                                        Err(ServerFnError::ServerError(msg)) => {
                                            check_error(msg);
                                            set_biometric_loading.set(false);
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
                Err(ServerFnError::ServerError(msg)) => {
                    check_error(msg);
                    set_biometric_loading.set(false);
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
    #[allow(unused_variables)]
    let (award_pts_input, set_award_pts_input) = signal(5u32);

    // ----------------------------------------------------------------------------
    // Premium Dashboard Navigation & Sections State
    // ----------------------------------------------------------------------------
    let location = leptos_router::hooks::use_location();
    let active_section = Memo::new(move |_| {
        let path = location.pathname.get();
        if path.contains("flushline") {
            "flushline".to_string()
        } else if path.contains("matrix") {
            "matrix".to_string()
        } else if path.contains("downlines") {
            "downlines".to_string()
        } else if path.contains("security") {
            "security".to_string()
        } else if path.contains("linked") {
            "linked".to_string()
        } else if path.contains("settings") {
            "settings".to_string()
        } else {
            "dashboard".to_string()
        }
    });
    let (copied, set_copied) = signal(false);
    let (simulate_loading, set_simulate_loading) = signal(false);
    let (linked_google, set_linked_google) = signal(false);
    let (linked_apple, set_linked_apple) = signal(false);
    let (linked_microsoft, set_linked_microsoft) = signal(false);
    let (linked_facebook, set_linked_facebook) = signal(false);
    let (linking_provider, set_linking_provider) = signal(Option::<String>::None);
    let (selected_theme, set_selected_theme) = signal("obsidian".to_string());
    let (selected_avatar, set_selected_avatar) = signal("avatar_1".to_string());
    let (profile_success_toast, set_profile_success_toast) = signal(false);

    let handle_toggle_whitelist = move |session_id: Uuid| {
        leptos::task::spawn_local(async move {
            let _ = toggle_session_whitelist(session_id).await;
            refresh_dashboard();
        });
    };

    let handle_simulate_signup = move || {
        set_simulate_loading.set(true);
        leptos::task::spawn_local(async move {
            let _ = simulate_downline_signup().await;
            refresh_dashboard();
            set_simulate_loading.set(false);
        });
    };
    #[allow(unused_variables)]
    let (award_loading, set_award_loading) = signal(false);

    #[allow(dead_code, unused_variables)]
    let handle_award_points = move || {
        let account_id = selected_account_id.get().unwrap_or_else(|| {
            dashboard_data.get().accounts.first().map(|a| a.id).unwrap_or_default()
        });
        if account_id.is_nil() {
            return;
        }
        set_award_loading.set(true);
        leptos::task::spawn_local(async move {
            let pts = award_pts_input.get();
            if let Ok(res) = award_points(account_id, pts).await {
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

    // Fetch feature flag values
    let (magic_link_enabled, set_magic_link_enabled) = signal(true);
    Effect::new(move |_| {
        leptos::task::spawn_local(async move {
            if let Ok(enabled) = check_local_testing_enabled().await {
                set_show_local_links.set(enabled);
            }
            if let Ok(enabled) = check_magic_link_enabled().await {
                set_magic_link_enabled.set(enabled);
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
                    Err(ServerFnError::ServerError(msg)) => {
                        set_password_auth_error.set(Some(msg));
                        set_password_auth_loading.set(false);
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
                    Err(ServerFnError::ServerError(msg)) => {
                        set_password_auth_error.set(Some(msg));
                        set_password_auth_loading.set(false);
                    }
                    Err(e) => {
                        set_password_auth_error.set(Some(e.to_string()));
                        set_password_auth_loading.set(false);
                    }
                }
            }
        });
    };

    let (selected_matrix_account, set_selected_matrix_account) = signal(Option::<Uuid>::None);
    let (selected_cycle_number, set_selected_cycle_number) = signal(Option::<i32>::None);
    let (matrix_cycle_options, set_matrix_cycle_options) = signal(Vec::<CycleOption>::new());
    let (matrix_info, set_matrix_info) = signal(Option::<MatrixInfo>::None);

    let (acc_dropdown_open, set_acc_dropdown_open) = signal(false);
    let (cycle_dropdown_open, set_cycle_dropdown_open) = signal(false);
    let (acc_search_query, set_acc_search_query) = signal(String::new());
    let (cycle_search_query, set_cycle_search_query) = signal(String::new());
    let (acc_highlighted_index, set_acc_highlighted_index) = signal(0);
    let (cycle_highlighted_index, set_cycle_highlighted_index) = signal(0);

    let (show_downline_modal, set_show_downline_modal) = signal(false);
    let (modal_sponsor_id, set_modal_sponsor_id) = signal(Option::<Uuid>::None);
    let (modal_slot_number, set_modal_slot_number) = signal(Option::<i32>::None);
    let (new_downline_username, set_new_downline_username) = signal(String::new());
    let (create_downline_loading, set_create_downline_loading) = signal(false);
    let (create_downline_error, set_create_downline_error) = signal(String::new());

    Effect::new(move |_| {
        if let Some(id) = selected_account_id.get() {
            if selected_matrix_account.get_untracked().is_none() {
                set_selected_matrix_account.set(Some(id));
            }
        }
    });

    Effect::new(move |_| {
        let accounts = dashboard_data.get().accounts;
        if selected_matrix_account.get().is_none() {
            if let Some(first_acc) = accounts.first() {
                set_selected_matrix_account.set(Some(first_acc.id));
            }
        }
    });

    Effect::new(move |_| {
        let acc_id_opt = selected_matrix_account.get();
        let cycle_num_opt = selected_cycle_number.get();
        if let Some(acc_id) = acc_id_opt {
            leptos::task::spawn_local(async move {
                if let Ok(res) = get_matrix_for_account(acc_id, cycle_num_opt).await {
                    set_matrix_info.set(Some(res.current_matrix));
                    set_matrix_cycle_options.set(res.cycle_options);
                }
            });
        } else {
            set_matrix_info.set(None);
            set_matrix_cycle_options.set(Vec::new());
        }
    });

    let filtered_matrix_accounts = move || {
        let accounts = dashboard_data.get().accounts;
        let query = acc_search_query.get().trim().to_lowercase();
        if query.is_empty() {
            accounts
        } else {
            accounts
                .into_iter()
                .filter(|acc| acc.label.to_lowercase().contains(&query))
                .collect::<Vec<_>>()
        }
    };

    let filtered_matrix_cycles = move || {
        let options = matrix_cycle_options.get();
        let query = cycle_search_query.get().trim().to_lowercase();
        if query.is_empty() {
            options
        } else {
            options
                .into_iter()
                .filter(|opt| opt.label.to_lowercase().contains(&query))
                .collect::<Vec<_>>()
        }
    };

    let get_slot_account_id = move |idx: usize| {
        matrix_info.get().and_then(|m| m.slots.get(idx).and_then(|s| s.account_id))
    };

    let get_slot_parent_account_id = move |slot_number: i32| -> Option<Uuid> {
        match slot_number {
            2 | 3 => get_slot_account_id(0),
            4 | 5 => get_slot_account_id(1),
            6 | 7 => get_slot_account_id(2),
            _ => None,
        }
    };

    let handle_open_create_modal = move |slot_number: i32| {
        if let Some(parent_id) = get_slot_parent_account_id(slot_number) {
            set_modal_sponsor_id.set(Some(parent_id));
            set_modal_slot_number.set(Some(slot_number));
            set_new_downline_username.set(String::new());
            set_create_downline_error.set(String::new());
            set_show_downline_modal.set(true);
        }
    };

    let handle_create_downline = move || {
        let sponsor_id = match modal_sponsor_id.get() {
            Some(id) => id,
            None => return,
        };
        let username = new_downline_username.get();
        if username.trim().is_empty() {
            set_create_downline_error.set("Username cannot be empty".to_string());
            return;
        }
        set_create_downline_loading.set(true);
        leptos::task::spawn_local(async move {
            match create_downline_account(sponsor_id, username).await {
                Ok(_) => {
                    set_show_downline_modal.set(false);
                    set_create_downline_loading.set(false);
                    refresh_dashboard();
                    if let Some(curr_acc) = selected_matrix_account.get() {
                        if let Ok(res) = get_matrix_for_account(curr_acc, selected_cycle_number.get()).await {
                            set_matrix_info.set(Some(res.current_matrix));
                            set_matrix_cycle_options.set(res.cycle_options);
                        }
                    }
                }
                Err(e) => {
                    set_create_downline_error.set(e.to_string());
                    set_create_downline_loading.set(false);
                }
            }
        });
    };

    let get_slot_username = move |idx: usize| {
        matrix_info
            .get()
            .map(|m| {
                m.slots
                    .get(idx)
                    .map(|s| s.username.clone())
                    .unwrap_or_else(|| "Empty".to_string())
            })
            .unwrap_or_else(|| "Empty".to_string())
    };

    let is_slot_filled = move |idx: usize| {
        matrix_info
            .get()
            .map(|m| {
                m.slots
                    .get(idx)
                    .map(|s| s.username != "Empty")
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    };

    let is_slot_user = move |idx: usize| {
        matrix_info
            .get()
            .map(|m| m.slots.get(idx).map(|s| s.is_user).unwrap_or(false))
            .unwrap_or(false)
    };

    let render_modal_overlay = move || {
        if !show_downline_modal.get() {
            return view! { <div class="hidden"></div> }.into_any();
        }
        
        let sponsor_name = move || {
            let sp_id = modal_sponsor_id.get();
            let state_data = dashboard_data.get();
            if let Some(id) = sp_id {
                if let Some(acc) = state_data.accounts.iter().find(|a| a.id == id) {
                    acc.label.clone()
                } else if let Some(ref_item) = state_data.referrals.iter().find(|r| r.account_id == id) {
                    ref_item.username.clone()
                } else {
                    if let Some(m) = matrix_info.get_untracked() {
                        if let Some(slot) = m.slots.iter().find(|s| s.account_id == Some(id)) {
                            return slot.username.clone();
                        }
                    }
                    format!("Account ID: {}", id.to_string().chars().take(8).collect::<String>())
                }
            } else {
                "None".to_string()
            }
        };

        let slot_label = move || {
            modal_slot_number.get()
                .map(|s| format!("Slot {}", s))
                .unwrap_or_else(|| "Empty Slot".to_string())
        };

        view! {
            <div class="fixed inset-0 bg-[#070b13]/85 backdrop-blur-md flex items-center justify-center z-[100] animate-fadeIn">
                <div class="bg-[#111827] border border-zinc-800 rounded-3xl p-8 max-w-md w-full mx-4 shadow-2xl relative space-y-6 text-left">
                    <button
                        on:click=move |_| set_show_downline_modal.set(false)
                        class="absolute top-5 right-5 text-slate-400 hover:text-white transition-colors text-lg"
                    >
                        "✕"
                    </button>

                    <div class="space-y-1 text-left">
                        <h3 class="text-lg font-black text-white">"Register New Downline"</h3>
                        <p class="text-xs text-slate-400">"This account will be placed directly in your matrix tree."</p>
                    </div>

                    <div class="bg-zinc-950 border border-zinc-900 rounded-xl p-4 space-y-3 font-mono text-[11px] text-left">
                        <div class="flex justify-between">
                            <span class="text-slate-500 uppercase">"Sponsor / Parent:"</span>
                            <span class="text-emerald-400 font-bold">{sponsor_name()}</span>
                        </div>
                        <div class="flex justify-between">
                            <span class="text-slate-500 uppercase">"Placement Slot:"</span>
                            <span class="text-[#00d4aa] font-bold">{slot_label()}</span>
                        </div>
                    </div>

                    <Show when=move || !create_downline_error.get().is_empty()>
                        <div class="p-3 bg-rose-950/40 border border-rose-800 text-rose-400 text-xs rounded-xl font-mono text-left">
                            {move || create_downline_error.get()}
                        </div>
                    </Show>

                    <div class="space-y-1.5 text-left">
                        <label class="text-[10px] font-bold uppercase text-slate-400 tracking-wider">"Desired Username"</label>
                        <input
                            type="text"
                            on:input=move |ev| set_new_downline_username.set(event_target_value(&ev))
                            prop:value=new_downline_username
                            placeholder="e.g. SatoshiAlpha"
                            class="w-full px-4 py-2.5 bg-zinc-950 border border-zinc-800 focus:border-[#00d4aa] rounded-xl text-white text-xs outline-none tracking-wide"
                        />
                    </div>

                    <div class="flex gap-3">
                        <button
                            on:click=move |_| set_show_downline_modal.set(false)
                            class="flex-1 py-2.5 border border-zinc-800 text-slate-300 hover:bg-zinc-900 font-bold text-xs rounded-xl transition-all"
                        >
                            "Cancel"
                        </button>
                        <button
                            on:click=move |_| handle_create_downline()
                            disabled=move || create_downline_loading.get()
                            class="flex-1 py-2.5 bg-gradient-to-r from-emerald-500 to-[#00d4aa] hover:from-emerald-600 hover:to-emerald-400 text-[#0b0f19] font-extrabold text-xs rounded-xl transition-all shadow-lg shadow-emerald-500/10 flex items-center justify-center gap-1.5"
                        >
                            <Show when=move || create_downline_loading.get()>
                                <div class="w-3 h-3 border-2 border-transparent border-t-[#0b0f19] rounded-full animate-spin"></div>
                            </Show>
                            "Create Downline"
                        </button>
                    </div>
                </div>
            </div>
        }.into_any()
    };

    let render_matrix_node = move |slot_number: i32, idx: usize| {
        let is_filled = is_slot_filled(idx);
        let is_user = is_slot_user(idx);
        let username = get_slot_username(idx);
        let acc_id = get_slot_account_id(idx);

        let position_label = match slot_number {
            1 => "SLOT 1 (ROOT)".to_string(),
            _ => format!("POSITION {}", slot_number - 1),
        };

        if is_filled {
            let is_user_owned = {
                let list = dashboard_data.get().accounts;
                acc_id.map(|id| list.iter().any(|a| a.id == id)).unwrap_or(false)
            };

            let on_node_click = move |_| {
                if is_user_owned {
                    if let Some(id) = acc_id {
                        set_selected_matrix_account.set(Some(id));
                        set_selected_cycle_number.set(None);
                    }
                }
            };

            view! {
                <div 
                    on:click=on_node_click
                    class=move || {
                        let base = "flex flex-col items-center relative z-10 ";
                        if is_user_owned {
                            format!("{base} cursor-pointer hover:scale-105 transition-all duration-300 group")
                        } else {
                            base.to_string()
                        }
                    }
                >
                    <div class=move || {
                        let ring = if is_user { 
                            "border-[#00d4aa] ring-4 ring-[#00d4aa]/20" 
                        } else if is_user_owned {
                            "border-indigo-400 group-hover:border-[#00d4aa] transition-colors"
                        } else { 
                            "border-zinc-700" 
                        };
                        format!("w-16 h-16 rounded-full bg-zinc-900 border-2 {} flex flex-col items-center justify-center font-bold text-sm text-white shadow-xl relative", ring)
                    }>
                        {username.chars().take(2).collect::<String>().to_uppercase()}
                        
                        <Show when=move || is_user_owned>
                            <span class="absolute -top-1.5 -right-1.5 bg-[#00d4aa] text-[#0b0f19] text-[8px] font-extrabold px-1.5 py-0.5 rounded-full uppercase tracking-wider">
                                "You"
                            </span>
                        </Show>
                    </div>
                    <span class="text-xs text-white font-semibold mt-2">{username}</span>
                    <span class="text-[8px] text-[#00d4aa] font-extrabold uppercase mt-0.5 tracking-wider">{position_label}</span>
                </div>
            }.into_any()
        } else {
            view! {
                <div 
                    on:click=move |_| handle_open_create_modal(slot_number)
                    class="flex flex-col items-center relative z-10 cursor-pointer group"
                >
                    <div class="w-16 h-16 rounded-full border-2 border-dashed border-emerald-500/20 group-hover:border-emerald-500/50 bg-emerald-500/5 flex items-center justify-center transition-all duration-300 relative">
                        <div class="w-8 h-8 rounded-full border border-dashed border-emerald-500/30 group-hover:border-emerald-500/60 flex items-center justify-center font-bold text-emerald-500/70 group-hover:text-emerald-500 text-xs transition-colors">
                            "+"
                        </div>
                    </div>
                    <span class="text-xs text-slate-500 mt-2 font-medium">"Empty"</span>
                    <span class="text-[8px] text-slate-500 font-bold uppercase mt-0.5 tracking-wider">{position_label}</span>
                </div>
            }.into_any()
        }
    };

    view! {
        <Show
            when=move || dashboard_data.get().user.is_some()
            fallback=move || view! {
                <div class="max-w-6xl mx-auto px-4 py-8 space-y-8 min-h-screen flex flex-col justify-start">
                    // Global Header
                    <header class="flex items-center justify-between border-b border-[#1e293b] pb-6">
                        <div class="flex items-center gap-3">
                            <div class="w-10 h-10 bg-[#00d4aa] rounded-lg flex items-center justify-center shadow-lg shadow-[#00d4aa]/20">
                                <span class="text-[#0b0f19] font-extrabold text-xl">"M"</span>
                            </div>
                            <div>
                                <h1 class="text-2xl font-bold tracking-tight text-white">"MaxPayout"</h1>
                                <p class="text-xs text-slate-400">"Saga Orchestration & Biometrics Integration (MaxPayout 2.0)"</p>
                            </div>
                        </div>
                    </header>

                    // LOGIN OR REGISTER CARD (when not logged in)
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
                                    {move || if show_register.get() {
                                        "Choose your preferred secure registration method"
                                    } else if magic_link_enabled.get() {
                                        "Log in using password, magic link, or biometric passkeys"
                                    } else {
                                        "Log in using password or biometric passkeys"
                                    }}
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
                                <Show when=move || magic_link_enabled.get()>
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
                                </Show>
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
                                        <circle cx="7.5" cy="15.5" r="5.5" />
                                        <path d="m21 2-9.6 9.6" />
                                        <path d="m15.5 7.5 3 3" />
                                        <path d="m19 4 3 3" />
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

                                        <div class="p-3 bg-slate-950/40 border border-[#1f2937]/60 rounded-xl text-left space-y-1.5 mt-2 animate-fadeIn">
                                            <p class="text-[10px] font-bold text-slate-300 flex items-center gap-1.5">
                                                <span>"💡"</span> "Logging in on a new computer?"
                                            </p>
                                            <p class="text-[10px] text-slate-400 leading-relaxed">
                                                "Type your registered email and click Log In. Your browser will display a secure QR code you can scan with your phone's camera to authenticate instantly."
                                            </p>
                                        </div>
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
                                                <circle cx="7.5" cy="15.5" r="5.5" />
                                                <path d="m21 2-9.6 9.6" />
                                                <path d="m15.5 7.5 3 3" />
                                                <path d="m19 4 3 3" />
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
                                    <div class="p-4 bg-amber-950/40 border border-amber-800 rounded-xl text-left space-y-3.5 animate-fadeIn">
                                        <div class="flex gap-2.5 items-start">
                                            <svg class="w-5 h-5 text-amber-400 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                                <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                            </svg>
                                            <div>
                                                <p class="text-xs font-bold text-amber-200">"Alternative Login Required"</p>
                                                <p class="text-xs text-amber-400 mt-0.5 leading-relaxed">
                                                    {move || if magic_link_enabled.get() {
                                                        "This account is registered but has no passkeys on this device yet. Please log in using your Password or a Magic Link first, then register this device in Settings."
                                                    } else {
                                                        "This account is registered but has no passkeys on this device yet. Please log in using your Password first, then register this device in Settings."
                                                    }}
                                                </p>
                                            </div>
                                        </div>
                                        <div class="flex flex-col gap-2">
                                            <button
                                                type="button"
                                                on:click=move |_| {
                                                    switch_tab("password".to_string());
                                                }
                                                class="w-full py-2.5 bg-[#1f2937] hover:bg-slate-700 text-white text-xs font-semibold rounded-lg transition-all duration-150 flex items-center justify-center gap-1.5 border border-[#334155] shadow-md shadow-black/25"
                                            >
                                                <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                                                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                                                </svg>
                                                "Log In with Password"
                                            </button>
                                            <Show when=move || magic_link_enabled.get()>
                                                <button
                                                    type="button"
                                                    on:click=move |_| {
                                                        switch_tab("magic".to_string());
                                                    }
                                                    class="w-full py-2.5 bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold rounded-lg transition-all duration-150 flex items-center justify-center gap-1.5 shadow-md shadow-amber-950/30"
                                                >
                                                    <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                                        <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
                                                        <polyline points="22,6 12,13 2,6" />
                                                    </svg>
                                                    "Log In with Magic Link"
                                                </button>
                                            </Show>
                                        </div>
                                    </div>
                                </Show>
                            </div>
                        </div>
                    </div>
                </div>
            }
        >
            // Logged-in full view with sidebar & panels!
            <div class="flex flex-col md:flex-row min-h-screen bg-[#070b14] text-slate-100 font-sans">
                // LEFT SIDEBAR - PREMIUM GLASSMORPHIC DESIGNS
                <aside class="w-full md:w-64 bg-[#0c111d]/90 backdrop-blur-xl border-b md:border-b-0 md:border-r border-zinc-800/80 p-6 flex flex-col justify-between shrink-0 z-20">
                    <div class="space-y-8">
                        // Brand Logo
                        <div class="flex items-center gap-3">
                            <div class="w-10 h-10 bg-gradient-to-br from-[#00d4aa] to-emerald-500 rounded-xl flex items-center justify-center shadow-lg shadow-emerald-500/20">
                                <span class="text-[#0b0f19] font-extrabold text-xl">"M"</span>
                            </div>
                            <div>
                                <h1 class="text-xl font-extrabold tracking-tight bg-gradient-to-r from-white to-slate-300 bg-clip-text text-transparent">"MaxPayout"</h1>
                                <p class="text-[10px] text-emerald-400 font-semibold tracking-widest uppercase">"V2.0 Saga Platform"</p>
                            </div>
                        </div>

                        // User profile card widget inside sidebar
                        <div class="p-3 bg-zinc-900/40 border border-zinc-800/60 rounded-xl flex items-center gap-3">
                            <div class="w-10 h-10 rounded-full bg-gradient-to-tr from-emerald-500/10 to-teal-500/20 border border-emerald-500/30 flex items-center justify-center font-bold text-sm text-[#00d4aa]">
                                {move || dashboard_data.get().user.clone().unwrap_or_default().username.chars().take(2).collect::<String>().to_uppercase()}
                            </div>
                            <div class="min-w-0 flex-1">
                                <p class="text-xs font-bold text-white truncate">{move || dashboard_data.get().user.clone().unwrap_or_default().username}</p>
                                <p class="text-[9px] text-slate-400 truncate">{move || dashboard_data.get().user.clone().unwrap_or_default().email}</p>
                            </div>
                        </div>

                        // Sidebar navigation buttons
                        <nav class="space-y-1">
                            <a
                                href="/dashboard"
                                class=move || {
                                    let active = active_section.get() == "dashboard";
                                    let base = "w-full py-2.5 px-4 text-xs font-semibold rounded-lg flex items-center gap-3 transition-all duration-150 ";
                                    if active {
                                        format!("{base} bg-gradient-to-r from-emerald-500/10 to-teal-500/5 text-[#00d4aa] border border-emerald-500/20 shadow-sm")
                                    } else {
                                        format!("{base} text-slate-400 hover:text-white hover:bg-zinc-900/30 border border-transparent")
                                    }
                                }
                            >
                                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v4a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v4a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v4a2 2 0 01-2 2H6a2 2 0 01-2-2v-4zM14 16a2 2 0 012-2h2a2 2 0 012 2v4a2 2 0 01-2 2h-2a2 2 0 01-2-2v-4z" />
                                </svg>
                                "Overview"
                            </a>

                            <a
                                href="/flushline"
                                class=move || {
                                    let active = active_section.get() == "flushline";
                                    let base = "w-full py-2.5 px-4 text-xs font-semibold rounded-lg flex items-center gap-3 transition-all duration-150 ";
                                    if active {
                                        format!("{base} bg-gradient-to-r from-emerald-500/10 to-teal-500/5 text-[#00d4aa] border border-emerald-500/20 shadow-sm")
                                    } else {
                                        format!("{base} text-slate-400 hover:text-white hover:bg-zinc-900/30 border border-transparent")
                                    }
                                }
                            >
                                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
                                </svg>
                                "Flushline Engine"
                            </a>

                            <a
                                href="/matrix"
                                class=move || {
                                    let active = active_section.get() == "matrix";
                                    let base = "w-full py-2.5 px-4 text-xs font-semibold rounded-lg flex items-center gap-3 transition-all duration-150 ";
                                    if active {
                                        format!("{base} bg-gradient-to-r from-emerald-500/10 to-teal-500/5 text-[#00d4aa] border border-emerald-500/20 shadow-sm")
                                    } else {
                                        format!("{base} text-slate-400 hover:text-white hover:bg-zinc-900/30 border border-transparent")
                                    }
                                }
                            >
                                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M12 4v16m8-8H4" />
                                </svg>
                                "Matrix Tree"
                            </a>

                            <a
                                href="/downlines"
                                class=move || {
                                    let active = active_section.get() == "downlines";
                                    let base = "w-full py-2.5 px-4 text-xs font-semibold rounded-lg flex items-center gap-3 transition-all duration-150 ";
                                    if active {
                                        format!("{base} bg-gradient-to-r from-emerald-500/10 to-teal-500/5 text-[#00d4aa] border border-emerald-500/20 shadow-sm")
                                    } else {
                                        format!("{base} text-slate-400 hover:text-white hover:bg-zinc-900/30 border border-transparent")
                                    }
                                }
                            >
                                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                                </svg>
                                "My Downlines"
                            </a>

                            <a
                                href="/security"
                                class=move || {
                                    let active = active_section.get() == "security";
                                    let base = "w-full py-2.5 px-4 text-xs font-semibold rounded-lg flex items-center gap-3 transition-all duration-150 ";
                                    if active {
                                        format!("{base} bg-gradient-to-r from-emerald-500/10 to-teal-500/5 text-[#00d4aa] border border-emerald-500/20 shadow-sm")
                                    } else {
                                        format!("{base} text-slate-400 hover:text-white hover:bg-zinc-900/30 border border-transparent")
                                    }
                                }
                            >
                                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                </svg>
                                "Device Security"
                            </a>

                            <a
                                href="/linked"
                                class=move || {
                                    let active = active_section.get() == "linked";
                                    let base = "w-full py-2.5 px-4 text-xs font-semibold rounded-lg flex items-center gap-3 transition-all duration-150 ";
                                    if active {
                                        format!("{base} bg-gradient-to-r from-emerald-500/10 to-teal-500/5 text-[#00d4aa] border border-emerald-500/20 shadow-sm")
                                    } else {
                                        format!("{base} text-slate-400 hover:text-white hover:bg-zinc-900/30 border border-transparent")
                                    }
                                }
                            >
                                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                                </svg>
                                "Linked Accounts"
                            </a>

                            <a
                                href="/settings"
                                class=move || {
                                    let active = active_section.get() == "settings";
                                    let base = "w-full py-2.5 px-4 text-xs font-semibold rounded-lg flex items-center gap-3 transition-all duration-150 ";
                                    if active {
                                        format!("{base} bg-gradient-to-r from-emerald-500/10 to-teal-500/5 text-[#00d4aa] border border-emerald-500/20 shadow-sm")
                                    } else {
                                        format!("{base} text-slate-400 hover:text-white hover:bg-zinc-900/30 border border-transparent")
                                    }
                                }
                            >
                                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                                    <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                </svg>
                                "Settings"
                            </a>
                        </nav>
                    </div>

                    // Bottom Sign Out button
                    <div class="pt-6 border-t border-zinc-800/80">
                        <button
                            on:click=move |_| handle_logout()
                            class="w-full py-2 bg-zinc-900/60 hover:bg-red-950/20 text-slate-300 hover:text-red-400 border border-zinc-800 hover:border-red-900/40 font-semibold text-xs rounded-lg transition-all duration-150 flex items-center justify-center gap-2"
                        >
                            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                            </svg>
                            "Sign Out"
                        </button>
                    </div>
                </aside>

                // RIGHT CONTENT PANELS (Instantaneous switching)
                <main class="flex-1 p-6 md:p-10 overflow-y-auto space-y-8 min-h-screen">
                    // OVERVIEW DASHBOARD PANEL
                    <Show when=move || active_section.get() == "dashboard">
                        <div class="space-y-8 animate-fadeIn">
                            // Main Welcome message with current date
                            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-zinc-800 pb-5">
                                <div>
                                    <h2 class="text-2xl font-black text-white">"Welcome Back, " {move || dashboard_data.get().user.clone().unwrap_or_default().username} "!"</h2>
                                    <p class="text-xs text-slate-400">"Your financial progression, matrix, and security dashboard is fully active."</p>
                                </div>
                                <span class="text-xs font-semibold text-[#00d4aa] px-3 py-1 bg-[#00d4aa]/10 rounded-full border border-[#00d4aa]/20 self-start sm:self-auto">
                                    "Platform Connected"
                                </span>
                            </div>

                            // Stat Cards Grid
                            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
                                // 1. Total Earnings
                                <div class="bg-gradient-to-br from-emerald-500/10 to-teal-500/5 border border-emerald-500/20 rounded-2xl p-5 relative overflow-hidden group hover:border-emerald-500/40 transition-all duration-300">
                                    <div class="absolute -top-12 -right-12 w-24 h-24 bg-[#00d4aa]/5 rounded-full blur-2xl group-hover:bg-[#00d4aa]/10 transition-all"></div>
                                    <p class="text-[10px] uppercase font-bold tracking-widest text-slate-400">"Total Earnings"</p>
                                    <p class="text-2xl font-black text-emerald-400 mt-2">
                                        "$" {move || format!("{:.2}", dashboard_data.get().total_earnings)}
                                    </p>
                                    <div class="text-[9px] text-slate-400 mt-1">"Accumulated from all completions"</div>
                                </div>

                                // 2. Total Payouts
                                <div class="bg-gradient-to-br from-cyan-500/10 to-blue-500/5 border border-cyan-500/20 rounded-2xl p-5 relative overflow-hidden group hover:border-cyan-500/40 transition-all duration-300">
                                    <div class="absolute -top-12 -right-12 w-24 h-24 bg-cyan-500/5 rounded-full blur-2xl group-hover:bg-cyan-500/10 transition-all"></div>
                                    <p class="text-[10px] uppercase font-bold tracking-widest text-slate-400">"Available Payouts"</p>
                                    <p class="text-2xl font-black text-cyan-400 mt-2">
                                        "$" {move || format!("{:.2}", dashboard_data.get().total_payouts)}
                                    </p>
                                    <div class="text-[9px] text-slate-400 mt-1">"80% available for immediate release"</div>
                                </div>

                                // 3. Referred Downlines
                                <div class="bg-gradient-to-br from-purple-500/10 to-indigo-500/5 border border-purple-500/20 rounded-2xl p-5 relative overflow-hidden group hover:border-purple-500/40 transition-all duration-300">
                                    <div class="absolute -top-12 -right-12 w-24 h-24 bg-purple-500/5 rounded-full blur-2xl group-hover:bg-purple-500/10 transition-all"></div>
                                    <p class="text-[10px] uppercase font-bold tracking-widest text-slate-400">"Direct Referrals"</p>
                                    <p class="text-2xl font-black text-purple-400 mt-2">
                                        {move || dashboard_data.get().referrals_count} " Members"
                                    </p>
                                    <div class="text-[9px] text-slate-400 mt-1">"Active users registered in matrix"</div>
                                </div>

                                // 4. Weekly Pot Bonus Pool
                                <div class="bg-gradient-to-br from-amber-500/10 to-orange-500/5 border border-amber-500/20 rounded-2xl p-5 relative overflow-hidden group hover:border-amber-500/40 transition-all duration-300">
                                    <div class="absolute -top-12 -right-12 w-24 h-24 bg-amber-500/5 rounded-full blur-2xl group-hover:bg-amber-500/10 transition-all"></div>
                                    <p class="text-[10px] uppercase font-bold tracking-widest text-slate-400">"Pot Bonus Pool"</p>
                                    <p class="text-2xl font-black text-amber-400 mt-2">
                                        "$" {move || format!("{:.2}", dashboard_data.get().pot_bonus_amount)}
                                    </p>
                                    <div class="flex items-center gap-1.5 mt-1.5">
                                        <span class="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse"></span>
                                        <span class="text-[9px] text-slate-300 font-medium">"Dual Qualification Pending"</span>
                                    </div>
                                </div>
                            </div>

                            // Secondary Widgets Layout
                            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                                // Quick Action Widget: Copy Referral Invitation Link
                                <div class="lg:col-span-2 bg-[#111827] border border-zinc-800 rounded-2xl p-6 space-y-4">
                                    <h3 class="text-sm font-bold text-white uppercase tracking-wider">"Quick Action: Direct Referral Program"</h3>
                                    <p class="text-xs text-slate-400 leading-relaxed">
                                        "Share your secure referral link with downline candidates. Once registered, they will instantly enter Slot positions in your Matrix tree and fuel your next financial graduation!"
                                    </p>

                                    <div class="flex gap-2">
                                        <div class="flex-1 px-4 py-2.5 bg-zinc-950 border border-zinc-800 rounded-lg text-xs font-mono text-slate-300 select-all truncate">
                                            {move || {
                                                let account_id = dashboard_data.get().flushline.map(|fl| fl.id.to_string()).unwrap_or_default();
                                                format!("http://localhost:4000/?sponsor_id={}", account_id)
                                            }}
                                        </div>
                                        <button
                                            on:click=move |_| {
                                                set_copied.set(true);
                                                // Simulating browser copying
                                                #[cfg(feature = "hydrate")]
                                                {
                                                    if let Some(window) = web_sys::window() {
                                                        let navigator = window.navigator().clipboard();
                                                        let account_id = dashboard_data.get().flushline.map(|fl| fl.id.to_string()).unwrap_or_default();
                                                        let link = format!("http://localhost:4000/?sponsor_id={}", account_id);
                                                        let _ = navigator.write_text(&link);
                                                    }
                                                }
                                                leptos::task::spawn_local(async move {
                                                    sleep_delay(std::time::Duration::from_secs(2)).await;
                                                    set_copied.set(false);
                                                });
                                            }
                                            class="px-4 py-2 bg-[#00d4aa] hover:bg-emerald-500 text-[#0b0f19] text-xs font-bold rounded-lg transition-all flex items-center justify-center gap-1.5 shrink-0"
                                        >
                                            <Show when=move || copied.get() fallback=|| view! { <span>"Copy Link"</span> }>
                                                <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3">
                                                    <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
                                                </svg>
                                                <span>"Copied!"</span>
                                            </Show>
                                        </button>
                                    </div>
                                </div>

                                // Recent Activity Timeline Widget
                                <div class="lg:col-span-1 bg-[#111827] border border-zinc-800 rounded-2xl p-6 space-y-4 flex flex-col justify-start">
                                    <h3 class="text-sm font-bold text-white uppercase tracking-wider">"Platform Activity Log"</h3>

                                    <div class="space-y-4 flex-1">
                                        <div class="flex gap-3 items-start text-xs">
                                            <div class="w-2 h-2 rounded-full bg-emerald-400 mt-1.5 shrink-0"></div>
                                            <div>
                                                <p class="font-semibold text-slate-200">"Authenticated via Passkey"</p>
                                                <p class="text-[10px] text-slate-400">"Touch ID login accepted"</p>
                                            </div>
                                        </div>
                                        <div class="flex gap-3 items-start text-xs">
                                            <div class="w-2 h-2 rounded-full bg-cyan-400 mt-1.5 shrink-0"></div>
                                            <div>
                                                <p class="font-semibold text-slate-200">"Device whitelisted"</p>
                                                <p class="text-[10px] text-slate-400">"Primary workstation whitelisted"</p>
                                            </div>
                                        </div>
                                        <div class="flex gap-3 items-start text-xs">
                                            <div class="w-2 h-2 rounded-full bg-purple-400 mt-1.5 shrink-0"></div>
                                            <div>
                                                <p class="font-semibold text-slate-200">"Matrix Tree Loaded"</p>
                                                <p class="text-[10px] text-slate-400">"Tree coordinates validated"</p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </Show>

                    // FLUSHLINE PROGRESSION ENGINE PANEL
                    <Show when=move || active_section.get() == "flushline">
                        <div class="space-y-6 animate-fadeIn lg:h-[calc(100vh-80px)] lg:flex lg:flex-col lg:min-h-0 lg:overflow-hidden">
                            // Redesigned Header: Shows Title & Weekly Pot Bonus Pool
                            <div class="border-b border-zinc-800 pb-5 flex flex-col md:flex-row md:items-center md:justify-between gap-4 shrink-0">
                                <div>
                                    <h2 class="text-2xl font-black text-white">"Flushline Progression Engine"</h2>
                                    <p class="text-xs text-slate-400">"Multi-Account neon pipeline timeline & cycle progression status."</p>
                                </div>
                                <div class="bg-gradient-to-r from-amber-500/10 via-amber-500/5 to-zinc-900 border border-amber-500/20 rounded-2xl px-5 py-3 flex items-center gap-5 shadow-lg shadow-amber-500/5">
                                    <div class="w-10 h-10 rounded-full bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-xl shrink-0 animate-pulse">
                                        "💰"
                                    </div>
                                    <div class="flex items-center gap-6">
                                        <div>
                                            <div class="text-[9px] font-bold text-slate-400 uppercase tracking-widest">"Weekly Pot Pool"</div>
                                            <div class="text-lg font-black text-amber-400 mt-0.5">
                                                "$" {move || format!("{:.2}", dashboard_data.get().pot_bonus_amount)}
                                            </div>
                                        </div>
                                        <div class="h-8 w-px bg-zinc-800"></div>
                                        <div>
                                            <div class="text-[9px] font-bold text-slate-400 uppercase tracking-widest">"Draw Countdown"</div>
                                            <div class="text-sm font-mono font-black text-[#00d4aa] mt-1 bg-[#00d4aa]/10 border border-[#00d4aa]/20 px-2.5 py-1 rounded-lg">
                                                {move || time_left.get()}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div class="grid grid-cols-1 lg:grid-cols-4 gap-8 lg:flex-1 lg:min-h-0">
                                // 1. Left Sidebar: Interactive Combobox and Account Stats Summary
                                <div class="lg:col-span-1 bg-[#111827]/80 backdrop-blur-md border border-zinc-800/80 rounded-2xl p-5 space-y-5 flex flex-col shadow-xl">
                                    <div class="space-y-1.5">
                                        <h3 class="text-xs font-black text-slate-400 uppercase tracking-wider">"Select Account"</h3>
                                        <p class="text-[10px] text-slate-500">"Type or use Arrow Up/Down & Enter to select"</p>
                                    </div>

                                    // Searchable Combobox Component
                                    <div class="relative">
                                        <div class="relative">
                                            <input
                                                type="text"
                                                placeholder="Search accounts..."
                                                class="w-full px-3.5 py-2.5 bg-zinc-950/80 border border-zinc-800/80 focus:border-[#00d4aa] focus:ring-1 focus:ring-[#00d4aa] rounded-xl text-xs text-white outline-none transition-all placeholder-slate-500 pr-10"
                                                on:focus=move |_| set_combobox_open.set(true)
                                                on:blur=move |_| {
                                                    set_combobox_open.set(false);
                                                }
                                                on:input=move |ev| {
                                                    set_combobox_query.set(event_target_value(&ev));
                                                    set_combobox_open.set(true);
                                                }
                                                on:keydown=handle_combobox_keydown
                                                prop:value=combobox_query
                                            />
                                            <div class="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                                                <svg class="h-4 w-4 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                                                </svg>
                                            </div>
                                        </div>

                                        // Floating Option Dropdown
                                        <Show when=move || combobox_open.get() && !filtered_accounts().is_empty()>
                                            <div class="absolute z-50 mt-1.5 w-full bg-zinc-900 border border-zinc-800 rounded-xl shadow-2xl overflow-hidden max-h-60 overflow-y-auto">
                                                {move || {
                                                    let list = filtered_accounts();
                                                    let highlighted_idx = combobox_highlighted.get();
                                                    list.into_iter().enumerate().map(|(idx, acc)| {
                                                        let is_highlighted = idx == highlighted_idx;
                                                        let is_selected = selected_account_id.get() == Some(acc.id);
                                                        let label = acc.label.clone();
                                                        let id = acc.id;
                                                        let tier = acc.tier.clone();
                                                        
                                                        view! {
                                                            <div
                                                                on:mousedown=move |ev| {
                                                                    ev.prevent_default(); // bypasses input blur
                                                                    handle_option_select(id, label.clone());
                                                                }
                                                                class=move || {
                                                                    let bg = if is_selected {
                                                                        "bg-emerald-950/50 text-[#00d4aa] border-l-2 border-[#00d4aa]"
                                                                    } else if is_highlighted {
                                                                        "bg-zinc-800 text-white"
                                                                    } else {
                                                                        "text-slate-300 hover:bg-zinc-800/40 hover:text-white"
                                                                    };
                                                                    format!("px-4 py-3 text-xs cursor-pointer transition-all flex items-center justify-between {}", bg)
                                                                }
                                                            >
                                                                <div class="flex flex-col gap-0.5">
                                                                    <span class="font-bold">{acc.label.clone()}</span>
                                                                    <span class="text-[10px] text-slate-500">"Tier: " {tier} " | " {acc.current_pts} " pts"</span>
                                                                </div>
                                                                <Show when=move || acc.graduated>
                                                                    <span class="text-[8px] bg-amber-500/10 text-amber-400 border border-amber-500/20 px-1.5 py-0.5 rounded font-bold">"GRADUATED"</span>
                                                                </Show>
                                                            </div>
                                                        }
                                                    }).collect_view()
                                                }}
                                            </div>
                                        </Show>
                                    </div>

                                    // Account Details Summary (below the combobox selector)
                                    <div class="border-t border-zinc-800/80 pt-4 flex-1 flex flex-col gap-4">
                                        {move || {
                                            let data = dashboard_data.get();
                                            let sel_id_opt = selected_account_id.get();
                                            if let Some(acc) = data.accounts.iter().find(|acc| Some(acc.id) == sel_id_opt).cloned() {
                                                view! {
                                                                                    <div class="space-y-4 animate-fadeIn">
                                                        <div class="bg-zinc-950/40 border border-zinc-800/60 rounded-xl p-3.5 space-y-2.5">
                                                            <div class="flex justify-between items-center text-[10px] text-slate-400 font-bold uppercase tracking-wider">
                                                                <span>"Account Details"</span>
                                                                <Show when=move || acc.graduated>
                                                                    <span class="bg-amber-500/10 text-amber-400 border border-amber-500/30 px-1.5 py-0.5 rounded-full text-[8px] font-black">"GRADUATED"</span>
                                                                </Show>
                                                            </div>
                                                            <div class="space-y-1.5">
                                                                <div class="flex justify-between text-xs">
                                                                    <span class="text-slate-500">"Label:"</span>
                                                                    <span class="font-bold text-white">{acc.label.clone()}</span>
                                                                </div>
                                                                <div class="flex justify-between text-xs">
                                                                    <span class="text-slate-500">"Current Tier:"</span>
                                                                    <span class="font-black text-[#00d4aa]">{acc.tier.clone()}</span>
                                                                </div>
                                                                <div class="flex justify-between text-xs">
                                                                    <span class="text-slate-500">"Total Points:"</span>
                                                                    <span class="font-bold text-slate-200">{acc.current_pts} " pts"</span>
                                                                </div>
                                                                <div class="flex justify-between text-xs">
                                                                    <span class="text-slate-500">"royalflush cycle:"</span>
                                                                    <span class="font-bold text-slate-200">{acc.cycle_count}</span>
                                                                </div>
                                                            </div>
                                                        </div>

                                                        <div class="bg-zinc-950/40 border border-zinc-800/60 rounded-xl p-3.5 space-y-3">
                                                            <div class="text-[10px] text-slate-400 font-bold uppercase tracking-wider">"Pot Qualifications"</div>
                                                            <div class="flex items-center gap-2.5">
                                                                <div class=move || {
                                                                    let bg = if acc.is_pot_qualified { "bg-amber-500/10 text-amber-400 border-amber-500/30" } else { "bg-zinc-900 text-slate-500 border-zinc-800" };
                                                                    format!("w-5 h-5 rounded-full border flex items-center justify-center text-xs {}", bg)
                                                                }>
                                                                    {if acc.is_pot_qualified { "✓" } else { "✗" }}
                                                                </div>
                                                                <div class="flex-1 min-w-0">
                                                                    <div class="text-xs font-bold text-white">
                                                                        {if acc.is_pot_qualified { "Pot Qualified" } else { "Pending Graduation" }}
                                                                    </div>
                                                                    <div class="text-[9px] text-slate-500 truncate">
                                                                        {if acc.is_pot_qualified { "Ready for weekly distribution" } else { "Complete Ace + Matrix cycle" }}
                                                                    </div>
                                                                </div>
                                                            </div>
                                                            <div class="border-t border-zinc-800/60 pt-2.5 space-y-2 text-[10px]">
                                                                <div class="flex justify-between">
                                                                    <span class="text-slate-500">"Shared 75% Shares:"</span>
                                                                    <span class="font-bold text-slate-300">{acc.cycle_count} " / " {move || dashboard_data.get().total_system_shares} " total"</span>
                                                                </div>
                                                                <div class="flex justify-between">
                                                                    <span class="text-slate-500">"Est. Shared Payout:"</span>
                                                                    <span class="font-bold text-emerald-400">"$" {move || format!("{:.2}", dashboard_data.get().user_shared_payout)}</span>
                                                                </div>
                                                                <div class="flex justify-between">
                                                                    <span class="text-slate-500">"Selective 25% Qual:"</span>
                                                                    <span class=move || {
                                                                        let is_qualified = acc.graduated && acc.cycle_count >= dashboard_data.get().pot_bonus_config.selective_min_shares;
                                                                        if is_qualified { "font-bold text-purple-400" } else { "text-slate-500" }
                                                                    }>
                                                                        {move || {
                                                                            let is_qualified = acc.graduated && acc.cycle_count >= dashboard_data.get().pot_bonus_config.selective_min_shares;
                                                                            if is_qualified { "QUALIFIED" } else { "NOT QUALIFIED" }
                                                                        }}
                                                                    </span>
                                                                </div>
                                                                <div class="flex justify-between">
                                                                    <span class="text-slate-500">"Est. Selective Payout:"</span>
                                                                    <span class="font-bold text-purple-400">"$" {move || format!("{:.2}", dashboard_data.get().user_selective_payout)}</span>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    </div>
                                                }.into_any()
                                            } else {
                                                view! {
                                                    <div class="text-center text-xs text-slate-500 py-8">
                                                        "No account selected."
                                                    </div>
                                                }.into_any()
                                            }
                                        }}
                                    </div>
                                </div>

                                // 2. Right Middle/Main Panel: Stitch Tactical Console Redesign
                                <div class="lg:col-span-3 space-y-6 flex flex-col min-h-0 lg:h-full lg:overflow-hidden">
                                    {move || {
                                        let data = dashboard_data.get();
                                        let sel_id_opt = selected_account_id.get();
                                        let account_progress = data.accounts.iter().find(|acc| Some(acc.id) == sel_id_opt).cloned();
                                        
                                        if let Some(acc) = account_progress {
                                            view! {
                                                <div class="space-y-6 animate-fadeIn min-h-0 lg:flex-1 lg:flex lg:flex-col lg:overflow-hidden">
                                                    // STRATEGIC_TIERS Compact Row Section
                                                    <section class="shrink-0 bg-[#0b1326] border border-zinc-800 rounded-2xl p-5 shadow-2xl">
                                                        <div class="flex items-center justify-between mb-4 px-1">
                                                            <div class="flex items-center gap-2">
                                                                <span class="text-xs text-emerald-400 font-bold tracking-widest uppercase">"STRATEGIC_TIERS"</span>
                                                            </div>
                                                            <div class="font-mono text-[10px] text-slate-400 uppercase">
                                                                "Active: " {acc.tier.clone()} "_FLOW"
                                                            </div>
                                                        </div>
                                                        
                                                        <div class="grid grid-cols-5 gap-3">
                                                            {["Ten", "Jack", "Queen", "King", "Ace"].into_iter().map(|tier_name| {
                                                                let acc_cloned = acc.clone();
                                                                let tier_order = |t: &str| match t {
                                                                    "Ten" => 1,
                                                                    "Jack" => 2,
                                                                    "Queen" => 3,
                                                                    "King" => 4,
                                                                    "Ace" => 5,
                                                                    _ => 0,
                                                                };
                                                                
                                                                let active_val = tier_order(&acc_cloned.tier);
                                                                let card_val = tier_order(tier_name);
                                                                
                                                                let is_active = active_val == card_val && !acc_cloned.graduated;
                                                                let is_passed = acc_cloned.graduated || (active_val > card_val);
                                                                let is_locked = !is_active && !is_passed;
                                                                
                                                                let tier_label = match tier_name {
                                                                    "Ten" => "10",
                                                                    "Jack" => "J",
                                                                    "Queen" => "Q",
                                                                    "King" => "K",
                                                                    "Ace" => "A",
                                                                    _ => "",
                                                                };

                                                                let _tier_display_name = match tier_name {
                                                                    "Ten" => "TEN",
                                                                    "Jack" => "JACK",
                                                                    "Queen" => "QUEEN",
                                                                    "King" => "KING",
                                                                    "Ace" => "ACE",
                                                                    _ => "",
                                                                };

                                                                let (tier_pts_val, tier_threshold_val) = if is_passed {
                                                                    let t = match tier_name {
                                                                        "Ten" => 1,
                                                                        "Jack" => 2,
                                                                        "Queen" => 3,
                                                                        "King" => 4,
                                                                        "Ace" => 5,
                                                                        _ => 5,
                                                                    };
                                                                    (t, t)
                                                                } else if is_active {
                                                                    (acc_cloned.tier_pts, acc_cloned.tier_threshold)
                                                                } else {
                                                                    let t = match tier_name {
                                                                        "Ten" => 1,
                                                                        "Jack" => 2,
                                                                        "Queen" => 3,
                                                                        "King" => 4,
                                                                        "Ace" => 5,
                                                                        _ => 5,
                                                                    };
                                                                    (0, t)
                                                                };

                                                                let fill_pct = ((tier_pts_val as f32) / (tier_threshold_val as f32) * 100.0).min(100.0).max(0.0);
                                                                let queue_pos = acc_cloned.queue_position;
                                                                let has_queue_pos = queue_pos > 0;

                                                                let data_val = dashboard_data.get();
                                                                let queue_info = data_val.tier_queues.iter().find(|t| t.tier_name == tier_name);
                                                                let top_owner = queue_info.and_then(|q| q.top_card_owner.clone());
                                                                let top_owner_str = top_owner.unwrap_or_else(|| "None".to_string());
                                                                
                                                                let top_owner_passed = top_owner_str.clone();
                                                                let top_owner_active = top_owner_str.clone();
                                                                let top_owner_locked = top_owner_str.clone();

                                                                view! {
                                                                    <div>
                                                                        <Show when=move || is_passed>
                                                                            <div class="border border-zinc-800 bg-zinc-900/40 p-3.5 flex flex-col h-28 relative overflow-hidden opacity-75 rounded-xl transition-all duration-300">
                                                                                <div class="flex justify-between items-start">
                                                                                    <span class="font-mono text-sm text-slate-400">{tier_label}</span>
                                                                                    <span class="text-emerald-400 text-xs font-bold">"✓"</span>
                                                                                </div>
                                                                                <div class="mt-auto">
                                                                                    <div class="text-[10px] text-slate-300 truncate font-mono">"Top: " <span class="font-bold text-slate-400">{top_owner_passed.clone()}</span></div>
                                                                                    <div class="text-[8px] font-mono text-emerald-400 tracking-tighter uppercase mt-1">"CYCLED"</div>
                                                                                </div>
                                                                            </div>
                                                                        </Show>
                                                                        <Show when=move || is_active>
                                                                            <div class="border border-[#00d4aa]/40 bg-[#090e1a] p-3.5 flex flex-col h-28 relative overflow-hidden active-glow rounded-xl shadow-[0_0_20px_rgba(0,212,170,0.15)] transition-all duration-300">
                                                                                <div class="flex justify-between items-start">
                                                                                    <span class="font-mono text-sm text-[#00d4aa] font-bold">{tier_label}</span>
                                                                                    <Show when=move || has_queue_pos>
                                                                                        <div class="text-right">
                                                                                            <span class="text-[8px] font-mono text-[#00d4aa]/60 block">"POS"</span>
                                                                                            <span class="text-xs font-mono text-[#00d4aa] font-bold">"#" {queue_pos}</span>
                                                                                        </div>
                                                                                    </Show>
                                                                                </div>
                                                                                <div class="mt-auto space-y-1.5">
                                                                                    <div class="text-[10px] text-slate-200 truncate font-mono">"Top: " <span class="font-bold text-[#00d4aa]">{top_owner_active.clone()}</span></div>
                                                                                    <div class="space-y-1">
                                                                                        <div class="flex justify-between text-[8px] font-mono text-[#00d4aa]/70">
                                                                                            <span>"PROGRESS"</span>
                                                                                            <span>{tier_pts_val} " / " {tier_threshold_val} " PTS"</span>
                                                                                        </div>
                                                                                        <div class="h-1 w-full bg-zinc-950 rounded-full overflow-hidden">
                                                                                            <div class="h-full bg-[#00d4aa]" style:width=format!("{}%", fill_pct)></div>
                                                                                        </div>
                                                                                    </div>
                                                                                </div>
                                                                            </div>
                                                                        </Show>
                                                                        <Show when=move || is_locked>
                                                                            <div class="border border-zinc-850 bg-zinc-950/40 p-3.5 flex flex-col h-28 relative overflow-hidden opacity-40 grayscale rounded-xl transition-all duration-300">
                                                                                <div class="flex justify-between items-start">
                                                                                    <span class="font-mono text-sm text-slate-500">{tier_label}</span>
                                                                                    <span class="text-slate-500 text-xs">"🔒"</span>
                                                                                </div>
                                                                                <div class="mt-auto">
                                                                                    <div class="text-[10px] text-slate-500 truncate font-mono">"Top: " <span class="font-bold text-slate-500">{top_owner_locked.clone()}</span></div>
                                                                                    <div class="text-[8px] font-mono text-slate-500 tracking-tighter uppercase mt-1">"LOCKED"</div>
                                                                                </div>
                                                                            </div>
                                                                        </Show>
                                                                    </div>
                                                                }
                                                            }).collect_view()}
                                                        </div>
                                                    </section>
                                                    
                                                    // Middle Row: Pot (8 cols) & Top Entities (4 cols)
                                                    <div class="grid grid-cols-12 gap-6 min-h-0 lg:flex-1">
                                                        // Aggregate Pot & Live Logs
                                                        <div class="col-span-8 flex flex-col gap-6 min-h-0 lg:h-full">
                                                            // 3-Card Pot Row: Replace single pot widget with three premium cards
                                                            <div class="grid grid-cols-3 gap-4 shrink-0">
                                                                // Card 1: Total Pool (100%)
                                                                <section class="border border-zinc-800 bg-[#0b1326] p-4 relative overflow-hidden rounded-2xl flex flex-col justify-center min-h-[140px]">
                                                                    <div class="relative z-10">
                                                                        <div class="font-mono text-[9px] text-slate-400 tracking-[0.15em] mb-1">"TOTAL_POT_POOL (100%)"</div>
                                                                        <div class="font-mono text-2xl lg:text-3xl text-white font-bold tracking-tight">
                                                                            "$" {move || format!("{:.2}", dashboard_data.get().pot_bonus_amount)}
                                                                        </div>
                                                                    </div>
                                                                </section>

                                                                // Card 2: Shared Liquidity (75%)
                                                                <section class="border border-zinc-800 bg-[#061e1b] p-4 relative overflow-hidden rounded-2xl flex flex-col justify-between min-h-[140px]">
                                                                    <div class="relative z-10">
                                                                        <div class="font-mono text-[9px] text-[#00d4aa] tracking-[0.15em] mb-1">"SHARED_LIQUIDITY (75%)"</div>
                                                                        <div class="font-mono text-2xl lg:text-3xl text-[#4edea3] font-bold tracking-tight">
                                                                            "$" {move || format!("{:.2}", dashboard_data.get().pot_bonus_amount * 0.75)}
                                                                        </div>
                                                                    </div>
                                                                    <div class="mt-4 pt-3 border-t border-[#00d4aa]/20 relative z-10">
                                                                        <div class="h-1 w-full bg-zinc-950 rounded-full overflow-hidden mb-1">
                                                                            <div class="h-full bg-[#00d4aa] w-3/4"></div>
                                                                        </div>
                                                                        <div class="flex justify-between text-[8px] font-mono text-slate-400">
                                                                            <span>"EST_DIST_SHARES"</span>
                                                                            <span class="text-[#00d4aa]">{move || dashboard_data.get().total_system_shares}</span>
                                                                        </div>
                                                                    </div>
                                                                </section>

                                                                // Card 3: Selective Incentive (25%)
                                                                <section class="border border-zinc-800 bg-[#120a21] p-4 relative overflow-hidden rounded-2xl flex flex-col justify-between min-h-[140px]">
                                                                    <div class="relative z-10">
                                                                        <div class="font-mono text-[9px] text-purple-400 tracking-[0.15em] mb-1">"SELECTIVE_INCENTIVE (25%)"</div>
                                                                        <div class="font-mono text-2xl lg:text-3xl text-purple-300 font-bold tracking-tight">
                                                                            "$" {move || format!("{:.2}", dashboard_data.get().pot_bonus_amount * 0.25)}
                                                                        </div>
                                                                    </div>
                                                                    <div class="mt-4 pt-3 border-t border-purple-900/40 relative z-10">
                                                                        <div class="h-1 w-full bg-zinc-950 rounded-full overflow-hidden mb-1">
                                                                            <div class="h-full bg-purple-500 w-1/4"></div>
                                                                        </div>
                                                                        <div class="flex justify-between text-[8px] font-mono text-slate-400">
                                                                            <span>"RULE"</span>
                                                                            <span class="text-purple-400 uppercase">{move || dashboard_data.get().pot_bonus_config.selective_rule.clone()}</span>
                                                                        </div>
                                                                    </div>
                                                                </section>
                                                            </div>
                                                            
                                                            // Live Network Stream Log Terminal
                                                            <section class="border border-zinc-800 bg-[#03060b] flex flex-col min-h-0 flex-1 rounded-2xl overflow-hidden shadow-xl">
                                                                <div class="px-4 py-2 border-b border-zinc-800 flex justify-between items-center bg-[#090e1a]/80">
                                                                    <div class="flex items-center gap-2">
                                                                        <span class="w-1.5 h-1.5 bg-[#00d4aa] rounded-full animate-pulse"></span>
                                                                        <h3 class="font-mono text-[10px] text-white font-bold uppercase tracking-wider">"LIVE_NETWORK_STREAM"</h3>
                                                                    </div>
                                                                    <span class="text-[8px] font-mono text-[#00d4aa]/60">"T_SECURE_ENCRYPTED"</span>
                                                                </div>
                                                                <div class="flex-1 overflow-y-auto p-4 font-mono text-[10px] space-y-1.5">
                                                                    {move || {
                                                                        let events = dashboard_data.get().graduation_events;
                                                                        if events.is_empty() {
                                                                            view! {
                                                                                <div class="flex gap-3 items-baseline p-1 rounded font-mono text-[10px] text-sky-400">
                                                                                    <span class="text-zinc-600 shrink-0">"SYSTEM"</span>
                                                                                    <span class="font-bold">"[INFO]"</span>
                                                                                    <span class="text-sky-300">"Listening for graduation events on the neon pipeline..."</span>
                                                                                </div>
                                                                            }.into_any()
                                                                        } else {
                                                                            events.into_iter().rev().map(|event| {
                                                                                let time_str = event.timestamp.format("%H:%M:%S").to_string();
                                                                                let msg = format!("Account {} completed {} tier (Royal Flush Cycle #{})", event.username, event.tier, event.cycle_count);
                                                                                view! {
                                                                                    <div class="flex gap-3 items-baseline hover:bg-zinc-800/20 transition-colors p-1 rounded font-mono text-[10px]">
                                                                                        <span class="text-zinc-600 shrink-0">{time_str}</span>
                                                                                        <span class="text-emerald-400 font-bold">"[GRADUATION]"</span>
                                                                                        <span class="text-slate-300">{msg}</span>
                                                                                    </div>
                                                                                }
                                                                            }).collect_view().into_any()
                                                                        }
                                                                    }}
                                                                </div>
                                                            </section>
                                                        </div>
                                                        
                                                        // Top Entities Leaderboard (Right Side - Vertical)
                                                        <div class="col-span-4 flex flex-col min-h-0 lg:h-full">
                                                            <section class="border border-zinc-800 bg-[#0b1326] flex flex-col h-full rounded-2xl overflow-hidden shadow-2xl">
                                                                <div class="p-4 border-b border-zinc-800 flex justify-between items-center bg-[#090e1a]/80">
                                                                    <h3 class="font-mono text-[11px] text-white font-bold tracking-wider">"TOP_ENTITIES"</h3>
                                                                    <div class="px-1.5 py-0.5 border border-[#00d4aa]/30 rounded-lg text-[8px] text-[#00d4aa] font-bold uppercase tracking-wider">
                                                                        "TOP_PERFORMERS"
                                                                    </div>
                                                                </div>
                                                                // Table Header
                                                                <div class="grid grid-cols-[40px_1fr_60px_80px] gap-2 px-4 py-2 border-b border-zinc-800/40 bg-zinc-950 font-mono text-[8px] text-slate-500 uppercase">
                                                                    <div>"RK"</div>
                                                                    <div>"ENTITY_ID"</div>
                                                                    <div class="text-right">"CYC"</div>
                                                                    <div class="text-right">"VAL_EQ"</div>
                                                                </div>
                                                                // Leaderboard Scroll List
                                                                <div class="overflow-y-auto flex-1 font-mono text-xs">
                                                                    {move || {
                                                                        let data = dashboard_data.get();
                                                                        let mut entries = Vec::new();
                                                                        
                                                                        // Add user sub-accounts
                                                                        for acc in &data.accounts {
                                                                            let cycles = acc.cycle_count;
                                                                            let val_eq = cycles as f64 * 500.0;
                                                                            entries.push((
                                                                                acc.label.clone(),
                                                                                cycles,
                                                                                format!("${:.1}k", val_eq / 1000.0),
                                                                            ));
                                                                        }
                                                                        
                                                                        // Add referrals
                                                                        for r in &data.referrals {
                                                                            let cycles = match r.tier.as_str() {
                                                                                "Ace" => 5,
                                                                                "King" => 4,
                                                                                "Queen" => 3,
                                                                                "Jack" => 2,
                                                                                _ => 1,
                                                                            } + if r.active { 1 } else { 0 };
                                                                            let val_eq = cycles as f64 * 500.0;
                                                                            entries.push((
                                                                                r.username.clone(),
                                                                                cycles,
                                                                                format!("${:.1}k", val_eq / 1000.0),
                                                                            ));
                                                                        }
                                                                        
                                                                        // Sort by cycles descending
                                                                        entries.sort_by(|a, b| b.1.cmp(&a.1));
                                                                        
                                                                        entries.into_iter().enumerate().take(6).map(|(idx, (name, cycles, val_eq_str))| {
                                                                            let rank = idx + 1;
                                                                            let rank_str = format!("{:02}", rank);
                                                                            let rank_class = if rank == 1 {
                                                                                "text-[#00d4aa] font-bold"
                                                                            } else {
                                                                                "text-slate-500 font-bold"
                                                                            };
                                                                            let row_bg = if rank == 1 {
                                                                                "bg-[#00d4aa]/5 border-l-2 border-[#00d4aa]"
                                                                            } else {
                                                                                "hover:bg-zinc-800/10 border-b border-zinc-800/10"
                                                                            };
                                                                            view! {
                                                                                <div class=format!("grid grid-cols-[40px_1fr_60px_80px] gap-2 px-4 py-2.5 items-center transition-colors {}", row_bg)>
                                                                                    <div class=rank_class>{rank_str}</div>
                                                                                    <div class="text-slate-300 font-medium truncate text-[11px] font-mono">{name}</div>
                                                                                    <div class="text-slate-400 text-right text-[11px] font-mono">{cycles} "x"</div>
                                                                                    <div class=format!("font-bold text-right text-[11px] font-mono {}", if rank == 1 { "text-[#00d4aa]" } else { "text-slate-400" })>{val_eq_str}</div>
                                                                                </div>
                                                                            }
                                                                        }).collect_view()
                                                                    }}
                                                                </div>
                                                            </section>
                                                        </div>
                                                    </div>
                                                    
                                                    // Footer Live Ticker removed
                                                </div>
                                            }.into_any()
                                        } else {
                                            view! {
                                                <div class="bg-[#111827] border border-zinc-800 rounded-2xl p-12 text-center text-slate-400 shadow-xl">
                                                    "Select an account from the sidebar search box to view progression timeline."
                                                </div>
                                            }.into_any()
                                        }
                                    }}
                                </div>
                            </div>
                        </div>
                    </Show>

                    // MATRIX TREE GRAPH PANEL
                    // MATRIX TREE GRAPH PANEL
                    <Show when=move || active_section.get() == "matrix">
                        <div class="space-y-8 animate-fadeIn relative">
                            // Backdrop dismissal overlay for dropdowns
                            {move || {
                                if acc_dropdown_open.get() || cycle_dropdown_open.get() {
                                    Some(view! {
                                        <div
                                            class="fixed inset-0 z-40 bg-transparent"
                                            on:click=move |_| {
                                                set_acc_dropdown_open.set(false);
                                                set_cycle_dropdown_open.set(false);
                                            }
                                        />
                                    })
                                } else {
                                    None
                                }
                            }}

                            <div class="border-b border-zinc-800 pb-5">
                                <h2 class="text-2xl font-black text-white">"Forced 2×2 Matrix Tree Visualizer"</h2>
                                <p class="text-xs text-slate-400">"Premium genealogy matches your current 7-slot binary structure (Slots 1 to 7)."</p>
                            </div>

                            <div class="bg-[#111827] border border-zinc-800 rounded-2xl p-8 space-y-6 flex flex-col items-center">
                                // Swapped combobox selectors (Cycle Selection on Left, Account Selection on Right)
                                <div class="flex flex-col sm:flex-row gap-6 w-full justify-between items-center bg-[#070b13]/60 border border-zinc-800/60 rounded-2xl p-6 relative z-50">
                                    <div class="flex flex-col sm:flex-row gap-6 w-full sm:w-auto">
                                        // 1. SELECT CYCLE MATRIX (Left)
                                        <div class="relative w-full sm:w-64 text-left z-50">
                                            <label class="text-[10px] font-bold uppercase text-slate-400 tracking-wider block mb-1.5">"Select Cycle Matrix"</label>
                                            <div class="relative">
                                                <input
                                                    type="text"
                                                    class="w-full px-4 py-2.5 bg-zinc-950 border border-zinc-800 focus:border-[#00d4aa] rounded-xl text-white text-xs outline-none transition-all hover:bg-zinc-900 pr-10 font-bold"
                                                    placeholder=move || {
                                                        let cyc_val = selected_cycle_number.get();
                                                        let opts = matrix_cycle_options.get();
                                                        if let Some(val) = cyc_val {
                                                            opts.iter()
                                                                .find(|o| o.cycle_num as i32 == val)
                                                                .map(|o| o.label.clone())
                                                                .unwrap_or_else(|| format!("Cycle #{}", val))
                                                        } else {
                                                            opts.last().map(|o| o.label.clone()).unwrap_or_else(|| "Select Cycle".to_string())
                                                        }
                                                    }
                                                    prop:value=move || {
                                                        if cycle_dropdown_open.get() {
                                                            cycle_search_query.get()
                                                        } else {
                                                            String::new()
                                                        }
                                                    }
                                                    on:input=move |ev| {
                                                        set_cycle_search_query.set(event_target_value(&ev));
                                                        set_cycle_highlighted_index.set(0);
                                                    }
                                                    on:focus=move |_| {
                                                        set_cycle_dropdown_open.set(true);
                                                        set_acc_dropdown_open.set(false);
                                                        set_cycle_highlighted_index.set(0);
                                                    }
                                                    on:keydown=move |ev| {
                                                        match ev.key().as_str() {
                                                            "ArrowDown" => {
                                                                ev.prevent_default();
                                                                let filtered = filtered_matrix_cycles();
                                                                if !filtered.is_empty() {
                                                                    let current = cycle_highlighted_index.get();
                                                                    let next = (current + 1) % filtered.len();
                                                                    set_cycle_highlighted_index.set(next);
                                                                }
                                                            }
                                                            "ArrowUp" => {
                                                                ev.prevent_default();
                                                                let filtered = filtered_matrix_cycles();
                                                                if !filtered.is_empty() {
                                                                    let current = cycle_highlighted_index.get();
                                                                    let prev = if current == 0 { filtered.len() - 1 } else { current - 1 };
                                                                    set_cycle_highlighted_index.set(prev);
                                                                }
                                                            }
                                                            "Enter" => {
                                                                ev.prevent_default();
                                                                let filtered = filtered_matrix_cycles();
                                                                let idx = cycle_highlighted_index.get();
                                                                if idx < filtered.len() {
                                                                    let opt = &filtered[idx];
                                                                    set_selected_cycle_number.set(Some(opt.cycle_num as i32));
                                                                    set_cycle_dropdown_open.set(false);
                                                                    set_cycle_search_query.set(String::new());
                                                                }
                                                            }
                                                            "Escape" => {
                                                                set_cycle_dropdown_open.set(false);
                                                                set_cycle_search_query.set(String::new());
                                                            }
                                                            _ => {}
                                                        }
                                                    }
                                                />
                                                <div class="absolute inset-y-0 right-3 flex items-center pointer-events-none text-slate-400">
                                                    <svg class="w-4 h-4 transition-transform duration-200" class:rotate-180=move || cycle_dropdown_open.get() fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                                                    </svg>
                                                </div>
                                            </div>
                                            <Show when=move || cycle_dropdown_open.get()>
                                                <div class="absolute mt-2 w-full bg-zinc-900 border border-zinc-800 rounded-xl shadow-2xl z-[80] p-2 space-y-1 max-h-60 overflow-y-auto">
                                                    {move || {
                                                        let filtered = filtered_matrix_cycles();
                                                        if filtered.is_empty() {
                                                            view! {
                                                                <div class="p-2 text-xs text-slate-500 italic text-center">"No cycles found"</div>
                                                            }.into_any()
                                                        } else {
                                                            filtered
                                                                .into_iter()
                                                                .enumerate()
                                                                .map(|(item_idx, opt)| {
                                                                    let is_highlighted = move || cycle_highlighted_index.get() == item_idx;
                                                                    let is_sel = selected_cycle_number.get() == Some(opt.cycle_num as i32);
                                                                    let on_click = move |_| {
                                                                        set_selected_cycle_number.set(Some(opt.cycle_num as i32));
                                                                        set_cycle_dropdown_open.set(false);
                                                                        set_cycle_search_query.set(String::new());
                                                                    };
                                                                    view! {
                                                                        <button
                                                                            on:click=on_click
                                                                            class=move || {
                                                                                let base = "w-full text-left px-3 py-2 text-xs rounded-lg transition-colors font-semibold ";
                                                                                if is_highlighted() {
                                                                                    format!("{base} bg-[#00d4aa] text-[#0b0f19] font-bold")
                                                                                } else if is_sel {
                                                                                    format!("{base} bg-[#00d4aa]/10 text-[#00d4aa] font-bold")
                                                                                } else {
                                                                                    format!("{base} text-slate-300 hover:bg-zinc-800")
                                                                                }
                                                                            }
                                                                        >
                                                                            {opt.label}
                                                                        </button>
                                                                    }.into_any()
                                                                })
                                                                .collect::<Vec<_>>()
                                                                .into_any()
                                                        }
                                                    }}
                                                </div>
                                            </Show>
                                        </div>

                                        // 2. SELECT POSITION ACCOUNT (Right)
                                        <div class="relative w-full sm:w-64 text-left z-50">
                                            <label class="text-[10px] font-bold uppercase text-slate-400 tracking-wider block mb-1.5">"Select Position Account"</label>
                                            <div class="relative">
                                                <input
                                                    type="text"
                                                    class="w-full px-4 py-2.5 bg-zinc-950 border border-zinc-800 focus:border-[#00d4aa] rounded-xl text-white text-xs outline-none transition-all hover:bg-zinc-900 pr-10 font-bold"
                                                    placeholder=move || {
                                                        let acc_id = selected_matrix_account.get();
                                                        let accounts = dashboard_data.get().accounts;
                                                        if let Some(id) = acc_id {
                                                            accounts.iter()
                                                                .find(|a| a.id == id)
                                                                .map(|a| a.label.clone())
                                                                .unwrap_or_else(|| "Select Account".to_string())
                                                        } else {
                                                            "Select Account".to_string()
                                                        }
                                                    }
                                                    prop:value=move || {
                                                        if acc_dropdown_open.get() {
                                                            acc_search_query.get()
                                                        } else {
                                                            String::new()
                                                        }
                                                    }
                                                    on:input=move |ev| {
                                                        set_acc_search_query.set(event_target_value(&ev));
                                                        set_acc_highlighted_index.set(0);
                                                    }
                                                    on:focus=move |_| {
                                                        set_acc_dropdown_open.set(true);
                                                        set_cycle_dropdown_open.set(false);
                                                        set_acc_highlighted_index.set(0);
                                                    }
                                                    on:keydown=move |ev| {
                                                        match ev.key().as_str() {
                                                            "ArrowDown" => {
                                                                ev.prevent_default();
                                                                let filtered = filtered_matrix_accounts();
                                                                if !filtered.is_empty() {
                                                                    let current = acc_highlighted_index.get();
                                                                    let next = (current + 1) % filtered.len();
                                                                    set_acc_highlighted_index.set(next);
                                                                }
                                                            }
                                                            "ArrowUp" => {
                                                                ev.prevent_default();
                                                                let filtered = filtered_matrix_accounts();
                                                                if !filtered.is_empty() {
                                                                    let current = acc_highlighted_index.get();
                                                                    let prev = if current == 0 { filtered.len() - 1 } else { current - 1 };
                                                                    set_acc_highlighted_index.set(prev);
                                                                }
                                                            }
                                                            "Enter" => {
                                                                ev.prevent_default();
                                                                let filtered = filtered_matrix_accounts();
                                                                let idx = acc_highlighted_index.get();
                                                                if idx < filtered.len() {
                                                                    let acc = &filtered[idx];
                                                                    set_selected_matrix_account.set(Some(acc.id));
                                                                    set_selected_cycle_number.set(None);
                                                                    set_acc_dropdown_open.set(false);
                                                                    set_acc_search_query.set(String::new());
                                                                }
                                                            }
                                                            "Escape" => {
                                                                set_acc_dropdown_open.set(false);
                                                                set_acc_search_query.set(String::new());
                                                            }
                                                            _ => {}
                                                        }
                                                    }
                                                />
                                                <div class="absolute inset-y-0 right-3 flex items-center pointer-events-none text-slate-400">
                                                    <svg class="w-4 h-4 transition-transform duration-200" class:rotate-180=move || acc_dropdown_open.get() fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                                                    </svg>
                                                </div>
                                            </div>
                                            <Show when=move || acc_dropdown_open.get()>
                                                <div class="absolute mt-2 w-full bg-zinc-900 border border-zinc-800 rounded-xl shadow-2xl z-[80] p-2 space-y-1 max-h-60 overflow-y-auto">
                                                    {move || {
                                                        let filtered = filtered_matrix_accounts();
                                                        if filtered.is_empty() {
                                                            view! {
                                                                <div class="p-2 text-xs text-slate-500 italic text-center">"No accounts found"</div>
                                                            }.into_any()
                                                        } else {
                                                            filtered
                                                                .into_iter()
                                                                .enumerate()
                                                                .map(|(item_idx, acc)| {
                                                                    let is_highlighted = move || acc_highlighted_index.get() == item_idx;
                                                                    let is_sel = selected_matrix_account.get() == Some(acc.id);
                                                                    let on_click = move |_| {
                                                                        set_selected_matrix_account.set(Some(acc.id));
                                                                        set_selected_cycle_number.set(None);
                                                                        set_acc_dropdown_open.set(false);
                                                                        set_acc_search_query.set(String::new());
                                                                    };
                                                                    view! {
                                                                        <button
                                                                            on:click=on_click
                                                                            class=move || {
                                                                                let base = "w-full text-left px-3 py-2 text-xs rounded-lg transition-colors flex justify-between items-center font-semibold ";
                                                                                if is_highlighted() {
                                                                                    format!("{base} bg-[#00d4aa] text-[#0b0f19] font-bold")
                                                                                } else if is_sel {
                                                                                    format!("{base} bg-[#00d4aa]/10 text-[#00d4aa] font-bold")
                                                                                } else {
                                                                                    format!("{base} text-slate-300 hover:bg-zinc-800")
                                                                                }
                                                                            }
                                                                        >
                                                                            <div class="flex flex-col text-left">
                                                                                <span>{acc.label.clone()}</span>
                                                                                <span class="text-[9px] opacity-80 mt-0.5 font-mono">
                                                                                    {acc.id.to_string().chars().take(8).collect::<String>()}
                                                                                </span>
                                                                            </div>
                                                                        </button>
                                                                    }.into_any()
                                                                })
                                                                .collect::<Vec<_>>()
                                                                .into_any()
                                                        }
                                                    }}
                                                </div>
                                            </Show>
                                        </div>
                                    </div>

                                    <div class="text-right w-full sm:w-auto">
                                        <span class="text-[10px] font-bold uppercase text-slate-400 tracking-wider block mb-1.5">"Completed Cycles"</span>
                                        <span class="text-xs bg-emerald-950 text-emerald-400 border border-emerald-800/60 px-4 py-2 rounded-xl font-bold tracking-wide uppercase">
                                            {move || {
                                                let acc_id = selected_matrix_account.get();
                                                let accounts = dashboard_data.get().accounts;
                                                let cycles = if let Some(id) = acc_id {
                                                    accounts.iter()
                                                        .find(|a| a.id == id)
                                                        .map(|a| a.matrix_cycles)
                                                        .unwrap_or(0)
                                                } else {
                                                    0
                                                };
                                                format!("{} cycles", cycles)
                                            }}
                                        </span>
                                    </div>
                                </div>

                                // High fidelity visual tree
                                <div class="flex flex-col items-center py-8 space-y-12 relative w-full overflow-x-auto min-h-[480px]">
                                    // Slot 1: Root
                                    <div class="relative z-10 flex flex-col items-center">
                                        {render_matrix_node(1, 0)}
                                    </div>

                                    // Level 2 (Left & Right)
                                    <div class="flex justify-around w-full max-w-lg relative">
                                        // Connect lines to Level 2
                                        <div class="absolute -top-12 left-1/2 w-0.5 h-12 border-l-2 border-dashed border-zinc-800/80"></div>
                                        <div class="absolute -top-6 left-1/4 right-1/4 h-0.5 border-t-2 border-dashed border-zinc-800/80"></div>
                                        <div class="absolute -top-6 left-1/4 w-0.5 h-6 border-l-2 border-dashed border-zinc-800/80"></div>
                                        <div class="absolute -top-6 right-1/4 w-0.5 h-6 border-l-2 border-dashed border-zinc-800/80"></div>

                                        {render_matrix_node(2, 1)}
                                        {render_matrix_node(3, 2)}
                                    </div>

                                    // Level 3 (Leaf nodes 4, 5, 6, 7)
                                    <div class="flex justify-around w-full max-w-lg relative">
                                        // Connect lines to Level 3 (Left Sub-branch: Slot 2 -> Slots 4 & 5)
                                        <div class="absolute -top-12 left-1/4 w-0.5 h-12 border-l-2 border-dashed border-zinc-800/80"></div>
                                        <div class="absolute -top-6 left-[12.5%] right-[62.5%] h-0.5 border-t-2 border-dashed border-zinc-800/80"></div>
                                        <div class="absolute -top-6 left-[12.5%] w-0.5 h-6 border-l-2 border-dashed border-zinc-800/80"></div>
                                        <div class="absolute -top-6 left-[37.5%] w-0.5 h-6 border-l-2 border-dashed border-zinc-800/80"></div>

                                        // Connect lines to Level 3 (Right Sub-branch: Slot 3 -> Slots 6 & 7)
                                        <div class="absolute -top-12 right-1/4 w-0.5 h-12 border-l-2 border-dashed border-zinc-800/80"></div>
                                        <div class="absolute -top-6 left-[62.5%] right-[12.5%] h-0.5 border-t-2 border-dashed border-zinc-800/80"></div>
                                        <div class="absolute -top-6 left-[62.5%] w-0.5 h-6 border-l-2 border-dashed border-zinc-800/80"></div>
                                        <div class="absolute -top-6 left-[87.5%] w-0.5 h-6 border-l-2 border-dashed border-zinc-800/80"></div>

                                        {render_matrix_node(4, 3)}
                                        {render_matrix_node(5, 4)}
                                        {render_matrix_node(6, 5)}
                                        {render_matrix_node(7, 6)}
                                    </div>
                                </div>
                            </div>
                        </div>

                        // Modal Downline Account Form Overlay
                        {render_modal_overlay()}
                    </Show>

                    // MY DOWNLINES PANEL (With Simulate Direct Signup)
                    <Show when=move || active_section.get() == "downlines">
                        <div class="space-y-8 animate-fadeIn">
                            <div class="border-b border-zinc-800 pb-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                                <div>
                                    <h2 class="text-2xl font-black text-white">"Direct Referral Program (Downline)"</h2>
                                    <p class="text-xs text-slate-400">"Expand your direct network, trigger matrix cycles, and accelerate Flushline graduations."</p>
                                </div>
                                <button
                                    on:click=move |_| handle_simulate_signup()
                                    disabled=move || simulate_loading.get()
                                    class="py-2.5 px-5 bg-gradient-to-r from-emerald-500 to-[#00d4aa] text-[#0b0f19] hover:from-emerald-600 hover:to-emerald-400 font-extrabold text-xs rounded-xl shadow-lg shadow-emerald-500/10 hover:shadow-emerald-500/20 transition-all flex items-center justify-center gap-1.5 self-start"
                                >
                                    <Show when=move || simulate_loading.get()>
                                        <div class="w-3.5 h-3.5 border-2 border-transparent border-t-[#0b0f19] rounded-full animate-spin"></div>
                                    </Show>
                                    "Simulate Direct Signup"
                                </button>
                            </div>

                            // Referred Directory Table
                            <div class="bg-[#111827] border border-zinc-800 rounded-2xl p-6 space-y-4">
                                <h3 class="text-sm font-bold text-white uppercase tracking-wider border-b border-zinc-800 pb-3">"Referred Member Directory"</h3>

                                <div class="overflow-x-auto">
                                    <table class="w-full text-left text-xs">
                                        <thead>
                                            <tr class="border-b border-zinc-800 text-slate-400">
                                                <th class="py-3 px-2 font-semibold uppercase">"Downline Account ID"</th>
                                                <th class="py-3 px-2 font-semibold uppercase">"Username"</th>
                                                <th class="py-3 px-2 font-semibold uppercase">"Card Tier"</th>
                                                <th class="py-3 px-2 font-semibold uppercase">"Registered At"</th>
                                                <th class="py-3 px-2 text-right uppercase">"Status"</th>
                                            </tr>
                                        </thead>
                                        <tbody class="divide-y divide-zinc-800/40 text-slate-300">
                                            <For
                                                each=move || dashboard_data.get().referrals
                                                key=|ref_item| ref_item.account_id
                                                let:ref_item
                                            >
                                                <tr class="hover:bg-zinc-900/10">
                                                    <td class="py-4 px-2 font-mono">{ref_item.account_id.to_string()}</td>
                                                    <td class="py-4 px-2 font-bold text-white">{ref_item.username.clone()}</td>
                                                    <td class="py-4 px-2 font-semibold text-[#00d4aa]">{ref_item.tier.clone()}</td>
                                                    <td class="py-4 px-2">{ref_item.registered_at.clone()}</td>
                                                    <td class="py-4 px-2 text-right">
                                                        <span class="px-2 py-0.5 bg-emerald-950/30 text-emerald-400 border border-emerald-800/50 rounded font-semibold text-[10px]">
                                                            "Active"
                                                        </span>
                                                    </td>
                                                </tr>
                                            </For>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </Show>

                    // DEVICE SECURITY PANEL (With session-level whitelisting/revoking)
                    <Show when=move || active_section.get() == "security">
                        <div class="space-y-8 animate-fadeIn">
                            <div class="border-b border-zinc-800 pb-5">
                                <h2 class="text-2xl font-black text-white">"Device Security & Biometrics"</h2>
                                <p class="text-xs text-slate-400">"Whitelist authorized user devices, block intruders, and manage registered passkeys."</p>
                            </div>

                            <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
                                // Biometrics Key Enrollment
                                <div class="bg-[#111827] border border-zinc-800 rounded-2xl p-6 space-y-4">
                                    <h3 class="text-sm font-bold text-white uppercase tracking-wider">"Enroll Secure Passkey"</h3>
                                    <p class="text-xs text-slate-400 leading-relaxed">
                                        "Add Apple Touch ID, Face ID, or Windows Hello credentials to allow secure biometric authentication on other devices without relying on magic link delivery."
                                    </p>

                                    <Show
                                        when=move || {
                                            dashboard_data.get().user.as_ref().map(|u| u.has_passkey).unwrap_or(false)
                                        }
                                        fallback=move || view! {
                                            <button
                                                on:click=move |_| handle_register_passkey()
                                                disabled=move || biometric_loading.get()
                                                class="w-full py-2.5 bg-gradient-to-r from-[#00d4aa] to-teal-500 text-[#0b0f19] font-bold text-xs rounded-xl shadow-lg transition-all flex items-center justify-center gap-1.5"
                                            >
                                                <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                                                    <path d="M12 2c5.522 0 10 4.477 10 10s-4.478 10-10 10S2 17.523 2 12 6.478 2 12 2zm1 10h3v-2h-3V7h-2v3H8v2h3v3h2v-3z"/>
                                                </svg>
                                                "Enroll Apple / Hello Key"
                                            </button>
                                        }
                                    >
                                        <div class="p-4 bg-emerald-950/40 border border-emerald-800/60 rounded-xl text-left space-y-3">
                                            <div class="flex gap-2.5 items-center text-emerald-400">
                                                <svg class="w-5 h-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                                    <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                                </svg>
                                                <div>
                                                    <p class="text-xs font-bold text-emerald-200">"Biometric Credential Active"</p>
                                                    <p class="text-[10px] text-emerald-400 mt-0.5">"Device is locked into passkey database."</p>
                                                </div>
                                            </div>
                                            <button
                                                on:click=move |_| handle_register_passkey()
                                                disabled=move || biometric_loading.get()
                                                class="w-full py-1.5 bg-emerald-900/20 hover:bg-emerald-900/40 border border-emerald-800/60 text-emerald-200 text-[10px] font-bold rounded-lg transition-all duration-150 flex items-center justify-center gap-1"
                                            >
                                                "Register Sibling Device"
                                            </button>
                                        </div>
                                    </Show>
                                </div>

                                // Active Sessions List
                                <div class="md:col-span-2 bg-[#111827] border border-zinc-800 rounded-2xl p-6 space-y-4">
                                    <div class="flex items-center justify-between border-b border-zinc-800 pb-3">
                                        <h3 class="text-sm font-bold text-white uppercase tracking-wider">"Active Logged Devices"</h3>
                                        <button
                                            on:click=move |_| handle_revoke_other_sessions()
                                            class="px-3 py-1.5 text-[10px] font-bold text-red-400 hover:text-white bg-red-950/20 hover:bg-red-900 border border-red-900/50 rounded-lg transition-all"
                                        >
                                            "Revoke Other Sessions"
                                        </button>
                                    </div>

                                    <div class="overflow-x-auto">
                                        <table class="w-full text-left text-xs">
                                            <thead>
                                                <tr class="border-b border-zinc-800 text-slate-400">
                                                    <th class="py-3 px-2 font-semibold uppercase">"OS / Device"</th>
                                                    <th class="py-3 px-2 font-semibold uppercase">"IP Address"</th>
                                                    <th class="py-3 px-2 font-semibold uppercase">"Whitelist"</th>
                                                    <th class="py-3 px-2 text-right uppercase">"Action"</th>
                                                </tr>
                                            </thead>
                                            <tbody class="divide-y divide-zinc-800/40 text-slate-300">
                                                <For
                                                    each=move || active_sessions.get()
                                                    key=|s| s.id
                                                    let:session
                                                >
                                                    <tr class="hover:bg-zinc-900/10">
                                                        <td class="py-4 px-2">
                                                            <div class="flex items-center gap-2">
                                                                <span class="text-slate-100 font-bold">
                                                                    {session.device_name.clone().unwrap_or_else(|| "Workstation".to_string())}
                                                                </span>
                                                                <Show when=move || session.is_current>
                                                                    <span class="text-[9px] bg-emerald-950 text-emerald-400 px-1.5 py-0.5 rounded border border-emerald-800/40 font-bold">"Current"</span>
                                                                </Show>
                                                            </div>
                                                        </td>
                                                        <td class="py-4 px-2 font-mono">{session.ip_address.clone().unwrap_or_else(|| "127.0.0.1".to_string())}</td>
                                                        <td class="py-4 px-2">
                                                            <button
                                                                on:click=move |_| handle_toggle_whitelist(session.id)
                                                                class=move || {
                                                                    let enabled = session.is_whitelisted;
                                                                    let base = "px-3 py-1 text-[10px] font-bold rounded-lg border transition-all ";
                                                                    if enabled {
                                                                        format!("{base} bg-emerald-950/40 border-emerald-800/60 text-emerald-400")
                                                                    } else {
                                                                        format!("{base} bg-red-950/20 border-red-900/50 text-red-400")
                                                                    }
                                                                }
                                                            >
                                                                {move || if session.is_whitelisted { "Whitelisted" } else { "Blocked / Limited" }}
                                                            </button>
                                                        </td>
                                                        <td class="py-4 px-2 text-right">
                                                            <Show
                                                                when=move || !session.is_current
                                                                fallback=|| view! { <span class="text-xs text-slate-500 font-medium">"-"</span> }
                                                            >
                                                                <button
                                                                    on:click=move |_| handle_revoke_session(session.id)
                                                                    class="text-red-400 hover:text-red-300 font-semibold"
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

                    // LINKED ACCOUNTS PANEL (Simulated)
                    <Show when=move || active_section.get() == "linked">
                        <div class="space-y-8 animate-fadeIn">
                            <div class="border-b border-zinc-800 pb-5">
                                <h2 class="text-2xl font-black text-white">"Linked Accounts"</h2>
                                <p class="text-xs text-slate-400">"Authenticate instantly by linking your social credentials to your security keychain."</p>
                            </div>

                            // Badges Grid
                            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
                                // 1. Google
                                <div class="bg-[#111827] border border-zinc-800 rounded-2xl p-5 space-y-4 flex flex-col justify-between">
                                    <div class="flex items-center gap-3">
                                        <div class="w-10 h-10 bg-red-950/10 rounded-xl flex items-center justify-center text-red-400 border border-red-900/30">
                                            "G"
                                        </div>
                                        <div>
                                            <h3 class="text-xs font-bold text-white">"Google Account"</h3>
                                            <p class="text-[10px] text-slate-400">"OAuth Identity Provider"</p>
                                        </div>
                                    </div>
                                    <button
                                        on:click=move |_| {
                                            set_linking_provider.set(Some("Google".to_string()));
                                            leptos::task::spawn_local(async move {
                                                sleep_delay(std::time::Duration::from_millis(1200)).await;
                                                set_linked_google.update(|v| *v = !*v);
                                                set_linking_provider.set(None);
                                            });
                                        }
                                        class=move || {
                                            let linked = linked_google.get();
                                            let base = "w-full py-2 text-xs font-bold rounded-lg transition-all border ";
                                            if linked {
                                                format!("{base} bg-emerald-950/30 border-emerald-800 text-emerald-400")
                                            } else {
                                                format!("{base} bg-zinc-900/60 border-zinc-800 text-slate-300 hover:border-slate-500")
                                            }
                                        }
                                    >
                                        {move || if linked_google.get() { "Linked ✅" } else { "Link Account" }}
                                    </button>
                                </div>

                                // 2. Apple
                                <div class="bg-[#111827] border border-zinc-800 rounded-2xl p-5 space-y-4 flex flex-col justify-between">
                                    <div class="flex items-center gap-3">
                                        <div class="w-10 h-10 bg-slate-900 rounded-xl flex items-center justify-center text-white border border-zinc-800">
                                            "A"
                                        </div>
                                        <div>
                                            <h3 class="text-xs font-bold text-white">"Apple ID"</h3>
                                            <p class="text-[10px] text-slate-400">"Secure Apple Keychain"</p>
                                        </div>
                                    </div>
                                    <button
                                        on:click=move |_| {
                                            set_linking_provider.set(Some("Apple".to_string()));
                                            leptos::task::spawn_local(async move {
                                                sleep_delay(std::time::Duration::from_millis(1200)).await;
                                                set_linked_apple.update(|v| *v = !*v);
                                                set_linking_provider.set(None);
                                            });
                                        }
                                        class=move || {
                                            let linked = linked_apple.get();
                                            let base = "w-full py-2 text-xs font-bold rounded-lg transition-all border ";
                                            if linked {
                                                format!("{base} bg-emerald-950/30 border-emerald-800 text-emerald-400")
                                            } else {
                                                format!("{base} bg-zinc-900/60 border-zinc-800 text-slate-300 hover:border-slate-500")
                                            }
                                        }
                                    >
                                        {move || if linked_apple.get() { "Linked ✅" } else { "Link Account" }}
                                    </button>
                                </div>

                                // 3. Windows / Microsoft
                                <div class="bg-[#111827] border border-zinc-800 rounded-2xl p-5 space-y-4 flex flex-col justify-between">
                                    <div class="flex items-center gap-3">
                                        <div class="w-10 h-10 bg-blue-950/10 rounded-xl flex items-center justify-center text-blue-400 border border-blue-900/30">
                                            "W"
                                        </div>
                                        <div>
                                            <h3 class="text-xs font-bold text-white">"Windows Hello"</h3>
                                            <p class="text-[10px] text-slate-400">"Microsoft Passport SDK"</p>
                                        </div>
                                    </div>
                                    <button
                                        on:click=move |_| {
                                            set_linking_provider.set(Some("Microsoft".to_string()));
                                            leptos::task::spawn_local(async move {
                                                sleep_delay(std::time::Duration::from_millis(1200)).await;
                                                set_linked_microsoft.update(|v| *v = !*v);
                                                set_linking_provider.set(None);
                                            });
                                        }
                                        class=move || {
                                            let linked = linked_microsoft.get();
                                            let base = "w-full py-2 text-xs font-bold rounded-lg transition-all border ";
                                            if linked {
                                                format!("{base} bg-emerald-950/30 border-emerald-800 text-emerald-400")
                                            } else {
                                                format!("{base} bg-zinc-900/60 border-zinc-800 text-slate-300 hover:border-slate-500")
                                            }
                                        }
                                    >
                                        {move || if linked_microsoft.get() { "Linked ✅" } else { "Link Account" }}
                                    </button>
                                </div>

                                // 4. Facebook
                                <div class="bg-[#111827] border border-zinc-800 rounded-2xl p-5 space-y-4 flex flex-col justify-between">
                                    <div class="flex items-center gap-3">
                                        <div class="w-10 h-10 bg-indigo-950/15 rounded-xl flex items-center justify-center text-indigo-400 border border-indigo-900/30">
                                            "F"
                                        </div>
                                        <div>
                                            <h3 class="text-xs font-bold text-white">"Facebook Identity"</h3>
                                            <p class="text-[10px] text-slate-400">"Meta Graph API"</p>
                                        </div>
                                    </div>
                                    <button
                                        on:click=move |_| {
                                            set_linking_provider.set(Some("Facebook".to_string()));
                                            leptos::task::spawn_local(async move {
                                                sleep_delay(std::time::Duration::from_millis(1200)).await;
                                                set_linked_facebook.update(|v| *v = !*v);
                                                set_linking_provider.set(None);
                                            });
                                        }
                                        class=move || {
                                            let linked = linked_facebook.get();
                                            let base = "w-full py-2 text-xs font-bold rounded-lg transition-all border ";
                                            if linked {
                                                format!("{base} bg-emerald-950/30 border-emerald-800 text-emerald-400")
                                            } else {
                                                format!("{base} bg-zinc-900/60 border-zinc-800 text-slate-300 hover:border-slate-500")
                                            }
                                        }
                                    >
                                        {move || if linked_facebook.get() { "Linked ✅" } else { "Link Account" }}
                                    </button>
                                </div>
                            </div>

                            // Simulated Linking overlay spinner
                            <Show when=move || linking_provider.get().is_some()>
                                <div class="fixed inset-0 bg-slate-950/60 backdrop-blur-md flex flex-col gap-4 items-center justify-center z-50 animate-fadeIn">
                                    <div class="w-10 h-10 border-4 border-transparent border-t-[#00d4aa] rounded-full animate-spin"></div>
                                    <p class="text-xs font-bold text-[#00d4aa]">"Establishing OAuth handshake with " {move || linking_provider.get().unwrap()} "..."</p>
                                </div>
                            </Show>
                        </div>
                    </Show>

                    // PROFILE & SETTINGS CUSTOMIZER
                    <Show when=move || active_section.get() == "settings">
                        <div class="space-y-8 animate-fadeIn">
                            <div class="border-b border-zinc-800 pb-5">
                                <h2 class="text-2xl font-black text-white">"Settings & Customization"</h2>
                                <p class="text-xs text-slate-400">"Configure your platform profile, select custom illustrated avatars, and change themes instantly."</p>
                            </div>

                            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                                // 1. Custom illustrated Avatars
                                <div class="bg-[#111827] border border-zinc-800 rounded-2xl p-6 space-y-4">
                                    <h3 class="text-sm font-bold text-white uppercase tracking-wider border-b border-zinc-800/60 pb-2">"Illustrated Avatars"</h3>

                                    <div class="grid grid-cols-4 gap-4">
                                        <button
                                            on:click=move |_| set_selected_avatar.set("avatar_1".to_string())
                                            class=move || {
                                                let active = selected_avatar.get() == "avatar_1";
                                                let base = "w-12 h-12 rounded-full border-2 flex items-center justify-center font-bold text-sm ";
                                                if active {
                                                    format!("{base} border-[#00d4aa] bg-[#00d4aa]/10 text-[#00d4aa]")
                                                } else {
                                                    format!("{base} border-zinc-800 bg-zinc-950 text-slate-400 hover:border-slate-500")
                                                }
                                            }
                                        >
                                            "🦊"
                                        </button>
                                        <button
                                            on:click=move |_| set_selected_avatar.set("avatar_2".to_string())
                                            class=move || {
                                                let active = selected_avatar.get() == "avatar_2";
                                                let base = "w-12 h-12 rounded-full border-2 flex items-center justify-center font-bold text-sm ";
                                                if active {
                                                    format!("{base} border-[#00d4aa] bg-[#00d4aa]/10 text-[#00d4aa]")
                                                } else {
                                                    format!("{base} border-zinc-800 bg-zinc-950 text-slate-400 hover:border-slate-500")
                                                }
                                            }
                                        >
                                            "🐱"
                                        </button>
                                        <button
                                            on:click=move |_| set_selected_avatar.set("avatar_3".to_string())
                                            class=move || {
                                                let active = selected_avatar.get() == "avatar_3";
                                                let base = "w-12 h-12 rounded-full border-2 flex items-center justify-center font-bold text-sm ";
                                                if active {
                                                    format!("{base} border-[#00d4aa] bg-[#00d4aa]/10 text-[#00d4aa]")
                                                } else {
                                                    format!("{base} border-zinc-800 bg-zinc-950 text-slate-400 hover:border-slate-500")
                                                }
                                            }
                                        >
                                            "🐯"
                                        </button>
                                        <button
                                            on:click=move |_| set_selected_avatar.set("avatar_4".to_string())
                                            class=move || {
                                                let active = selected_avatar.get() == "avatar_4";
                                                let base = "w-12 h-12 rounded-full border-2 flex items-center justify-center font-bold text-sm ";
                                                if active {
                                                    format!("{base} border-[#00d4aa] bg-[#00d4aa]/10 text-[#00d4aa]")
                                                } else {
                                                    format!("{base} border-zinc-800 bg-zinc-950 text-slate-400 hover:border-slate-500")
                                                }
                                            }
                                        >
                                            "🐨"
                                        </button>
                                    </div>
                                </div>

                                // 2. Custom theme selectors
                                <div class="bg-[#111827] border border-zinc-800 rounded-2xl p-6 space-y-4">
                                    <h3 class="text-sm font-bold text-white uppercase tracking-wider border-b border-zinc-800/60 pb-2">"Custom Theme Styles"</h3>

                                    <div class="space-y-2">
                                        <button
                                            on:click=move |_| set_selected_theme.set("obsidian".to_string())
                                            class=move || {
                                                let active = selected_theme.get() == "obsidian";
                                                let base = "w-full py-2.5 px-4 text-xs font-semibold rounded-lg border text-left flex justify-between items-center transition-all ";
                                                if active {
                                                    format!("{base} border-[#00d4aa] bg-[#00d4aa]/5 text-[#00d4aa]")
                                                } else {
                                                    format!("{base} border-zinc-800 bg-zinc-950 text-slate-300 hover:border-slate-600")
                                                }
                                            }
                                        >
                                            <span>"Sleek Obsidian (Default)"</span>
                                            <span class="w-3 h-3 rounded-full bg-slate-900 border border-slate-700"></span>
                                        </button>
                                        <button
                                            on:click=move |_| set_selected_theme.set("cyberpunk".to_string())
                                            class=move || {
                                                let active = selected_theme.get() == "cyberpunk";
                                                let base = "w-full py-2.5 px-4 text-xs font-semibold rounded-lg border text-left flex justify-between items-center transition-all ";
                                                if active {
                                                    format!("{base} border-pink-500 bg-pink-500/5 text-pink-400")
                                                } else {
                                                    format!("{base} border-zinc-800 bg-zinc-950 text-slate-300 hover:border-slate-600")
                                                }
                                            }
                                        >
                                            <span>"Neon Cyberpunk"</span>
                                            <span class="w-3 h-3 rounded-full bg-pink-500 border border-pink-400"></span>
                                        </button>
                                    </div>
                                </div>

                                // 3. Form trigger details with Success toast
                                <div class="bg-[#111827] border border-zinc-800 rounded-2xl p-6 space-y-4">
                                    <h3 class="text-sm font-bold text-white uppercase tracking-wider border-b border-zinc-800/60 pb-2">"Identity Information"</h3>

                                    <div class="space-y-3">
                                        <div>
                                            <label class="text-[10px] uppercase font-bold text-slate-400">"Username"</label>
                                            <input
                                                type="text"
                                                prop:value=move || dashboard_data.get().user.clone().unwrap_or_default().username
                                                class="w-full mt-1 px-3 py-2 bg-zinc-950 border border-zinc-800 focus:border-[#00d4aa] rounded-lg text-white text-xs outline-none"
                                            />
                                        </div>
                                        <div>
                                            <label class="text-[10px] uppercase font-bold text-slate-400">"Email Address"</label>
                                            <input
                                                type="email"
                                                prop:value=move || dashboard_data.get().user.clone().unwrap_or_default().email
                                                class="w-full mt-1 px-3 py-2 bg-zinc-950 border border-zinc-800 focus:border-[#00d4aa] rounded-lg text-white text-xs outline-none"
                                            />
                                        </div>

                                        <button
                                            on:click=move |_| {
                                                set_profile_success_toast.set(true);
                                                leptos::task::spawn_local(async move {
                                                    sleep_delay(std::time::Duration::from_secs(2)).await;
                                                    set_profile_success_toast.set(false);
                                                });
                                            }
                                            class="w-full py-2 bg-[#00d4aa] hover:bg-emerald-500 text-[#0b0f19] text-xs font-bold rounded-lg transition-all"
                                        >
                                            "Save Preferences"
                                        </button>
                                    </div>
                                </div>
                            </div>

                            // Sliding notification toast
                            <Show when=move || profile_success_toast.get()>
                                <div class="fixed bottom-6 right-6 p-4 bg-emerald-950 border border-emerald-800 rounded-xl text-emerald-400 text-xs font-bold shadow-2xl flex items-center gap-2.5 animate-slideUp">
                                    <svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3">
                                        <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
                                    </svg>
                                    <span>"Settings saved successfully!"</span>
                                </div>
                            </Show>
                        </div>
                    </Show>
                </main>
            </div>
        </Show>
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
