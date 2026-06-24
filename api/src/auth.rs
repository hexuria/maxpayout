use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use chrono::{DateTime, Utc};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::handlers::{ApiError, AppState};
use crate::middleware::{AuthSession, AuthUser};

// ----------------------------------------------------------------------------
// Request / Response Structs
// ----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct MagicLinkRequest {
    pub email: String,
    pub username: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PasswordRegisterRequest {
    pub email: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct PasswordLoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct MagicLinkLoginQuery {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyRegisterStartResponse {
    pub challenge: CreationChallengeResponse,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyLoginStartRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct PasskeyLoginStartResponse {
    pub challenge_id: Uuid,
    pub challenge: RequestChallengeResponse,
}

#[derive(Debug, Deserialize)]
pub struct PasskeyLoginFinishRequest {
    pub challenge_id: Uuid,
    pub credential: PublicKeyCredential,
}

#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub id: Uuid,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
    pub is_current: bool,
}

// ----------------------------------------------------------------------------
// Magic Link Handlers
// ----------------------------------------------------------------------------

pub async fn request_magic_link(
    State(state): State<AppState>,
    Json(payload): Json<MagicLinkRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let email = payload.email.trim().to_lowercase();
    if email.is_empty() {
        return Err(ApiError::Flushline("Email cannot be empty".to_string()));
    }

    // Generate secure token (32 chars)
    let token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let expires_at = Utc::now() + chrono::Duration::minutes(15);

    // Save magic link token in DB
    sqlx::query("INSERT INTO auth_magic_links (token, email, expires_at) VALUES ($1, $2, $3)")
        .bind(&token)
        .bind(&email)
        .bind(expires_at)
        .execute(&state.pool)
        .await?;

    let magic_url = format!(
        "http://localhost:8080/api/auth/magic-link/login?token={}",
        token
    );

    // Check if RESEND_API_KEY is configured
    if let Ok(api_key) = std::env::var("RESEND_API_KEY") {
        if !api_key.trim().is_empty() {
            let sender = std::env::var("RESEND_SENDER")
                .unwrap_or_else(|_| "onboarding@resend.dev".to_string());

            let client = reqwest::Client::new();
            let response = client
                .post("https://api.resend.com/emails")
                .header("Authorization", format!("Bearer {}", api_key))
                .json(&serde_json::json!({
                    "from": sender,
                    "to": [email],
                    "subject": "Log in to MaxPayout",
                    "html": format!(
                        "<p>Click the link below to log in to your MaxPayout account:</p><p><a href=\"{}\">Log In Now</a></p>",
                        magic_url
                    )
                }))
                .send()
                .await;

            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        tracing::info!(
                            "Successfully sent magic link email to {} via Resend",
                            email
                        );
                    } else {
                        let status = resp.status();
                        let error_text = resp.text().await.unwrap_or_default();
                        tracing::error!(
                            "Failed to send email via Resend (Status: {}): {}",
                            status,
                            error_text
                        );
                        return Err(ApiError::Flushline(format!(
                            "Failed to send email: {}",
                            error_text
                        )));
                    }
                }
                Err(e) => {
                    tracing::error!("Error connecting to Resend API: {}", e);
                    return Err(ApiError::Flushline(format!(
                        "Failed to connect to email service: {}",
                        e
                    )));
                }
            }
        } else {
            // Fallback: log the URL if key is empty
            tracing::info!(
                "MOCK EMAIL -> Magic Link requested for {}. URL: {}",
                email,
                magic_url
            );
        }
    } else {
        // Fallback: log the URL if key is not set
        tracing::info!(
            "MOCK EMAIL -> Magic Link requested for {}. URL: {}",
            email,
            magic_url
        );
    }

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Magic link sent successfully.",
            "token": token // Exposed for local automated testing
        })),
    ))
}

pub async fn login_via_magic_link(
    State(state): State<AppState>,
    cookie_jar: CookieJar,
    Query(query): Query<MagicLinkLoginQuery>,
) -> Result<impl IntoResponse, ApiError> {
    // 1. Verify token
    let row = sqlx::query("SELECT email, expires_at, used FROM auth_magic_links WHERE token = $1")
        .bind(&query.token)
        .fetch_optional(&state.pool)
        .await?;

    let (email, expires_at, used) = match row {
        Some(r) => {
            let email: String = r.get("email");
            let expires_at: DateTime<Utc> = r.get("expires_at");
            let used: bool = r.get("used");
            (email, expires_at, used)
        }
        None => return Err(ApiError::NotFound(Uuid::nil())), // Generic 404/invalid response
    };

    if used || expires_at < Utc::now() {
        return Err(ApiError::Flushline(
            "Token has expired or already been used.".to_string(),
        ));
    }

    // Mark token as used
    sqlx::query("UPDATE auth_magic_links SET used = TRUE WHERE token = $1")
        .bind(&query.token)
        .execute(&state.pool)
        .await?;

    // 2. Fetch or create user
    let user_row = sqlx::query("SELECT id, username, role FROM auth_users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&state.pool)
        .await?;

    let user = match user_row {
        Some(ur) => AuthUser {
            id: ur.get("id"),
            email: email.clone(),
            username: ur.get("username"),
            role: ur.get("role"),
        },
        None => {
            // Register new user
            let new_user_id = Uuid::now_v7();
            let derived_username = email.split('@').next().unwrap_or("user").to_string();
            sqlx::query(
                "INSERT INTO auth_users (id, email, username, role) VALUES ($1, $2, $3, 'user')",
            )
            .bind(new_user_id)
            .bind(&email)
            .bind(&derived_username)
            .execute(&state.pool)
            .await?;

            AuthUser {
                id: new_user_id,
                email: email.clone(),
                username: derived_username,
                role: "user".to_string(),
            }
        }
    };

    // 3. Create active session
    let session_token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let session_expires = Utc::now() + chrono::Duration::days(7);

    sqlx::query(
        "INSERT INTO auth_sessions (user_id, session_token, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(user.id)
    .bind(&session_token)
    .bind(session_expires)
    .execute(&state.pool)
    .await?;

    // Set secure cookie
    let cookie = Cookie::build(("session_token", session_token))
        .path("/")
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(time::Duration::days(7))
        .build();

    let updated_jar = cookie_jar.add(cookie);

    Ok((updated_jar, Json(user)))
}

// ----------------------------------------------------------------------------
// Password Authentication Handlers
// ----------------------------------------------------------------------------

pub async fn register_password_user(
    State(state): State<AppState>,
    Json(payload): Json<PasswordRegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let email = payload.email.trim().to_lowercase();
    let username = payload.username.trim();
    let password = payload.password;

    if email.is_empty() {
        return Err(ApiError::Flushline("Email cannot be empty".to_string()));
    }
    if username.is_empty() {
        return Err(ApiError::Flushline("Username cannot be empty".to_string()));
    }
    if password.len() < 8 {
        return Err(ApiError::Flushline(
            "Password must be at least 8 characters".to_string(),
        ));
    }

    // Check if email already exists
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth_users WHERE email = $1)")
            .bind(&email)
            .fetch_one(&state.pool)
            .await?;

    if exists {
        return Err(ApiError::Flushline(
            "User with this email already exists".to_string(),
        ));
    }

    // Hash password safely using bcrypt
    let password_hash = bcrypt::hash(&password, bcrypt::DEFAULT_COST)
        .map_err(|e| ApiError::Flushline(format!("Hashing error: {e}")))?;

    // Insert user
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO auth_users (id, email, username, role, password_hash) VALUES ($1, $2, $3, 'user', $4)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(username)
    .bind(&password_hash)
    .execute(&state.pool)
    .await?;

    let auth_user = AuthUser {
        id: user_id,
        email,
        username: username.to_string(),
        role: "user".to_string(),
    };

    Ok((StatusCode::CREATED, Json(auth_user)))
}

pub async fn login_password_user(
    State(state): State<AppState>,
    cookie_jar: CookieJar,
    Json(payload): Json<PasswordLoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let email = payload.email.trim().to_lowercase();
    let password = payload.password;

    // Fetch user with password_hash
    let row =
        sqlx::query("SELECT id, username, role, password_hash FROM auth_users WHERE email = $1")
            .bind(&email)
            .fetch_optional(&state.pool)
            .await?;

    let (user_id, username, role, stored_hash) = match row {
        Some(r) => {
            let user_id: Uuid = r.get("id");
            let username: String = r.get("username");
            let role: String = r.get("role");
            let password_hash: Option<String> = r.get("password_hash");
            (user_id, username, role, password_hash)
        }
        None => return Err(ApiError::Flushline("Invalid email or password".to_string())),
    };

    let hash_str = match stored_hash {
        Some(h) => h,
        None => {
            return Err(ApiError::Flushline(
                "This account does not have a password configured".to_string(),
            ))
        }
    };

    // Verify bcrypt hash
    let valid = bcrypt::verify(&password, &hash_str)
        .map_err(|e| ApiError::Flushline(format!("Verification error: {e}")))?;

    if !valid {
        return Err(ApiError::Flushline("Invalid email or password".to_string()));
    }

    let auth_user = AuthUser {
        id: user_id,
        email,
        username,
        role,
    };

    // Create session
    let session_token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let session_expires = Utc::now() + chrono::Duration::days(7);

    sqlx::query(
        "INSERT INTO auth_sessions (user_id, session_token, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(auth_user.id)
    .bind(&session_token)
    .bind(session_expires)
    .execute(&state.pool)
    .await?;

    // Build session cookie
    let cookie = Cookie::build(("session_token", session_token))
        .path("/")
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(time::Duration::days(7))
        .build();

    let updated_jar = cookie_jar.add(cookie);

    Ok((updated_jar, Json(auth_user)))
}

// ----------------------------------------------------------------------------
// Passkey (WebAuthn) Registration Handlers
// ----------------------------------------------------------------------------

pub async fn register_passkey_start(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<impl IntoResponse, ApiError> {
    // Start passkey registration
    let (challenge_response, passkey_registration) = state
        .webauthn
        .start_passkey_registration(user.id, &user.username, &user.username, None)
        .map_err(|e| ApiError::Flushline(format!("WebAuthn error starting registration: {e}")))?;

    // Cache the challenge in database
    let challenge_json = serde_json::to_value(&passkey_registration)
        .map_err(|e| ApiError::Flushline(e.to_string()))?;

    let expires_at = Utc::now() + chrono::Duration::minutes(10);

    sqlx::query(
        "INSERT INTO auth_webauthn_challenges (email, challenge_json, expires_at) VALUES ($1, $2, $3)"
    )
    .bind(&user.email)
    .bind(challenge_json)
    .bind(expires_at)
    .execute(&state.pool)
    .await?;

    Ok((StatusCode::OK, Json(challenge_response)))
}

pub async fn register_passkey_finish(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(credential): Json<RegisterPublicKeyCredential>,
) -> Result<impl IntoResponse, ApiError> {
    // 1. Retrieve the cached registration challenge
    let challenge_row = sqlx::query(
        "SELECT challenge_id, challenge_json FROM auth_webauthn_challenges \
         WHERE email = $1 AND expires_at > NOW() \
         ORDER BY expires_at DESC LIMIT 1",
    )
    .bind(&user.email)
    .fetch_optional(&state.pool)
    .await?;

    let (challenge_id, challenge_val) = match challenge_row {
        Some(r) => {
            let id: Uuid = r.get("challenge_id");
            let val: serde_json::Value = r.get("challenge_json");
            (id, val)
        }
        None => {
            return Err(ApiError::Flushline(
                "Challenge has expired or not found. Please restart registration.".to_string(),
            ))
        }
    };

    let passkey_registration: PasskeyRegistration =
        serde_json::from_value(challenge_val).map_err(|e| ApiError::Flushline(e.to_string()))?;

    // 2. Complete registration check
    let passkey = state
        .webauthn
        .finish_passkey_registration(&credential, &passkey_registration)
        .map_err(|e| ApiError::Flushline(format!("Registration verification failed: {e}")))?;

    // 3. Persist Passkey in database
    let credential_id = passkey.cred_id().to_vec();
    let passkey_json =
        serde_json::to_value(&passkey).map_err(|e| ApiError::Flushline(e.to_string()))?;

    sqlx::query(
        "INSERT INTO auth_passkeys (user_id, credential_id, passkey_json) VALUES ($1, $2, $3)",
    )
    .bind(user.id)
    .bind(credential_id)
    .bind(passkey_json)
    .execute(&state.pool)
    .await?;

    // Delete used challenge
    let _ = sqlx::query("DELETE FROM auth_webauthn_challenges WHERE challenge_id = $1")
        .bind(challenge_id)
        .execute(&state.pool)
        .await;

    Ok(StatusCode::OK)
}

// ----------------------------------------------------------------------------
// Passkey (WebAuthn) Login/Authentication Handlers
// ----------------------------------------------------------------------------

pub async fn login_passkey_start(
    State(state): State<AppState>,
    Json(payload): Json<PasskeyLoginStartRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let email = payload.email.trim().to_lowercase();

    // 1. Fetch user by email
    let user_row = sqlx::query("SELECT id FROM auth_users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&state.pool)
        .await?;

    let user_id = match user_row {
        Some(ur) => ur.get::<Uuid, _>("id"),
        None => return Err(ApiError::NotFound(Uuid::nil())),
    };

    // 2. Load all registered passkeys for this user
    let passkeys_rows = sqlx::query("SELECT passkey_json FROM auth_passkeys WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(&state.pool)
        .await?;

    if passkeys_rows.is_empty() {
        return Err(ApiError::Flushline(
            "No registered passkeys found for this account.".to_string(),
        ));
    }

    let passkeys: Vec<Passkey> = passkeys_rows
        .into_iter()
        .map(|r| {
            let val: serde_json::Value = r.get("passkey_json");
            serde_json::from_value(val).unwrap()
        })
        .collect();

    // 3. Initiate WebAuthn authentication challenge
    let (challenge_response, passkey_authentication) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| ApiError::Flushline(format!("WebAuthn error starting login: {e}")))?;

    // Cache the authentication challenge
    let challenge_id = Uuid::now_v7();
    let challenge_json = serde_json::to_value(&passkey_authentication)
        .map_err(|e| ApiError::Flushline(e.to_string()))?;

    let expires_at = Utc::now() + chrono::Duration::minutes(10);

    sqlx::query(
        "INSERT INTO auth_webauthn_challenges (challenge_id, user_id, challenge_json, expires_at) VALUES ($1, $2, $3, $4)"
    )
    .bind(challenge_id)
    .bind(user_id)
    .bind(challenge_json)
    .bind(expires_at)
    .execute(&state.pool)
    .await?;

    Ok((
        StatusCode::OK,
        Json(PasskeyLoginStartResponse {
            challenge_id,
            challenge: challenge_response,
        }),
    ))
}

pub async fn login_passkey_finish(
    State(state): State<AppState>,
    cookie_jar: CookieJar,
    Json(payload): Json<PasskeyLoginFinishRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // 1. Retrieve the cached authentication challenge
    let challenge_row = sqlx::query(
        "SELECT user_id, challenge_json FROM auth_webauthn_challenges \
         WHERE challenge_id = $1 AND expires_at > NOW()",
    )
    .bind(payload.challenge_id)
    .fetch_optional(&state.pool)
    .await?;

    let (user_id, challenge_val) = match challenge_row {
        Some(r) => {
            let uid: Uuid = r.get("user_id");
            let val: serde_json::Value = r.get("challenge_json");
            (uid, val)
        }
        None => {
            return Err(ApiError::Flushline(
                "Challenge has expired or not found.".to_string(),
            ))
        }
    };

    let passkey_authentication: PasskeyAuthentication =
        serde_json::from_value(challenge_val).map_err(|e| ApiError::Flushline(e.to_string()))?;

    // 3. Verify signature
    let _auth_result = state
        .webauthn
        .finish_passkey_authentication(&payload.credential, &passkey_authentication)
        .map_err(|e| ApiError::Flushline(format!("Login verification failed: {e}")))?;

    // 4. Retrieve user info
    let user_row = sqlx::query("SELECT email, username, role FROM auth_users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.pool)
        .await?;

    let user = AuthUser {
        id: user_id,
        email: user_row.get("email"),
        username: user_row.get("username"),
        role: user_row.get("role"),
    };

    // 5. Create active session
    let session_token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let session_expires = Utc::now() + chrono::Duration::days(7);

    sqlx::query(
        "INSERT INTO auth_sessions (user_id, session_token, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(user.id)
    .bind(&session_token)
    .bind(session_expires)
    .execute(&state.pool)
    .await?;

    // Delete challenge
    let _ = sqlx::query("DELETE FROM auth_webauthn_challenges WHERE challenge_id = $1")
        .bind(payload.challenge_id)
        .execute(&state.pool)
        .await;

    // Set secure cookie
    let cookie = Cookie::build(("session_token", session_token))
        .path("/")
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(time::Duration::days(7))
        .build();

    let updated_jar = cookie_jar.add(cookie);

    Ok((updated_jar, Json(user)))
}

// ----------------------------------------------------------------------------
// Session Management Handlers
// ----------------------------------------------------------------------------

pub async fn list_active_sessions(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Extension(current_session): Extension<AuthSession>,
) -> Result<impl IntoResponse, ApiError> {
    let rows = sqlx::query(
        "SELECT id, user_agent, ip_address, created_at, last_active_at \
         FROM auth_sessions \
         WHERE user_id = $1 AND expires_at > NOW() \
         ORDER BY last_active_at DESC",
    )
    .bind(user.id)
    .fetch_all(&state.pool)
    .await?;

    let sessions: Vec<SessionInfo> = rows
        .into_iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            SessionInfo {
                id,
                user_agent: r.get("user_agent"),
                ip_address: r.get("ip_address"),
                created_at: r.get("created_at"),
                last_active_at: r.get("last_active_at"),
                is_current: id == current_session.id,
            }
        })
        .collect();

    Ok((StatusCode::OK, Json(sessions)))
}

pub async fn revoke_session(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let result = sqlx::query("DELETE FROM auth_sessions WHERE id = $1 AND user_id = $2")
        .bind(session_id)
        .bind(user.id)
        .execute(&state.pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound(session_id));
    }

    Ok(StatusCode::OK)
}

pub async fn revoke_other_sessions(
    State(state): State<AppState>,
    Extension(current_session): Extension<AuthSession>,
) -> Result<impl IntoResponse, ApiError> {
    sqlx::query("DELETE FROM auth_sessions WHERE user_id = $1 AND id != $2")
        .bind(current_session.user_id)
        .bind(current_session.id)
        .execute(&state.pool)
        .await?;

    Ok(StatusCode::OK)
}
