use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::net::{IpAddr, SocketAddr};
use uuid::Uuid;

use crate::handlers::AppState;

// ----------------------------------------------------------------------------
// Types and Structs
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub session_token: String,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

// ----------------------------------------------------------------------------
// Rate Limiter Implementation
// ----------------------------------------------------------------------------

pub struct IpRateLimiter {
    limiter: governor::DefaultKeyedRateLimiter<IpAddr>,
}

impl IpRateLimiter {
    pub fn new(replenish_per_sec: u32, max_burst: u32) -> Self {
        use governor::{Quota, RateLimiter};
        use std::num::NonZeroU32;

        let quota = Quota::per_second(NonZeroU32::new(replenish_per_sec).unwrap())
            .allow_burst(NonZeroU32::new(max_burst).unwrap());

        Self {
            limiter: RateLimiter::keyed(quota),
        }
    }

    pub fn check(&self, ip: IpAddr) -> bool {
        self.limiter.check_key(&ip).is_ok()
    }
}

// ----------------------------------------------------------------------------
// Rate Limiter Middleware
// ----------------------------------------------------------------------------

pub async fn rate_limiter_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let client_ip = addr.ip();

    // Verify rate limit
    if !state.rate_limiter.check(client_ip) {
        let body =
            Json(serde_json::json!({ "error": "Too many requests. Please try again later." }));
        return (StatusCode::TOO_MANY_REQUESTS, body).into_response();
    }

    next.run(req).await
}

// ----------------------------------------------------------------------------
// Session Authentication Middleware
// ----------------------------------------------------------------------------

pub async fn auth_middleware(
    State(state): State<AppState>,
    cookie_jar: CookieJar,
    mut req: Request,
    next: Next,
) -> Response {
    // 1. Resolve session token from Cookie or Authorization header
    let token_opt = cookie_jar
        .get("session_token")
        .map(|c| c.value().to_string())
        .or_else(|| {
            req.headers()
                .get(header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.strip_prefix("Bearer ").map(|t| t.to_string()))
        });

    let token = match token_opt {
        Some(t) => t,
        None => {
            let body =
                Json(serde_json::json!({ "error": "Authentication required. Missing token." }));
            return (StatusCode::UNAUTHORIZED, body).into_response();
        }
    };

    // 2. Query user and session state from database
    let db_row = match sqlx::query(
        "SELECT u.id as user_id, u.email, u.username, u.role, \
                s.id as session_id, s.expires_at, s.last_active_at \
         FROM auth_sessions s \
         JOIN auth_users u ON u.id = s.user_id \
         WHERE s.session_token = $1",
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            let body = Json(serde_json::json!({ "error": "Invalid or expired session token." }));
            return (StatusCode::UNAUTHORIZED, body).into_response();
        }
        Err(e) => {
            let body = Json(
                serde_json::json!({ "error": format!("Database error during session check: {e}") }),
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, body).into_response();
        }
    };

    // 3. Verify session expiration
    let expires_at: chrono::DateTime<Utc> = db_row.get("expires_at");
    if expires_at < Utc::now() {
        // Purge expired session
        let session_id: Uuid = db_row.get("session_id");
        let _ = sqlx::query("DELETE FROM auth_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&state.pool)
            .await;

        let body = Json(serde_json::json!({ "error": "Session has expired." }));
        return (StatusCode::UNAUTHORIZED, body).into_response();
    }

    // 4. Update activity timestamp (throttle writes to once per 60 seconds)
    let last_active: chrono::DateTime<Utc> = db_row.get("last_active_at");
    if (Utc::now() - last_active).num_seconds() > 60 {
        let session_id: Uuid = db_row.get("session_id");
        let _ = sqlx::query("UPDATE auth_sessions SET last_active_at = NOW() WHERE id = $1")
            .bind(session_id)
            .execute(&state.pool)
            .await;
    }

    // 5. Populate Auth structs
    let auth_user = AuthUser {
        id: db_row.get("user_id"),
        email: db_row.get("email"),
        username: db_row.get("username"),
        role: db_row.get("role"),
    };

    let auth_session = AuthSession {
        id: db_row.get("session_id"),
        user_id: db_row.get("user_id"),
        session_token: token,
        user_agent: None, // Filled if needed from headers
        ip_address: None,
    };

    // 6. Inject into request extensions
    req.extensions_mut().insert(auth_user);
    req.extensions_mut().insert(auth_session);

    next.run(req).await
}

// ----------------------------------------------------------------------------
// Authorization: Admin Role Middleware
// ----------------------------------------------------------------------------

pub async fn admin_middleware(req: Request, next: Next) -> Response {
    if let Some(user) = req.extensions().get::<AuthUser>() {
        if user.role == "admin" {
            return next.run(req).await;
        }
    }

    let body =
        Json(serde_json::json!({ "error": "Access denied. Administrator privileges required." }));
    (StatusCode::FORBIDDEN, body).into_response()
}
