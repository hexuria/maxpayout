use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    routing::get,
    Router,
};
use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

use api::{
    auth::{
        list_active_sessions, login_via_magic_link, request_magic_link, revoke_other_sessions,
        revoke_session,
    },
    handlers::{set_referral_cookie, AppState},
    middleware::{auth_middleware, IpRateLimiter},
    run_migrations,
};

static DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://localhost/rfn_dev".to_string());

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to test database");

    // Clean drop of all tables in dependency order
    let drop_statements = [
        "DROP TABLE IF EXISTS auth_sessions CASCADE",
        "DROP TABLE IF EXISTS auth_passkeys CASCADE",
        "DROP TABLE IF EXISTS auth_webauthn_challenges CASCADE",
        "DROP TABLE IF EXISTS auth_magic_links CASCADE",
        "DROP TABLE IF EXISTS auth_users CASCADE",
        "DROP TABLE IF EXISTS orchestrator_inbox_log CASCADE",
        "DROP TABLE IF EXISTS orchestrator_coordination_states CASCADE",
        "DROP TABLE IF EXISTS flushline_outbox CASCADE",
        "DROP TABLE IF EXISTS flushline_accounts CASCADE",
        "DROP TABLE IF EXISTS flushline_tiers CASCADE",
        "DROP TABLE IF EXISTS matrix_outbox CASCADE",
        "DROP TABLE IF EXISTS matrix_slots CASCADE",
        "DROP TABLE IF EXISTS matrices CASCADE",
        "DROP TABLE IF EXISTS pot_bonus_weekly_cycles CASCADE",
        "DROP TABLE IF EXISTS pot_bonus_weekly_graduations CASCADE",
        "DROP TABLE IF EXISTS pot_bonus_registrations CASCADE",
        "DROP TABLE IF EXISTS pot_bonus_state CASCADE",
        "DROP TABLE IF EXISTS sponsor_pool CASCADE",
        "DROP TABLE IF EXISTS sponsor_account_stats CASCADE",
        "DROP TABLE IF EXISTS sponsor_service_state CASCADE",
    ];

    for stmt in &drop_statements {
        let _ = sqlx::query(stmt).execute(&pool).await;
    }

    run_migrations(&pool).await;

    pool
}

async fn get_response_body(body: Body) -> String {
    let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn test_auth_and_referral_flow() {
    let _lock = DB_LOCK.lock().await;
    let pool = setup_test_db().await;

    let aggregator = Arc::new(coordinator::PgAccountAggregator::new(pool.clone()));
    let rp_id = "localhost";
    let rp_origin = webauthn_rs::prelude::Url::parse("http://localhost:8080").unwrap();
    let webauthn = Arc::new(
        webauthn_rs::prelude::WebauthnBuilder::new(rp_id, &rp_origin)
            .unwrap()
            .build()
            .unwrap(),
    );
    let rate_limiter = Arc::new(IpRateLimiter::new(100, 200));

    let state = AppState {
        pool: pool.clone(),
        aggregator,
        rate_limiter,
        webauthn,
    };

    let auth_routes = Router::new()
        .route(
            "/magic-link/request",
            axum::routing::post(request_magic_link),
        )
        .route(
            "/magic-link/login",
            axum::routing::get(login_via_magic_link),
        );

    let secure_auth_routes = Router::new()
        .route("/sessions", axum::routing::get(list_active_sessions))
        .route("/sessions/:id", axum::routing::delete(revoke_session))
        .route(
            "/sessions/other",
            axum::routing::delete(revoke_other_sessions),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let app = Router::new()
        .route("/api/ref/:sponsor_id", get(set_referral_cookie))
        .nest("/api/auth", auth_routes)
        .nest("/api/auth", secure_auth_routes)
        .with_state(state);

    // 1. Verify set_referral_cookie endpoint
    let sponsor_id = Uuid::now_v7();
    let ref_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/ref/{}", sponsor_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(ref_response.status(), StatusCode::OK);
    let ref_headers = ref_response.headers();
    let cookie_header = ref_headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cookie_header.contains("sponsor_id="));
    assert!(cookie_header.contains(&sponsor_id.to_string()));

    // 2. Request magic link
    let magic_payload = serde_json::json!({
        "email": "user@example.com",
        "username": "TestUser"
    });
    let magic_req_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/magic-link/request")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&magic_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(magic_req_response.status(), StatusCode::OK);
    let body_str = get_response_body(magic_req_response.into_body()).await;
    let body_json: Value = serde_json::from_str(&body_str).unwrap();
    let token = body_json.get("token").unwrap().as_str().unwrap();

    // 3. Login using the token
    let login_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/auth/magic-link/login?token={}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(login_response.status(), StatusCode::OK);
    let login_headers = login_response.headers();
    let session_cookie = login_headers
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(session_cookie.contains("session_token="));

    // Extract raw session token value
    let cookie_val = session_cookie
        .split(';')
        .next()
        .unwrap()
        .split('=')
        .nth(1)
        .unwrap();

    // 4. Access secure endpoint listing sessions using the session token in Cookie
    let sessions_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/auth/sessions")
                .header("Cookie", format!("session_token={}", cookie_val))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(sessions_response.status(), StatusCode::OK);
    let sessions_body = get_response_body(sessions_response.into_body()).await;
    let sessions_json: Value = serde_json::from_str(&sessions_body).unwrap();
    let sessions_arr = sessions_json.as_array().unwrap();
    assert_eq!(sessions_arr.len(), 1);
    let session_id = sessions_arr[0].get("id").unwrap().as_str().unwrap();

    // 5. Revoke session
    let revoke_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/auth/sessions/{}", session_id))
                .header("Cookie", format!("session_token={}", cookie_val))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(revoke_response.status(), StatusCode::OK);

    // 6. Verify accessing sessions now returns 401 Unauthorized
    let sessions_after_revoke = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/auth/sessions")
                .header("Cookie", format!("session_token={}", cookie_val))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(sessions_after_revoke.status(), StatusCode::UNAUTHORIZED);
}
