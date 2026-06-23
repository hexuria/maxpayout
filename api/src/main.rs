use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use api::auth::{
    list_active_sessions, login_passkey_finish, login_passkey_start, login_via_magic_link,
    register_passkey_finish, register_passkey_start, request_magic_link, revoke_other_sessions,
    revoke_session,
};
use api::middleware::{auth_middleware, rate_limiter_middleware, IpRateLimiter};
use api::{
    handlers::{award_points, get_account_status, set_referral_cookie, signup_user, AppState},
    run_migrations,
};

async fn health_check() -> &'static str {
    "OK"
}

async fn handle_404() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "Endpoint not found" })),
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "api=info,coordinator=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Database setup
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://localhost/rfn_dev".to_string());

    tracing::info!("Connecting to database at {}...", database_url);
    let pool = PgPool::connect(&database_url).await?;

    // Run schema setup migrations
    run_migrations(&pool).await;

    // Instantiate orchestrator aggregator
    let aggregator = Arc::new(coordinator::PgAccountAggregator::new(pool.clone()));

    // Spawn outbox coordinator daemon in background
    tracing::info!("Starting background orchestrator daemon...");
    let daemon_pool = pool.clone();
    let daemon_aggregator = aggregator.clone();
    let daemon_handle = tokio::spawn(coordinator::worker::start_orchestrator_daemon(
        daemon_aggregator,
        daemon_pool,
    ));

    // WebAuthn Setup (Relying Party ID and Origin)
    let rp_id = "localhost";
    let rp_origin = webauthn_rs::prelude::Url::parse("http://localhost:8080").unwrap();
    let webauthn = Arc::new(
        webauthn_rs::prelude::WebauthnBuilder::new(rp_id, &rp_origin)
            .unwrap()
            .build()
            .unwrap(),
    );

    // Rate Limiter Setup (e.g. 5 requests/sec replenish, max 10 requests burst)
    let rate_limiter = Arc::new(IpRateLimiter::new(5, 10));

    // Configure Axum routes
    let state = AppState {
        pool: pool.clone(),
        aggregator,
        rate_limiter,
        webauthn,
    };

    let auth_routes = Router::new()
        .route("/magic-link/request", post(request_magic_link))
        .route("/magic-link/login", get(login_via_magic_link))
        .route("/passkey/login/start", post(login_passkey_start))
        .route("/passkey/login/finish", post(login_passkey_finish))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limiter_middleware,
        ));

    let secure_auth_routes = Router::new()
        .route("/passkey/register/start", post(register_passkey_start))
        .route("/passkey/register/finish", post(register_passkey_finish))
        .route("/sessions", get(list_active_sessions))
        .route("/sessions/:id", delete(revoke_session))
        .route("/sessions/other", delete(revoke_other_sessions))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limiter_middleware,
        ));

    let app = Router::new()
        .route("/api/health", get(health_check))
        .route("/api/ref/:sponsor_id", get(set_referral_cookie))
        .route("/api/users/signup", post(signup_user))
        .route("/api/accounts/:id/award-points", post(award_points))
        .route("/api/accounts/:id/status", get(get_account_status))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limiter_middleware,
        ))
        .nest("/api/auth", auth_routes)
        .nest("/api/auth", secure_auth_routes)
        .fallback(handle_404)
        .with_state(state);

    // Bind and serve
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("Starting API server listening on {}...", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    // Shutdown daemon cleanly
    tracing::info!("Stopping orchestrator daemon...");
    daemon_handle.abort();
    let _ = daemon_handle.await;
    tracing::info!("Shutdown complete.");

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Signal received, starting graceful shutdown...");
}
