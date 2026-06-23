use axum::{
    routing::{get, post},
    Router,
};
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use api::{
    handlers::{award_points, get_account_status, signup_user, AppState},
    run_migrations,
};

async fn health_check() -> &'static str {
    "OK"
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

    // Configure Axum routes
    let state = AppState {
        pool: pool.clone(),
        aggregator,
    };

    let app = Router::new()
        .route("/api/health", get(health_check))
        .route("/api/users/signup", post(signup_user))
        .route("/api/accounts/:id/award-points", post(award_points))
        .route("/api/accounts/:id/status", get(get_account_status))
        .with_state(state);

    // Bind and serve
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("Starting API server listening on {}...", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app)
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
