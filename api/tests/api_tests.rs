use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::{get, post},
    Router,
};
use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;

use api::{
    handlers::{award_points, get_account_status, signup_user, AppState},
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
        sqlx::query(stmt)
            .execute(&pool)
            .await
            .expect("Failed to drop table");
    }

    run_migrations(&pool).await;

    pool
}

async fn get_response_body(body: Body) -> String {
    let bytes = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn test_api_full_flow() {
    let _lock = DB_LOCK.lock().await;
    let pool = setup_test_db().await;

    // Seed a sponsor in the sponsor pool
    let sponsor_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sponsor_account_stats (account_id, tier, cycle_count) VALUES ($1, 'King', 5)",
    )
    .bind(sponsor_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO sponsor_pool (account_id, sponsored_count) VALUES ($1, 0)")
        .bind(sponsor_id)
        .execute(&pool)
        .await
        .unwrap();

    // Setup active matrix for the sponsor
    let sponsor_matrix_id = Uuid::now_v7();
    sqlx::query("INSERT INTO matrices (id, owner_id, status) VALUES ($1, $2, 'Filling')")
        .bind(sponsor_matrix_id)
        .bind(sponsor_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO matrix_slots (matrix_id, slot_number, account_id) VALUES ($1, 1, $2)")
        .bind(sponsor_matrix_id)
        .bind(sponsor_id)
        .execute(&pool)
        .await
        .unwrap();

    // Setup app state and routing
    let aggregator = Arc::new(coordinator::PgAccountAggregator::new(pool.clone()));
    let rp_id = "localhost";
    let rp_origin = webauthn_rs::prelude::Url::parse("http://localhost:8080").unwrap();
    let webauthn = Arc::new(
        webauthn_rs::prelude::WebauthnBuilder::new(rp_id, &rp_origin)
            .unwrap()
            .build()
            .unwrap(),
    );
    let rate_limiter = Arc::new(api::middleware::IpRateLimiter::new(100, 200)); // higher limits for tests
    let state = AppState {
        pool: pool.clone(),
        aggregator: aggregator.clone(),
        rate_limiter,
        webauthn,
    };

    let app = Router::new()
        .route("/api/health", get(|| async { "OK" }))
        .route("/api/users/signup", post(signup_user))
        .route("/api/accounts/:id/award-points", post(award_points))
        .route("/api/accounts/:id/status", get(get_account_status))
        .with_state(state);

    // 1. Check health endpoint
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(get_response_body(response.into_body()).await, "OK");

    // 2. Signup User Alice
    let signup_payload = serde_json::json!({
        "username": "Alice"
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/users/signup")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&signup_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let res_body_str = get_response_body(response.into_body()).await;
    let res_json: Value = serde_json::from_str(&res_body_str).unwrap();
    let account_id_str = res_json.get("account_id").unwrap().as_str().unwrap();
    let account_id = Uuid::parse_str(account_id_str).unwrap();
    let user_id_str = res_json.get("user_id").unwrap().as_str().unwrap();
    let user_id = Uuid::parse_str(user_id_str).unwrap();

    // 3. Verify Initial Status
    let status_uri = format!("/api/accounts/{}/status", account_id);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&status_uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let res_body_str = get_response_body(response.into_body()).await;
    println!(
        "Status query response: status = {}, body = {}",
        status, res_body_str
    );
    assert_eq!(status, StatusCode::OK);

    let status_json: Value = serde_json::from_str(&res_body_str).unwrap();
    let fl_status = status_json.get("flushline").unwrap();
    assert_eq!(fl_status.get("tier").unwrap().as_str().unwrap(), "Ten");
    assert_eq!(fl_status.get("current_pts").unwrap().as_i64().unwrap(), 0);
    assert!(!fl_status.get("graduated").unwrap().as_bool().unwrap());

    // 4. Start Background Outbox Daemon
    let daemon_pool = pool.clone();
    let daemon_aggregator = aggregator.clone();
    let daemon_handle = tokio::spawn(coordinator::worker::start_orchestrator_daemon(
        daemon_aggregator,
        daemon_pool,
        100,
    ));

    // 5. Award Progression Points (award 15 points to trigger graduation)
    let points_payload = serde_json::json!({
        "points": 15
    });
    let award_uri = format!("/api/accounts/{}/award-points", account_id);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&award_uri)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&points_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let res_body_str = get_response_body(response.into_body()).await;
    println!(
        "Award points response: status = {}, body = {}",
        status, res_body_str
    );
    assert_eq!(status, StatusCode::OK);

    let points_json: Value = serde_json::from_str(&res_body_str).unwrap();
    assert!(points_json.get("graduated").unwrap().as_bool().unwrap());

    // 6. Write a MatrixCycled event to DB manually to complete the dual-qualification criteria
    let new_matrix_id = Uuid::now_v7();
    sqlx::query("INSERT INTO matrix_outbox (account_id, matrix_id) VALUES ($1, $2)")
        .bind(account_id)
        .bind(new_matrix_id)
        .execute(&pool)
        .await
        .unwrap();

    // Give background worker time to pick up and execute the dual graduation + cycle
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // 7. Verify Coordination result via status check
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(&status_uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let res_body_str = get_response_body(response.into_body()).await;
    let final_status_json: Value = serde_json::from_str(&res_body_str).unwrap();
    let coord_status = final_status_json.get("coordination_state").unwrap();

    // Coordination should show that a new free account was spawned
    assert!(coord_status
        .get("new_account_spawned")
        .unwrap()
        .as_bool()
        .unwrap());

    // Verify free account details exist in database
    let free_account_id_str: String = sqlx::query_scalar(
        "SELECT id::text FROM flushline_accounts WHERE owner LIKE 'FreeAccount_%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let free_account_id = Uuid::parse_str(&free_account_id_str).unwrap();

    // Verify the free account was registered to Alice's user ID in PotBonus registration table
    let pb_reg_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pot_bonus_registrations WHERE account_id = $1 AND user_id = $2",
    )
    .bind(free_account_id)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pb_reg_count, 1);

    // Stop daemon cleanly
    daemon_handle.abort();
    let _ = daemon_handle.await;
}
