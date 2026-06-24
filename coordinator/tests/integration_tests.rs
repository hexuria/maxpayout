use coordinator::{worker, PgAccountAggregator};
use sqlx::{PgPool, Row};
use uuid::Uuid;

static DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Re-creates clean database state and runs migrations for all sibling crates and coordinator.
async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://localhost/rfn_dev".to_string());

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to test database");

    // Clean up all tables across contexts
    let tables_to_drop = [
        "orchestrator_inbox_log",
        "orchestrator_coordination_states",
        "pot_bonus_weekly_cycles",
        "pot_bonus_weekly_graduations",
        "pot_bonus_registrations",
        "pot_bonus_state",
        "sponsor_pool",
        "sponsor_account_stats",
        "sponsor_service_state",
        "matrix_outbox",
        "matrix_slots",
        "matrices",
        "flushline_outbox",
        "flushline_accounts",
        "flushline_tiers",
    ];

    for table in tables_to_drop {
        sqlx::query(&format!("DROP TABLE IF EXISTS {} CASCADE", table))
            .execute(&pool)
            .await
            .expect("Failed to drop table");
    }

    // Run sibling crate migrations
    let migration_files = [
        include_str!("../../flushline/migrations/20260623000000_create_flushline_tables.sql"),
        include_str!("../../matrix/migrations/20260623000000_create_matrix_tables.sql"),
        include_str!(
            "../../sponsor_allocator/migrations/20260623000000_create_sponsor_allocator_tables.sql"
        ),
        include_str!("../../potbonus/migrations/20260623000000_create_pot_bonus_tables.sql"),
        include_str!("../migrations/20260624000000_create_coordination_tables.sql"),
    ];

    for migration in migration_files {
        for statement in migration.split(';') {
            let trimmed = statement.trim();
            if !trimmed.is_empty() {
                sqlx::query(trimmed)
                    .execute(&pool)
                    .await
                    .expect("Failed to run migration statement");
            }
        }
    }

    pool
}

#[tokio::test]
async fn test_matrix_cycled_saga_flow() {
    let _lock = DB_LOCK.lock().await;
    let pool = setup_test_db().await;
    let aggregator = PgAccountAggregator::new(pool.clone());

    let user_id = Uuid::now_v7();
    let account_id = Uuid::now_v7();
    let matrix_id = Uuid::now_v7();

    // 1. Seed initial data
    // We register the user and account in pot_bonus_registrations
    sqlx::query("INSERT INTO pot_bonus_registrations (account_id, user_id) VALUES ($1, $2)")
        .bind(account_id)
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

    // We seed a global sponsor service state so allocating doesn't fail on empty database
    sqlx::query(
        "INSERT INTO sponsor_service_state (id, active_strategy, last_allocated_index, max_pool_size) \
         VALUES (1, 'round_robin', 0, 10) \
         ON CONFLICT (id) DO NOTHING"
    )
    .execute(&pool)
    .await
    .unwrap();

    // Seed a sponsor in pool so free accounts can allocate sponsors
    let sponsor_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sponsor_account_stats (account_id, tier, cycle_count) VALUES ($1, 'King', 1)",
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

    // Add account to Flushline
    sqlx::query("INSERT INTO flushline_accounts (id, owner, tier, current_pts, cycle_count, graduated) VALUES ($1, 'UserAccount', 'Ten', 0, 0, FALSE)")
        .bind(account_id)
        .execute(&pool)
        .await
        .unwrap();

    // 2. Handle Matrix Cycled event
    let event_id = Uuid::now_v7();
    let spawn_res = aggregator
        .handle_matrix_cycled(event_id, account_id, matrix_id)
        .await
        .unwrap();

    // Verify duplication did NOT occur yet (flushline graduation not satisfied)
    assert!(spawn_res.is_none());

    // 3. Verify deduplication / idempotence logging
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM orchestrator_inbox_log WHERE event_id = $1)",
    )
    .bind(event_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(exists);

    // Verify duplicate replay is ignored safely
    let replay_res = aggregator
        .handle_matrix_cycled(event_id, account_id, matrix_id)
        .await
        .unwrap();
    assert!(replay_res.is_none());

    // 4. Verify coordination state is created and updated
    let state_row = sqlx::query("SELECT is_flushline_graduated, is_matrix_cycled, new_account_spawned FROM orchestrator_coordination_states WHERE account_id = $1")
        .bind(account_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let is_graduated: bool = state_row.get("is_flushline_graduated");
    let is_cycled: bool = state_row.get("is_matrix_cycled");
    assert!(!is_graduated);
    assert!(is_cycled);

    // 5. Verify PotBonus records the matrix cycle
    let bonus_cycles: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pot_bonus_weekly_cycles WHERE account_id = $1")
            .bind(account_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(bonus_cycles, 1);

    // 6. Verify SponsorAllocator has updated cycle stats
    let cycle_count: i32 =
        sqlx::query_scalar("SELECT cycle_count FROM sponsor_account_stats WHERE account_id = $1")
            .bind(account_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cycle_count, 1);

    // 7. Verify Flushline has received 9 points (driving it to at least Queen tier with leftovers cascading)
    let flushline_tier: Option<String> =
        sqlx::query_scalar("SELECT tier FROM flushline_accounts WHERE id = $1")
            .bind(account_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    // 9 points on fresh account drives: Ten (needs 1) -> Jack (needs 2) -> Queen (needs 3) -> King (leftovers cascade)
    // So it graduated past Ten and Jack, and is now at least in Queen, King, Ace, or completely graduated (None).
    if let Some(tier) = flushline_tier {
        assert_ne!(tier, "Ten");
        assert_ne!(tier, "Jack");
    }
}

#[tokio::test]
async fn test_full_free_account_duplication_saga() {
    let _lock = DB_LOCK.lock().await;
    let pool = setup_test_db().await;
    let aggregator = PgAccountAggregator::new(pool.clone());

    let user_id = Uuid::now_v7();
    let account_id = Uuid::now_v7();
    let matrix_id = Uuid::now_v7();

    // 1. Seed initial data
    sqlx::query("INSERT INTO pot_bonus_registrations (account_id, user_id) VALUES ($1, $2)")
        .bind(account_id)
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query(
        "INSERT INTO sponsor_service_state (id, active_strategy, last_allocated_index, max_pool_size) \
         VALUES (1, 'round_robin', 0, 10) \
         ON CONFLICT (id) DO NOTHING"
    )
    .execute(&pool)
    .await
    .unwrap();

    let sponsor_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sponsor_account_stats (account_id, tier, cycle_count) VALUES ($1, 'King', 1)",
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

    sqlx::query("INSERT INTO flushline_accounts (id, owner, tier, current_pts, cycle_count, graduated) VALUES ($1, 'UserAccount', 'Ten', 0, 0, FALSE)")
        .bind(account_id)
        .execute(&pool)
        .await
        .unwrap();

    // 2. Trigger FlushlineGraduated event (Saga criterion 1)
    let event1_id = Uuid::now_v7();
    let res1 = aggregator
        .handle_flushline_graduated(event1_id, account_id)
        .await
        .unwrap();
    assert!(res1.is_none());

    // 3. Trigger MatrixCycled event (Saga criterion 2)
    let event2_id = Uuid::now_v7();
    let res2 = aggregator
        .handle_matrix_cycled(event2_id, account_id, matrix_id)
        .await
        .unwrap();

    // The second condition is met, so duplication MUST occur!
    assert!(res2.is_some());
    let spawned_account_id = res2.unwrap();

    // 4. Verify coordination state shows new spawned account
    let state_row = sqlx::query("SELECT is_flushline_graduated, is_matrix_cycled, new_account_spawned FROM orchestrator_coordination_states WHERE account_id = $1")
        .bind(account_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let is_graduated: bool = state_row.get("is_flushline_graduated");
    let is_cycled: bool = state_row.get("is_matrix_cycled");
    let spawned: bool = state_row.get("new_account_spawned");
    assert!(!is_graduated); // reset
    assert!(!is_cycled); // reset
    assert!(spawned);

    // 5. Verify spawned account was added to Flushline (registered as new account, original marked graduated)
    let original_graduated: bool =
        sqlx::query_scalar("SELECT graduated FROM flushline_accounts WHERE id = $1")
            .bind(account_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(original_graduated);

    let spawned_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM flushline_accounts WHERE id = $1)")
            .bind(spawned_account_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(spawned_exists);

    // 6. Verify spawned account has a matrix tree created
    let matrix_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM matrices WHERE owner_id = $1)")
            .bind(spawned_account_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(matrix_exists);

    // 7. Verify sponsor allocation increments candidate's sponsorship count
    let sponsor_count: i32 =
        sqlx::query_scalar("SELECT sponsored_count FROM sponsor_pool WHERE account_id = $1")
            .bind(sponsor_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(sponsor_count, 1);
}

#[tokio::test]
async fn test_polling_outbox_worker_daemon() {
    let _lock = DB_LOCK.lock().await;
    let pool = setup_test_db().await;
    let aggregator = PgAccountAggregator::new(pool.clone());

    let user_id = Uuid::now_v7();
    let account_id = Uuid::now_v7();
    let matrix_id = Uuid::now_v7();

    // Initial setup
    sqlx::query("INSERT INTO pot_bonus_registrations (account_id, user_id) VALUES ($1, $2)")
        .bind(account_id)
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

    // Seed global sponsor state and pool so free duplication accounts can allocate
    sqlx::query(
        "INSERT INTO sponsor_service_state (id, active_strategy, last_allocated_index, max_pool_size) \
         VALUES (1, 'round_robin', 0, 10) \
         ON CONFLICT (id) DO NOTHING"
    )
    .execute(&pool)
    .await
    .unwrap();

    let sponsor_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sponsor_account_stats (account_id, tier, cycle_count) VALUES ($1, 'King', 1)",
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

    sqlx::query("INSERT INTO flushline_accounts (id, owner, tier, current_pts, cycle_count, graduated) VALUES ($1, 'UserAccount', 'Ten', 0, 0, FALSE)")
        .bind(account_id)
        .execute(&pool)
        .await
        .unwrap();

    // 1. Manually insert unprocessed outbox rows
    let m_event_id = Uuid::now_v7();
    sqlx::query("INSERT INTO matrix_outbox (event_id, account_id, matrix_id, processed) VALUES ($1, $2, $3, FALSE)")
        .bind(m_event_id)
        .bind(account_id)
        .bind(matrix_id)
        .execute(&pool)
        .await
        .unwrap();

    let f_event_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO flushline_outbox (event_id, account_id, processed) VALUES ($1, $2, FALSE)",
    )
    .bind(f_event_id)
    .bind(account_id)
    .execute(&pool)
    .await
    .unwrap();

    // 2. Start daemon background worker loop
    let aggregator_arc = std::sync::Arc::new(aggregator);
    let daemon_handle = tokio::spawn(worker::start_orchestrator_daemon(
        aggregator_arc.clone(),
        pool.clone(),
        50, // Poll every 50ms for tests
    ));

    // Wait a short time for polling to occur
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Terminate daemon background task
    daemon_handle.abort();

    // 3. Assert outboxes are now marked processed
    let m_processed: bool =
        sqlx::query_scalar("SELECT processed FROM matrix_outbox WHERE event_id = $1")
            .bind(m_event_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(m_processed);

    let f_processed: bool =
        sqlx::query_scalar("SELECT processed FROM flushline_outbox WHERE event_id = $1")
            .bind(f_event_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(f_processed);

    // 4. Assert coordination states show BOTH were fully processed
    let state_row = sqlx::query("SELECT is_flushline_graduated, is_matrix_cycled FROM orchestrator_coordination_states WHERE account_id = $1")
        .bind(account_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let is_graduated: bool = state_row.get("is_flushline_graduated");
    let is_cycled: bool = state_row.get("is_matrix_cycled");

    // Note: Since both were processed, check_and_spawn_free_account_tx triggered, spawned, and reset states to false
    // So is_graduated and is_cycled are reset back to FALSE (and new_account_spawned is true)
    let spawned: bool = sqlx::query_scalar(
        "SELECT new_account_spawned FROM orchestrator_coordination_states WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(spawned);
    assert!(!is_graduated);
    assert!(!is_cycled);
}
