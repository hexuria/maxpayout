use coordinator::PgAccountAggregator;
use sqlx::{PgPool, Row};
use uuid::Uuid;

static DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://localhost/rfn_dev".to_string());

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to test database");

    // Clean drop of all tables in dependency order
    let drop_statements = [
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

    // Execute migration scripts in correct order
    let migration_files = [
        include_str!("../../flushline/migrations/20260623000000_create_flushline_tables.sql"),
        include_str!("../../matrix/migrations/20260623000000_create_matrix_tables.sql"),
        include_str!("../../potbonus/migrations/20260623000000_create_pot_bonus_tables.sql"),
        include_str!(
            "../../sponsor_allocator/migrations/20260623000000_create_sponsor_allocator_tables.sql"
        ),
        include_str!("../migrations/20260624000000_create_coordination_tables.sql"),
    ];

    for file_content in &migration_files {
        for statement in file_content.split(';') {
            let trimmed = statement.trim();
            if !trimmed.is_empty() {
                sqlx::query(trimmed)
                    .execute(&pool)
                    .await
                    .expect("Failed to execute migration statement");
            }
        }
    }

    pool
}

#[tokio::test]
async fn test_event_deduplication() {
    let _lock = DB_LOCK.lock().await;
    let pool = setup_test_db().await;
    let aggregator = PgAccountAggregator::new(pool.clone());

    let event_id = Uuid::now_v7();
    let account_id = Uuid::now_v7();
    let matrix_id = Uuid::now_v7();

    // Setup the account in flushline to allow force_cycle loading
    sqlx::query("INSERT INTO flushline_accounts (id, owner, tier, current_pts, cycle_count, graduated) VALUES ($1, 'OriginalOwner', 'Ten', 0, 0, FALSE)")
        .bind(account_id)
        .execute(&pool)
        .await
        .unwrap();

    // 1. Process matrix cycled event first time
    let result = aggregator
        .handle_matrix_cycled(event_id, account_id, matrix_id)
        .await;
    assert!(result.is_ok());

    // Verify inbox log has 1 entry
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM orchestrator_inbox_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);

    // 2. Process the exact same event second time (should be a no-op / idempotent)
    let result_dup = aggregator
        .handle_matrix_cycled(event_id, account_id, matrix_id)
        .await;
    assert!(result_dup.is_ok());
    assert_eq!(result_dup.unwrap(), None);

    // Verify inbox log STILL has exactly 1 entry
    let count_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM orchestrator_inbox_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count_after, 1);
}

#[tokio::test]
async fn test_coordination_and_free_account_spawning() {
    let _lock = DB_LOCK.lock().await;
    let pool = setup_test_db().await;
    let aggregator = PgAccountAggregator::new(pool.clone());

    let user_id = Uuid::now_v7();
    let account_id = Uuid::now_v7();
    let sponsor_id = Uuid::now_v7();

    // Register user and account in PotBonus to allow qualifications recording
    sqlx::query("INSERT INTO pot_bonus_registrations (account_id, user_id) VALUES ($1, $2)")
        .bind(account_id)
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();

    // Set up active sponsor pool with a valid eligible sponsor candidate
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

    // Setup the account in flushline to allow force_cycle loading
    sqlx::query("INSERT INTO flushline_accounts (id, owner, tier, current_pts, cycle_count, graduated) VALUES ($1, 'OriginalOwner', 'Ten', 0, 0, FALSE)")
        .bind(account_id)
        .execute(&pool)
        .await
        .unwrap();

    // Trigger FlushlineGraduated event
    let event1_id = Uuid::now_v7();
    let res1 = aggregator
        .handle_flushline_graduated(event1_id, account_id)
        .await;
    assert!(res1.is_ok());
    assert_eq!(res1.unwrap(), None); // Matrix Cycled is still false, so no free account yet

    // Verify coordination state
    let state_row = sqlx::query("SELECT is_flushline_graduated, is_matrix_cycled, new_account_spawned FROM orchestrator_coordination_states WHERE account_id = $1")
        .bind(account_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(state_row.get::<bool, _>("is_flushline_graduated"));
    assert!(!state_row.get::<bool, _>("is_matrix_cycled"));

    // Trigger MatrixCycled event - this completes both criteria!
    let event2_id = Uuid::now_v7();
    let res2 = aggregator
        .handle_matrix_cycled(event2_id, account_id, Uuid::now_v7())
        .await;
    assert!(res2.is_ok());
    let spawned_id = res2.unwrap();
    assert!(spawned_id.is_some());
    let new_account_id = spawned_id.unwrap();

    // Verify new free account has been initialized in flushline
    let new_acc_row =
        sqlx::query("SELECT id, owner, tier, current_pts FROM flushline_accounts WHERE id = $1")
            .bind(new_account_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        new_acc_row.get::<String, _>("owner"),
        format!("FreeAccount_{}", new_account_id)
    );
    // Since it force-cycles with 5 points on add_account, it cycles Ten (1) and Jack (2), landing in Queen with 2 points:
    assert_eq!(new_acc_row.get::<String, _>("tier"), "Queen");
    assert_eq!(new_acc_row.get::<i32, _>("current_pts"), 2);

    // Verify the new account is registered to the same user in PotBonus
    let pb_reg_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pot_bonus_registrations WHERE account_id = $1 AND user_id = $2",
    )
    .bind(new_account_id)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pb_reg_count, 1);

    // Verify the new account is placed under sponsor's active matrix
    let slot_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM matrix_slots WHERE matrix_id = $1 AND account_id = $2",
    )
    .bind(sponsor_matrix_id)
    .bind(new_account_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(slot_count, 1);

    // Verify the coordination state has been reset for the original account
    let final_state_row = sqlx::query("SELECT is_flushline_graduated, is_matrix_cycled, new_account_spawned FROM orchestrator_coordination_states WHERE account_id = $1")
        .bind(account_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!final_state_row.get::<bool, _>("is_flushline_graduated"));
    assert!(!final_state_row.get::<bool, _>("is_matrix_cycled"));
    assert!(final_state_row.get::<bool, _>("new_account_spawned"));
}

#[tokio::test]
async fn test_transactional_rollback() {
    let _lock = DB_LOCK.lock().await;
    let pool = setup_test_db().await;
    let aggregator = PgAccountAggregator::new(pool.clone());

    let account_id = Uuid::now_v7();

    // Setup the account in flushline
    sqlx::query("INSERT INTO flushline_accounts (id, owner, tier, current_pts, cycle_count, graduated) VALUES ($1, 'OriginalOwner', 'Ten', 0, 0, FALSE)")
        .bind(account_id)
        .execute(&pool)
        .await
        .unwrap();

    // Trigger handle_matrix_cycled but since we have no sponsor pool set up,
    // the check_and_spawn_free_account will NOT be executed unless both criteria are met.
    // Let's set both criteria to true first by manually inserting coordination state
    sqlx::query("INSERT INTO orchestrator_coordination_states (account_id, is_flushline_graduated, is_matrix_cycled, new_account_spawned) VALUES ($1, TRUE, TRUE, FALSE)")
        .bind(account_id)
        .execute(&pool)
        .await
        .unwrap();

    // We do NOT seed any sponsor pool or pot_bonus registration.
    // The check_and_spawn_free_account should fail at sponsor allocation (due to empty pool)
    // which should abort/rollback the transaction.
    let result = aggregator.check_and_spawn_free_account(account_id).await;
    assert!(result.is_err());

    // Verify coordination state did NOT get updated/marked as spawned
    let state_row = sqlx::query("SELECT is_flushline_graduated, is_matrix_cycled, new_account_spawned FROM orchestrator_coordination_states WHERE account_id = $1")
        .bind(account_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(state_row.get::<bool, _>("is_flushline_graduated"));
    assert!(state_row.get::<bool, _>("is_matrix_cycled"));
    assert!(!state_row.get::<bool, _>("new_account_spawned"));
}
