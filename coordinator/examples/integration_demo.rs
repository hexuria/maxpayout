use coordinator::worker::start_orchestrator_daemon;
use coordinator::PgAccountAggregator;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

static DB_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn setup_demo_db() -> PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://localhost/rfn_dev".to_string());

    println!("Connecting to database at {}...", database_url);
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

    println!("Running database migrations...");
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

/// Simulated Client API Request: User Signup
async fn signup_user(
    pool: &PgPool,
    user_id: Uuid,
    account_id: Uuid,
    owner_name: &str,
) -> Result<(), sqlx::Error> {
    println!(
        "API -> Signing up user '{}' (ID: {}) with Account ID: {}...",
        owner_name, user_id, account_id
    );
    let mut tx = pool.begin().await?;

    // 1. Register account mapping in PotBonus context
    sqlx::query("INSERT INTO pot_bonus_registrations (account_id, user_id) VALUES ($1, $2)")
        .bind(account_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    // 2. Initialize account in Flushline context (starts at Ten tier)
    sqlx::query("INSERT INTO flushline_accounts (id, owner, tier, current_pts, cycle_count, graduated) VALUES ($1, $2, 'Ten', 0, 0, FALSE)")
        .bind(account_id)
        .bind(owner_name)
        .execute(&mut *tx)
        .await?;

    // 3. Initialize matrix tree for the user
    let matrix_id = Uuid::now_v7();
    sqlx::query("INSERT INTO matrices (id, owner_id, status) VALUES ($1, $2, 'Filling')")
        .bind(matrix_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO matrix_slots (matrix_id, slot_number, account_id) VALUES ($1, 1, $2)")
        .bind(matrix_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    println!("API -> Signup transaction committed for '{}'.", owner_name);
    Ok(())
}

/// Simulated Client API Request: Award Points and Publish Outbox Events
async fn publish_graduation_and_cycle(pool: &PgPool, account_id: Uuid) -> Result<(), sqlx::Error> {
    println!(
        "API -> Simulating Graduation and Matrix Cycle for account: {}...",
        account_id
    );
    let mut tx = pool.begin().await?;

    // 1. Graduate the user in Flushline and write a FlushlineGraduated outbox event
    sqlx::query("UPDATE flushline_accounts SET graduated = TRUE, tier = NULL WHERE id = $1")
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO flushline_outbox (account_id) VALUES ($1)")
        .bind(account_id)
        .execute(&mut *tx)
        .await?;

    // 2. Cycle a matrix for the user and write a MatrixCycled outbox event
    let new_matrix_id = Uuid::now_v7();
    sqlx::query("INSERT INTO matrix_outbox (account_id, matrix_id) VALUES ($1, $2)")
        .bind(account_id)
        .bind(new_matrix_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    println!("API -> Event publication transaction committed.");
    Ok(())
}

#[tokio::main]
async fn main() {
    let _lock = DB_LOCK.lock().await;

    // 1. Startup Routine: Initialize pool, run migrations, and aggregator
    let pool = setup_demo_db().await;
    let aggregator = Arc::new(PgAccountAggregator::new(pool.clone()));

    // Seed a sponsor in the sponsor pool to allow free account spawning
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

    // 2. Startup Daemon Worker Task
    println!("Starting orchestrator background daemon worker...");
    let daemon_handle = tokio::spawn(start_orchestrator_daemon(
        aggregator.clone(),
        pool.clone(),
        100,
    ));

    // 3. Simulate Client Requests
    let user_id = Uuid::now_v7();
    let account_id = Uuid::now_v7();

    // Signup the user
    signup_user(&pool, user_id, account_id, "Alice")
        .await
        .unwrap();

    // Small delay to simulate user activity
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Publish graduation and cycle events (writes to the outbox tables)
    publish_graduation_and_cycle(&pool, account_id)
        .await
        .unwrap();

    // Wait a moment for the background polling daemon to process the outbox events
    println!("Waiting for daemon worker to poll and process outbox events...");
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // 4. Verify coordination outcomes
    println!("Verifying results in the database...");

    // Coordination state should show spawned = true
    let spawned: bool = sqlx::query_scalar(
        "SELECT new_account_spawned FROM orchestrator_coordination_states WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    println!(
        "Result -> New account spawned flag in coordination state: {}",
        spawned
    );

    // Free account should be spawned in Flushline (should be Queen with 2 points)
    let new_acc_row = sqlx::query("SELECT id, owner, tier, current_pts FROM flushline_accounts WHERE owner LIKE 'FreeAccount_%'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let free_id: Uuid = new_acc_row.get("id");
    let free_tier: String = new_acc_row.get("tier");
    let free_pts: i32 = new_acc_row.get("current_pts");
    println!(
        "Result -> Spawned Free Account ID: {}, Tier: {}, Points: {}",
        free_id, free_tier, free_pts
    );

    // PotBonus registrations should have registered the new account under Alice's user ID
    let new_pb_reg_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pot_bonus_registrations WHERE account_id = $1 AND user_id = $2",
    )
    .bind(free_id)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    println!(
        "Result -> Free account registered to user ID in PotBonus: {}",
        new_pb_reg_count == 1
    );

    // 5. Graceful Shutdown
    println!("Shutting down orchestrator background worker...");
    daemon_handle.abort();
    let _ = daemon_handle.await;
    println!("Orchestrator worker shut down. Integration demo complete.");
}
