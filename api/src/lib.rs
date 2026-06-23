pub mod auth;
pub mod handlers;
pub mod middleware;

use sqlx::PgPool;

pub async fn run_migrations(pool: &PgPool) {
    let migration_files = [
        include_str!("../../flushline/migrations/20260623000000_create_flushline_tables.sql"),
        include_str!("../../matrix/migrations/20260623000000_create_matrix_tables.sql"),
        include_str!("../../potbonus/migrations/20260623000000_create_pot_bonus_tables.sql"),
        include_str!(
            "../../sponsor_allocator/migrations/20260623000000_create_sponsor_allocator_tables.sql"
        ),
        include_str!("../../coordinator/migrations/20260624000000_create_coordination_tables.sql"),
        include_str!("../migrations/20260625000000_create_auth_tables.sql"),
    ];

    tracing::info!("Running database migrations...");
    for file_content in &migration_files {
        for statement in file_content.split(';') {
            let trimmed = statement.trim();
            if !trimmed.is_empty() {
                sqlx::query(trimmed)
                    .execute(pool)
                    .await
                    .expect("Failed to execute migration statement");
            }
        }
    }
    tracing::info!("Database migrations complete.");
}
