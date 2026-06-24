//! Daemon worker for polling transactional outboxes and driving the saga aggregator.

use crate::PgAccountAggregator;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Start a polling loop daemon in a background tokio task.
pub async fn start_orchestrator_daemon(
    aggregator: Arc<PgAccountAggregator>,
    pool: PgPool,
    poll_interval_ms: u64,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(poll_interval_ms));
    loop {
        interval.tick().await;

        // 1. Poll and process matrix outbox events
        if let Err(e) = process_matrix_outbox_events(&aggregator, &pool).await {
            eprintln!("Error processing matrix outbox events: {:?}", e);
        }

        // 2. Poll and process flushline outbox events
        if let Err(e) = process_flushline_outbox_events(&aggregator, &pool).await {
            eprintln!("Error processing flushline outbox events: {:?}", e);
        }
    }
}

async fn process_matrix_outbox_events(
    aggregator: &PgAccountAggregator,
    pool: &PgPool,
) -> Result<(), sqlx::Error> {
    let rows = sqlx::query(
        "SELECT event_id, account_id, matrix_id FROM matrix_outbox \
         WHERE processed = FALSE ORDER BY created_at ASC LIMIT 50",
    )
    .fetch_all(pool)
    .await?;

    for row in rows {
        let event_id: Uuid = row.get("event_id");
        let account_id: Uuid = row.get("account_id");
        let matrix_id: Uuid = row.get("matrix_id");

        match aggregator
            .handle_matrix_cycled(event_id, account_id, matrix_id)
            .await
        {
            Ok(_) => {
                sqlx::query("UPDATE matrix_outbox SET processed = TRUE WHERE event_id = $1")
                    .bind(event_id)
                    .execute(pool)
                    .await?;
            }
            Err(e) => {
                eprintln!(
                    "Aggregator daemon matrix cycled coordination failed for event {}: {:?}",
                    event_id, e
                );
            }
        }
    }

    Ok(())
}

async fn process_flushline_outbox_events(
    aggregator: &PgAccountAggregator,
    pool: &PgPool,
) -> Result<(), sqlx::Error> {
    let rows = sqlx::query(
        "SELECT event_id, account_id FROM flushline_outbox \
         WHERE processed = FALSE ORDER BY created_at ASC LIMIT 50",
    )
    .fetch_all(pool)
    .await?;

    for row in rows {
        let event_id: Uuid = row.get("event_id");
        let account_id: Uuid = row.get("account_id");

        match aggregator
            .handle_flushline_graduated(event_id, account_id)
            .await
        {
            Ok(_) => {
                sqlx::query("UPDATE flushline_outbox SET processed = TRUE WHERE event_id = $1")
                    .bind(event_id)
                    .execute(pool)
                    .await?;
            }
            Err(e) => {
                eprintln!(
                    "Aggregator daemon flushline graduated coordination failed for event {}: {:?}",
                    event_id, e
                );
            }
        }
    }

    Ok(())
}
