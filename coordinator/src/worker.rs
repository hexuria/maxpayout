use crate::PgAccountAggregator;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct OutboxEvent {
    pub id: Uuid,
    pub account_id: Uuid,
    pub matrix_id: Option<Uuid>,
}

pub async fn start_orchestrator_daemon(aggregator: Arc<PgAccountAggregator>, pool: PgPool) {
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
    loop {
        interval.tick().await;

        // 1. Process Matrix Cycled Events
        if let Ok(events) = fetch_matrix_outbox(&pool).await {
            for event in events {
                if let Some(matrix_id) = event.matrix_id {
                    match aggregator
                        .handle_matrix_cycled(event.id, event.account_id, matrix_id)
                        .await
                    {
                        Ok(_) => {
                            let _ = mark_matrix_event_processed(&pool, event.id).await;
                        }
                        Err(e) => {
                            eprintln!(
                                "Error coordinating MatrixCycled event {}: {:?}",
                                event.id, e
                            );
                        }
                    }
                }
            }
        }

        // 2. Process Flushline Graduated Events
        if let Ok(events) = fetch_flushline_outbox(&pool).await {
            for event in events {
                match aggregator
                    .handle_flushline_graduated(event.id, event.account_id)
                    .await
                {
                    Ok(_) => {
                        let _ = mark_flushline_event_processed(&pool, event.id).await;
                    }
                    Err(e) => {
                        eprintln!(
                            "Error coordinating FlushlineGraduated event {}: {:?}",
                            event.id, e
                        );
                    }
                }
            }
        }
    }
}

pub async fn fetch_matrix_outbox(pool: &PgPool) -> Result<Vec<OutboxEvent>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT event_id, account_id, matrix_id FROM matrix_outbox WHERE processed = FALSE ORDER BY created_at ASC"
    )
    .fetch_all(pool)
    .await?;

    let events = rows
        .into_iter()
        .map(|row| OutboxEvent {
            id: row.get("event_id"),
            account_id: row.get("account_id"),
            matrix_id: Some(row.get("matrix_id")),
        })
        .collect();

    Ok(events)
}

pub async fn mark_matrix_event_processed(pool: &PgPool, event_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE matrix_outbox SET processed = TRUE WHERE event_id = $1")
        .bind(event_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn fetch_flushline_outbox(pool: &PgPool) -> Result<Vec<OutboxEvent>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT event_id, account_id FROM flushline_outbox WHERE processed = FALSE ORDER BY created_at ASC"
    )
    .fetch_all(pool)
    .await?;

    let events = rows
        .into_iter()
        .map(|row| OutboxEvent {
            id: row.get("event_id"),
            account_id: row.get("account_id"),
            matrix_id: None,
        })
        .collect();

    Ok(events)
}

pub async fn mark_flushline_event_processed(
    pool: &PgPool,
    event_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE flushline_outbox SET processed = TRUE WHERE event_id = $1")
        .bind(event_id)
        .execute(pool)
        .await?;
    Ok(())
}
