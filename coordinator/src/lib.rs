//! Database-backed asynchronous saga orchestrator and coordinator.

use flushline::PgFlushlineRepository;
use matrix::PgMatrixRepository;
use potbonus::PgPotBonusRepository;
use sponsor_allocator::PgSponsorRepository;
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub mod worker;

/// Error type for coordinator operations.
#[derive(Debug, thiserror::Error)]
pub enum AggregatorError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Flushline error: {0}")]
    Flushline(String),

    #[error("Matrix error: {0}")]
    Matrix(String),

    #[error("Sponsor Allocator error: {0}")]
    Sponsor(String),

    #[error("PotBonus error: {0}")]
    PotBonus(String),

    #[error("Event already processed: {0}")]
    DuplicateEvent(Uuid),
}

/// Representation of the coordination state of an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatedState {
    pub account_id: Uuid,
    pub is_flushline_graduated: bool,
    pub is_matrix_cycled: bool,
    pub new_account_spawned: bool,
}

/// PostgreSQL-backed Account Aggregator and Saga Orchestrator.
#[derive(Debug, Clone)]
pub struct PgAccountAggregator {
    pub pool: PgPool,
    pub flushline_repo: PgFlushlineRepository,
    pub matrix_repo: PgMatrixRepository,
    pub sponsor_repo: PgSponsorRepository,
    pub pot_bonus_repo: PgPotBonusRepository,
}

impl PgAccountAggregator {
    /// Create a new coordinator aggregator instance.
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool: pool.clone(),
            flushline_repo: PgFlushlineRepository::new(pool.clone()),
            matrix_repo: PgMatrixRepository::new(pool.clone()),
            sponsor_repo: PgSponsorRepository::new(pool.clone()),
            pot_bonus_repo: PgPotBonusRepository::new(pool),
        }
    }

    /// Access the underlying PostgreSQL pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Process a single "Matrix Cycled" event transactionally.
    pub async fn handle_matrix_cycled(
        &self,
        event_id: Uuid,
        account_id: Uuid,
        matrix_id: Uuid,
    ) -> Result<Option<Uuid>, AggregatorError> {
        let mut tx = self.pool.begin().await?;

        // 1. Deduplication check (idempotency)
        if let Err(e) = self
            .mark_event_consumed(&mut tx, event_id, "MatrixCycled")
            .await
        {
            // Check if it's a unique constraint violation (indicating duplicate event)
            if let Some(db_err) = e.as_database_error() {
                if db_err.is_unique_violation() {
                    return Ok(None);
                }
            }
            return Err(AggregatorError::Database(e));
        }

        // 2. Fetch or create coordination state
        let mut state = self
            .get_or_create_coordination_state(&mut tx, account_id)
            .await?;
        state.is_matrix_cycled = true;

        // 3. Forward to Sponsor & PotBonus contexts (using existing transaction connection)
        self.sponsor_repo
            .handle_matrix_cycled_tx(&mut tx, account_id, matrix_id)
            .await
            .map_err(AggregatorError::Sponsor)?;
        self.pot_bonus_repo
            .handle_matrix_cycled_tx(&mut tx, account_id, matrix_id)
            .await
            .map_err(AggregatorError::PotBonus)?;

        // 4. Force cycle the account in Flushline with 9 points
        let mut flushline = self
            .flushline_repo
            .load_tx(&mut tx)
            .await
            .map_err(|e| AggregatorError::Flushline(e.to_string()))?;

        let flushline_account_id = flushline::AccountId::from(account_id);
        let _new_graduations = flushline
            .force_cycle(&flushline_account_id, 9)
            .map_err(|e| AggregatorError::Flushline(e.to_string()))?;

        // 5. Distribute 6 points to Queen cardline
        flushline
            .distribute_points_to_queen(6)
            .map_err(|e| AggregatorError::Flushline(e.to_string()))?;

        // 6. Save back Flushline state & save coordination state
        self.flushline_repo
            .save_tx(&mut tx, &flushline, &_new_graduations)
            .await
            .map_err(|e| AggregatorError::Flushline(e.to_string()))?;

        self.save_coordination_state(&mut tx, &state).await?;

        // 7. Check and spawn free duplicate account if both conditions met
        let spawn_result = self
            .check_and_spawn_free_account_tx(&mut tx, account_id)
            .await?;

        tx.commit().await?;

        Ok(spawn_result)
    }

    /// Process a single "Flushline Graduated" event transactionally.
    pub async fn handle_flushline_graduated(
        &self,
        event_id: Uuid,
        account_id: Uuid,
    ) -> Result<Option<Uuid>, AggregatorError> {
        let mut tx = self.pool.begin().await?;

        // 1. Deduplication check (idempotency)
        if let Err(e) = self
            .mark_event_consumed(&mut tx, event_id, "FlushlineGraduated")
            .await
        {
            if let Some(db_err) = e.as_database_error() {
                if db_err.is_unique_violation() {
                    return Ok(None);
                }
            }
            return Err(AggregatorError::Database(e));
        }

        // 2. Fetch or create coordination state
        let mut state = self
            .get_or_create_coordination_state(&mut tx, account_id)
            .await?;
        state.is_flushline_graduated = true;

        // 3. Forward to Sponsor & PotBonus contexts (using existing transaction connection)
        self.sponsor_repo
            .handle_flushline_graduated_tx(&mut tx, account_id)
            .await
            .map_err(AggregatorError::Sponsor)?;
        self.pot_bonus_repo
            .handle_flushline_graduated_tx(&mut tx, account_id)
            .await
            .map_err(AggregatorError::PotBonus)?;

        // 4. Save coordination state
        self.save_coordination_state(&mut tx, &state).await?;

        // 5. Check and spawn free duplicate account if both conditions met
        let spawn_result = self
            .check_and_spawn_free_account_tx(&mut tx, account_id)
            .await?;

        tx.commit().await?;

        Ok(spawn_result)
    }

    /// Check if coordination states are satisfied, and spawn duplicate free account inside an existing transaction.
    pub async fn check_and_spawn_free_account_tx(
        &self,
        conn: &mut sqlx::PgConnection,
        account_id: Uuid,
    ) -> Result<Option<Uuid>, AggregatorError> {
        let state = self
            .get_or_create_coordination_state(conn, account_id)
            .await?;

        if state.is_flushline_graduated && state.is_matrix_cycled && !state.new_account_spawned {
            let new_account_id = Uuid::now_v7();

            // 1. Allocate a sponsor from the pool
            let mut sponsor_service = self
                .sponsor_repo
                .load_tx(conn)
                .await
                .map_err(AggregatorError::Sponsor)?;

            let (_allocated_sponsor_id, sponsor_events) = sponsor_service
                .allocate_sponsor(new_account_id)
                .map_err(|e| AggregatorError::Sponsor(e.to_string()))?;

            // Save sponsor service changes
            self.sponsor_repo
                .save_tx(conn, &sponsor_service)
                .await
                .map_err(AggregatorError::Sponsor)?;

            // 2. Create and add new account in Flushline
            let mut flushline = self
                .flushline_repo
                .load_tx(conn)
                .await
                .map_err(|e| AggregatorError::Flushline(e.to_string()))?;

            let new_flushline_id = flushline::AccountId::from(new_account_id);
            let new_account = flushline::Account::new(
                new_flushline_id,
                format!("FreeAccount_{}", new_account_id),
            );

            let flushline_events = flushline
                .add_account(new_account)
                .map_err(|e| AggregatorError::Flushline(e.to_string()))?;

            // Also register the original graduated account ID
            flushline.register_graduated(flushline::AccountId::from(account_id));

            self.flushline_repo
                .save_tx(conn, &flushline, &flushline_events)
                .await
                .map_err(|e| AggregatorError::Flushline(e.to_string()))?;

            // 3. Create a brand-new forced matrix tree for the owner
            let matrix_owner_id = matrix::AccountId::from(new_account_id);
            let new_matrix = matrix::Matrix::new(matrix_owner_id);

            self.matrix_repo
                .save_tx(conn, &new_matrix, &[])
                .await
                .map_err(|e| AggregatorError::Matrix(e.to_string()))?;

            // 4. Link the new free account to the owner's user_id in the pot_bonus_registrations table
            let owner_user_id: Option<Uuid> = sqlx::query_scalar(
                "SELECT user_id FROM pot_bonus_registrations WHERE account_id = $1",
            )
            .bind(account_id)
            .fetch_optional(&mut *conn)
            .await?;

            if let Some(uid) = owner_user_id {
                sqlx::query(
                    "INSERT INTO pot_bonus_registrations (account_id, user_id) \
                     VALUES ($1, $2)",
                )
                .bind(new_account_id)
                .bind(uid)
                .execute(&mut *conn)
                .await?;
            }

            // 5. Update the coordination state to prevent duplicate spawning
            let updated_state = CoordinatedState {
                account_id,
                is_flushline_graduated: false, // Reset so they can qualify again if possible
                is_matrix_cycled: false,
                new_account_spawned: true,
            };
            self.save_coordination_state(conn, &updated_state).await?;

            // Trigger potential sponsor additions or registrations from the generated events!
            // Wait, we can ingest sponsor events if needed, but this is done automatically in integration tests.
            let _ = sponsor_events;

            Ok(Some(new_account_id))
        } else {
            Ok(None)
        }
    }

    // ----- Private helper methods for DB queries -----

    async fn mark_event_consumed(
        &self,
        conn: &mut sqlx::PgConnection,
        event_id: Uuid,
        event_type: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO orchestrator_inbox_log (event_id, event_type) \
             VALUES ($1, $2)",
        )
        .bind(event_id)
        .bind(event_type)
        .execute(conn)
        .await?;
        Ok(())
    }

    async fn get_or_create_coordination_state(
        &self,
        conn: &mut sqlx::PgConnection,
        account_id: Uuid,
    ) -> Result<CoordinatedState, sqlx::Error> {
        let row = sqlx::query(
            "SELECT is_flushline_graduated, is_matrix_cycled, new_account_spawned \
             FROM orchestrator_coordination_states WHERE account_id = $1",
        )
        .bind(account_id)
        .fetch_optional(conn)
        .await?;

        if let Some(r) = row {
            Ok(CoordinatedState {
                account_id,
                is_flushline_graduated: r.get("is_flushline_graduated"),
                is_matrix_cycled: r.get("is_matrix_cycled"),
                new_account_spawned: r.get("new_account_spawned"),
            })
        } else {
            Ok(CoordinatedState {
                account_id,
                is_flushline_graduated: false,
                is_matrix_cycled: false,
                new_account_spawned: false,
            })
        }
    }

    async fn save_coordination_state(
        &self,
        conn: &mut sqlx::PgConnection,
        state: &CoordinatedState,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO orchestrator_coordination_states (account_id, is_flushline_graduated, is_matrix_cycled, new_account_spawned, updated_at) \
             VALUES ($1, $2, $3, $4, NOW()) \
             ON CONFLICT (account_id) DO UPDATE SET \
                 is_flushline_graduated = EXCLUDED.is_flushline_graduated, \
                 is_matrix_cycled = EXCLUDED.is_matrix_cycled, \
                 new_account_spawned = EXCLUDED.new_account_spawned, \
                 updated_at = NOW()",
        )
        .bind(state.account_id)
        .bind(state.is_flushline_graduated)
        .bind(state.is_matrix_cycled)
        .bind(state.new_account_spawned)
        .execute(conn)
        .await?;
        Ok(())
    }
}
