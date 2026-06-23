pub mod worker;

use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

// Re-map internal errors to a unified coordinator error
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

/// Postgres-backed Account Aggregator and Orchestrator.
pub struct PgAccountAggregator {
    pool: PgPool,
    pub flushline_repo: flushline::PgFlushlineRepository,
    pub matrix_repo: matrix::PgMatrixRepository,
    pub sponsor_repo: sponsor_allocator::PgSponsorRepository,
    pub pot_bonus_repo: potbonus::PgPotBonusRepository,
}

#[derive(Debug, Clone)]
pub struct CoordinatedState {
    pub account_id: Uuid,
    pub is_flushline_graduated: bool,
    pub is_matrix_cycled: bool,
    pub new_account_spawned: bool,
}

impl PgAccountAggregator {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool: pool.clone(),
            flushline_repo: flushline::PgFlushlineRepository::new(pool.clone()),
            matrix_repo: matrix::PgMatrixRepository::new(pool.clone()),
            sponsor_repo: sponsor_allocator::PgSponsorRepository::new(pool.clone()),
            pot_bonus_repo: potbonus::PgPotBonusRepository::new(pool),
        }
    }

    /// Process a single "Matrix Cycled" event transactionally.
    pub async fn handle_matrix_cycled(
        &self,
        event_id: Uuid,
        account_id: Uuid,
        matrix_id: Uuid,
    ) -> Result<Option<Uuid>, AggregatorError> {
        let mut tx = self.pool.begin().await?;

        // 1. Deduplication Check
        if self
            .mark_event_consumed(&mut tx, event_id, "MatrixCycled")
            .await
            .is_err()
        {
            // Event was already processed, early exit with Ok (idempotent)
            return Ok(None);
        }

        // 2. Fetch or create coordination state
        let mut state = self
            .get_or_create_coordination_state(&mut tx, account_id)
            .await?;
        state.is_matrix_cycled = true;

        // 3. Forward to Sponsor & PotBonus (using shared transaction)
        self.sponsor_repo
            .handle_matrix_cycled_tx(&mut tx, account_id, matrix_id)
            .await
            .map_err(|e| AggregatorError::Sponsor(e.to_string()))?;
        self.pot_bonus_repo
            .handle_matrix_cycled_tx(&mut tx, account_id, matrix_id)
            .await
            .map_err(|e| AggregatorError::PotBonus(e.to_string()))?;

        // 4. Force cycle the account with 9 points in Flushline
        let mut flushline = self
            .flushline_repo
            .load_tx(&mut tx)
            .await
            .map_err(|e| AggregatorError::Flushline(e.to_string()))?;

        let flushline_account_id = flushline::AccountId::from(account_id);

        let events = flushline
            .force_cycle(&flushline_account_id, 9)
            .map_err(|e| AggregatorError::Flushline(e.to_string()))?;

        // 5. Distribute 6 points to Queen cardline
        flushline
            .distribute_points_to_queen(6)
            .map_err(|e| AggregatorError::Flushline(e.to_string()))?;

        let mut all_events = events;
        all_events.extend(flushline.take_events());

        // 6. Save back Flushline & coordination states
        self.flushline_repo
            .save_tx(&mut tx, &flushline, &all_events)
            .await
            .map_err(|e| AggregatorError::Flushline(e.to_string()))?;
        self.save_coordination_state(&mut tx, &state).await?;

        tx.commit().await?;

        // Check if both criteria are now met for a free account spawn
        self.check_and_spawn_free_account(account_id).await
    }

    /// Process a single "Flushline Graduated" event transactionally.
    pub async fn handle_flushline_graduated(
        &self,
        event_id: Uuid,
        account_id: Uuid,
    ) -> Result<Option<Uuid>, AggregatorError> {
        let mut tx = self.pool.begin().await?;

        if self
            .mark_event_consumed(&mut tx, event_id, "FlushlineGraduated")
            .await
            .is_err()
        {
            return Ok(None);
        }

        let mut state = self
            .get_or_create_coordination_state(&mut tx, account_id)
            .await?;
        state.is_flushline_graduated = true;

        self.sponsor_repo
            .handle_flushline_graduated_tx(&mut tx, account_id)
            .await
            .map_err(|e| AggregatorError::Sponsor(e.to_string()))?;
        self.pot_bonus_repo
            .handle_flushline_graduated_tx(&mut tx, account_id)
            .await
            .map_err(|e| AggregatorError::PotBonus(e.to_string()))?;

        self.save_coordination_state(&mut tx, &state).await?;
        tx.commit().await?;

        self.check_and_spawn_free_account(account_id).await
    }

    /// Check if account coordinates qualify for free account creation, and perform it transactionally.
    pub async fn check_and_spawn_free_account(
        &self,
        account_id: Uuid,
    ) -> Result<Option<Uuid>, AggregatorError> {
        let mut tx = self.pool.begin().await?;

        let state = self
            .get_or_create_coordination_state(&mut tx, account_id)
            .await?;
        if state.is_flushline_graduated && state.is_matrix_cycled && !state.new_account_spawned {
            // 1. Allocate a sponsor from PgSponsorRepository
            let mut sponsor_service = self
                .sponsor_repo
                .load_tx(&mut tx)
                .await
                .map_err(|e| AggregatorError::Sponsor(e.to_string()))?;

            let new_account_id = Uuid::now_v7();

            let (sponsor_uuid, _sponsor_events) = sponsor_service
                .allocate_sponsor(new_account_id)
                .map_err(|e| AggregatorError::Sponsor(e.to_string()))?;

            self.sponsor_repo
                .save_tx(&mut tx, &sponsor_service)
                .await
                .map_err(|e| AggregatorError::Sponsor(e.to_string()))?;

            // 2. Create Flushline account
            let mut flushline = self
                .flushline_repo
                .load_tx(&mut tx)
                .await
                .map_err(|e| AggregatorError::Flushline(e.to_string()))?;

            let new_flushline_id = flushline::AccountId::from(new_account_id);
            let flushline_account = flushline::Account::new(
                new_flushline_id,
                format!("FreeAccount_{}", new_account_id),
            );

            let fl_events = flushline
                .add_account(flushline_account)
                .map_err(|e| AggregatorError::Flushline(e.to_string()))?;

            let old_flushline_id = flushline::AccountId::from(account_id);
            flushline.register_graduated(old_flushline_id);

            self.flushline_repo
                .save_tx(&mut tx, &flushline, &fl_events)
                .await
                .map_err(|e| AggregatorError::Flushline(e.to_string()))?;

            // 3. Add to sponsor's active matrix (if sponsor has an active matrix)
            if let Some(mut sponsor_matrix) = self
                .matrix_repo
                .find_active_by_owner_tx(&mut tx, matrix::AccountId::from(sponsor_uuid))
                .await
                .map_err(|e| AggregatorError::Matrix(e.to_string()))?
            {
                let new_matrix_account = matrix::Account::sponsored(
                    matrix::AccountId::from(new_account_id),
                    matrix::AccountId::from(sponsor_uuid),
                    format!("FreeAccount_{}", new_account_id),
                );
                sponsor_matrix
                    .add_account(new_matrix_account)
                    .map_err(|e| AggregatorError::Matrix(e.to_string()))?;

                if sponsor_matrix.is_full() {
                    let (new_m, _graduates, cycle_events) = sponsor_matrix
                        .cycle()
                        .map_err(|e| AggregatorError::Matrix(e.to_string()))?;

                    self.matrix_repo
                        .save_tx(&mut tx, &sponsor_matrix, &[])
                        .await
                        .map_err(|e| AggregatorError::Matrix(e.to_string()))?;
                    self.matrix_repo
                        .save_tx(&mut tx, &new_m, &cycle_events)
                        .await
                        .map_err(|e| AggregatorError::Matrix(e.to_string()))?;
                } else {
                    self.matrix_repo
                        .save_tx(&mut tx, &sponsor_matrix, &[])
                        .await
                        .map_err(|e| AggregatorError::Matrix(e.to_string()))?;
                }
            }

            // 4. Initialize a new matrix tree for the new owner
            let new_matrix = matrix::Matrix::new(matrix::AccountId::from(new_account_id));
            self.matrix_repo
                .save_tx(&mut tx, &new_matrix, &[])
                .await
                .map_err(|e| AggregatorError::Matrix(e.to_string()))?;

            // 5. Register new account in PotBonus to the same user
            let mut pot_bonus = self
                .pot_bonus_repo
                .load_tx(&mut tx)
                .await
                .map_err(|e| AggregatorError::PotBonus(e.to_string()))?;

            let user_uuid: Option<Uuid> = sqlx::query_scalar(
                "SELECT user_id FROM pot_bonus_registrations WHERE account_id = $1",
            )
            .bind(account_id)
            .fetch_optional(&mut *tx)
            .await?;

            if let Some(user_id) = user_uuid {
                pot_bonus.register_user_account(user_id, new_account_id);
                self.pot_bonus_repo
                    .save_tx(&mut tx, &pot_bonus)
                    .await
                    .map_err(|e| AggregatorError::PotBonus(e.to_string()))?;
            }

            // 6. Update coordination state
            let mut updated_state = state;
            updated_state.new_account_spawned = true;
            updated_state.is_flushline_graduated = false;
            updated_state.is_matrix_cycled = false;
            self.save_coordination_state(&mut tx, &updated_state)
                .await?;

            tx.commit().await?;
            Ok(Some(new_account_id))
        } else {
            Ok(None)
        }
    }

    async fn mark_event_consumed(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        event_id: Uuid,
        event_type: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO orchestrator_inbox_log (event_id, event_type) VALUES ($1, $2)")
            .bind(event_id)
            .bind(event_type)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    pub async fn get_or_create_coordination_state(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        account_id: Uuid,
    ) -> Result<CoordinatedState, sqlx::Error> {
        let row = sqlx::query(
            "SELECT is_flushline_graduated, is_matrix_cycled, new_account_spawned \
             FROM orchestrator_coordination_states WHERE account_id = $1",
        )
        .bind(account_id)
        .fetch_optional(&mut **tx)
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

    pub async fn save_coordination_state(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        state: &CoordinatedState,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO orchestrator_coordination_states (account_id, is_flushline_graduated, is_matrix_cycled, new_account_spawned, updated_at) \
             VALUES ($1, $2, $3, $4, NOW()) \
             ON CONFLICT (account_id) DO UPDATE SET \
                 is_flushline_graduated = EXCLUDED.is_flushline_graduated, \
                 is_matrix_cycled = EXCLUDED.is_matrix_cycled, \
                 new_account_spawned = EXCLUDED.new_account_spawned, \
                 updated_at = NOW()"
        )
        .bind(state.account_id)
        .bind(state.is_flushline_graduated)
        .bind(state.is_matrix_cycled)
        .bind(state.new_account_spawned)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
}
