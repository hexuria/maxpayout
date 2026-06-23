use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;

use coordinator::PgAccountAggregator;

// Shared state for Axum handlers
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub aggregator: Arc<PgAccountAggregator>,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Flushline error: {0}")]
    Flushline(String),
    #[error("Matrix error: {0}")]
    Matrix(String),
    #[error("Account not found: {0}")]
    NotFound(Uuid),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ApiError::Database(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            ApiError::Flushline(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Matrix(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::NotFound(id) => (StatusCode::NOT_FOUND, format!("Account not found: {}", id)),
        };

        let body = Json(serde_json::json!({ "error": message }));
        (status, body).into_response()
    }
}

// ----------------------------------------------------------------------------
// POST /api/users/signup
// ----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SignupRequest {
    pub username: String,
    pub user_id: Option<Uuid>,
    pub account_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct SignupResponse {
    pub user_id: Uuid,
    pub account_id: Uuid,
    pub username: String,
}

pub async fn signup_user(
    State(state): State<AppState>,
    Json(payload): Json<SignupRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let user_id = payload.user_id.unwrap_or_else(Uuid::now_v7);
    let account_id = payload.account_id.unwrap_or_else(Uuid::now_v7);

    let mut tx = state.pool.begin().await?;

    // 1. Register account mapping in PotBonus context
    sqlx::query("INSERT INTO pot_bonus_registrations (account_id, user_id) VALUES ($1, $2)")
        .bind(account_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

    // 2. Initialize account in Flushline context (starts at Ten tier)
    sqlx::query(
        "INSERT INTO flushline_accounts (id, owner, tier, current_pts, cycle_count, graduated) \
         VALUES ($1, $2, 'Ten', 0, 0, FALSE)",
    )
    .bind(account_id)
    .bind(&payload.username)
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

    Ok((
        StatusCode::CREATED,
        Json(SignupResponse {
            user_id,
            account_id,
            username: payload.username,
        }),
    ))
}

// ----------------------------------------------------------------------------
// POST /api/accounts/:id/award-points
// ----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AwardPointsRequest {
    pub points: u32,
}

#[derive(Debug, Serialize)]
pub struct AwardPointsResponse {
    pub account_id: Uuid,
    pub points_awarded: u32,
    pub current_tier: Option<String>,
    pub current_pts: i32,
    pub graduated: bool,
}

pub async fn award_points(
    State(state): State<AppState>,
    Path(account_id): Path<Uuid>,
    Json(payload): Json<AwardPointsRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let mut tx = state.pool.begin().await?;

    // Verify account exists
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM flushline_accounts WHERE id = $1)")
            .bind(account_id)
            .fetch_one(&mut *tx)
            .await?;

    if !exists {
        return Err(ApiError::NotFound(account_id));
    }

    // Load aggregate
    let mut flushline = state
        .aggregator
        .flushline_repo
        .load_tx(&mut tx)
        .await
        .map_err(|e| ApiError::Flushline(e.to_string()))?;

    let flushline_account_id = flushline::AccountId::from(account_id);

    // Apply points progression
    let events = flushline
        .force_cycle(&flushline_account_id, payload.points)
        .map_err(|e| ApiError::Flushline(e.to_string()))?;

    let mut all_events = events;
    all_events.extend(flushline.take_events());

    // Save and publish transactional outbox events
    state
        .aggregator
        .flushline_repo
        .save_tx(&mut tx, &flushline, &all_events)
        .await
        .map_err(|e| ApiError::Flushline(e.to_string()))?;

    // Query updated state from database (within same transaction to ensure consistency)
    let row =
        sqlx::query("SELECT tier, current_pts, graduated FROM flushline_accounts WHERE id = $1")
            .bind(account_id)
            .fetch_one(&mut *tx)
            .await?;

    let current_tier: Option<String> = row.get("tier");
    let current_pts: i32 = row.get("current_pts");
    let graduated: bool = row.get("graduated");

    tx.commit().await?;

    Ok((
        StatusCode::OK,
        Json(AwardPointsResponse {
            account_id,
            points_awarded: payload.points,
            current_tier,
            current_pts,
            graduated,
        }),
    ))
}

// ----------------------------------------------------------------------------
// GET /api/accounts/:id/status
// ----------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct AccountStatusResponse {
    pub account_id: Uuid,
    pub flushline: Option<FlushlineStatus>,
    pub matrix: Option<MatrixStatus>,
    pub potbonus: Option<PotBonusStatus>,
    pub coordination_state: Option<CoordinationStatus>,
}

#[derive(Debug, Serialize)]
pub struct FlushlineStatus {
    pub tier: Option<String>,
    pub current_pts: i32,
    pub cycle_count: i32,
    pub graduated: bool,
}

#[derive(Debug, Serialize)]
pub struct MatrixStatus {
    pub matrix_id: Uuid,
    pub status: String,
    pub slots: Vec<i32>,
}

#[derive(Debug, Serialize)]
pub struct PotBonusStatus {
    pub user_id: Uuid,
    pub cycle_count: i32,
    pub graduation_count: i32,
}

#[derive(Debug, Serialize)]
pub struct CoordinationStatus {
    pub is_flushline_graduated: bool,
    pub is_matrix_cycled: bool,
    pub new_account_spawned: bool,
}

pub async fn get_account_status(
    State(state): State<AppState>,
    Path(account_id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    // 1. Fetch Flushline Info
    let fl_row = sqlx::query(
        "SELECT tier, current_pts, cycle_count, graduated FROM flushline_accounts WHERE id = $1",
    )
    .bind(account_id)
    .fetch_optional(&state.pool)
    .await?;

    let flushline = fl_row.map(|r| FlushlineStatus {
        tier: r.get::<Option<String>, _>("tier"),
        current_pts: r.get::<i32, _>("current_pts"),
        cycle_count: r.get::<i32, _>("cycle_count"),
        graduated: r.get::<bool, _>("graduated"),
    });

    // 2. Fetch Matrix Info
    let m_row = sqlx::query("SELECT id, status FROM matrices WHERE owner_id = $1")
        .bind(account_id)
        .fetch_optional(&state.pool)
        .await?;

    let matrix = if let Some(row) = m_row {
        let m_id: Uuid = row.get("id");
        let status: String = row.get("status");

        let slot_rows = sqlx::query("SELECT slot_number FROM matrix_slots WHERE matrix_id = $1")
            .bind(m_id)
            .fetch_all(&state.pool)
            .await?;

        let slots: Vec<i32> = slot_rows
            .into_iter()
            .map(|r| r.get("slot_number"))
            .collect();

        Some(MatrixStatus {
            matrix_id: m_id,
            status,
            slots,
        })
    } else {
        None
    };

    // 3. Fetch PotBonus Info
    let pb_row = sqlx::query("SELECT user_id FROM pot_bonus_registrations WHERE account_id = $1")
        .bind(account_id)
        .fetch_optional(&state.pool)
        .await?;

    let potbonus = if let Some(row) = pb_row {
        let user_id: Uuid = row.get("user_id");

        let cycle_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pot_bonus_weekly_cycles WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(&state.pool)
                .await?;

        let graduation_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pot_bonus_weekly_graduations WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(&state.pool)
        .await?;

        Some(PotBonusStatus {
            user_id,
            cycle_count: cycle_count as i32,
            graduation_count: graduation_count as i32,
        })
    } else {
        None
    };

    // 4. Fetch Coordination State Info
    let coord_row = sqlx::query(
        "SELECT is_flushline_graduated, is_matrix_cycled, new_account_spawned \
         FROM orchestrator_coordination_states WHERE account_id = $1",
    )
    .bind(account_id)
    .fetch_optional(&state.pool)
    .await?;

    let coordination_state = coord_row.map(|r| CoordinationStatus {
        is_flushline_graduated: r.get("is_flushline_graduated"),
        is_matrix_cycled: r.get("is_matrix_cycled"),
        new_account_spawned: r.get("new_account_spawned"),
    });

    if flushline.is_none() && matrix.is_none() && potbonus.is_none() && coordination_state.is_none()
    {
        return Err(ApiError::NotFound(account_id));
    }

    Ok((
        StatusCode::OK,
        Json(AccountStatusResponse {
            account_id,
            flushline,
            matrix,
            potbonus,
            coordination_state,
        }),
    ))
}
