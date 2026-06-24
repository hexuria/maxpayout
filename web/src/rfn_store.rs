use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::{Arc, OnceLock, RwLock};
use uuid::Uuid;

// ----------------------------------------------------------------------------
// Database Models
// ----------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub password_hash: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PasskeyRecord {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub passkey_json: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChallengeRecord {
    pub challenge_id: Uuid,
    pub user_id: Option<Uuid>,
    pub challenge_json: serde_json::Value,
    pub expires_at: DateTime<Utc>,
    pub email: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MagicLinkRecord {
    pub token: String,
    pub email: String,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub session_token: String,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FlushlineAccount {
    pub id: Uuid,
    pub owner: String,
    pub tier: String,
    pub current_pts: i32,
    pub cycle_count: i32,
    pub graduated: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Matrix {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub status: String, // "Filling", "Cycled"
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MatrixSlot {
    pub matrix_id: Uuid,
    pub slot_number: i32, // 1 to 7
    pub account_id: Uuid,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SponsorStats {
    pub account_id: Uuid,
    pub tier: String,
    pub cycle_count: i32,
    pub sponsored_count: i32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CoordinationState {
    pub account_id: Uuid,
    pub is_flushline_graduated: bool,
    pub is_matrix_cycled: bool,
    pub new_account_spawned: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RfnState {
    pub users: HashMap<Uuid, User>,
    pub passkeys: Vec<PasskeyRecord>,
    pub challenges: HashMap<Uuid, ChallengeRecord>,
    pub magic_links: HashMap<String, MagicLinkRecord>,
    pub sessions: HashMap<String, SessionRecord>,
    pub flushline_accounts: HashMap<Uuid, FlushlineAccount>,
    pub matrices: HashMap<Uuid, Matrix>,
    pub matrix_slots: Vec<MatrixSlot>,
    pub pot_bonus_registrations: HashMap<Uuid, Uuid>, // account_id -> user_id
    pub sponsor_stats: HashMap<Uuid, SponsorStats>,
    pub sponsor_pool: Vec<Uuid>,
    pub coordination_states: HashMap<Uuid, CoordinationState>,
    pub inbox_log: HashSet<Uuid>,
}

// ----------------------------------------------------------------------------
// Global OnceLock and IO Handling
// ----------------------------------------------------------------------------

static STATE_STORE: OnceLock<Arc<RwLock<RfnState>>> = OnceLock::new();

fn get_storage_path() -> String {
    let base_path = std::env::var("STORAGE_PATH").unwrap_or_else(|_| "/data".to_string());
    format!("{}/rfn_store.json", base_path)
}

pub fn get_state() -> Arc<RwLock<RfnState>> {
    STATE_STORE
        .get_or_init(|| {
            let path_str = get_storage_path();
            let path = Path::new(&path_str);

            let initial_state = if path.exists() {
                if let Ok(content) = fs::read_to_string(path) {
                    serde_json::from_str::<RfnState>(&content).unwrap_or_default()
                } else {
                    RfnState::default()
                }
            } else {
                // Seed default sponsor and pool for first-time runs
                let mut state = RfnState::default();
                let default_sponsor_id =
                    Uuid::parse_str("01900000-0000-0000-0000-000000000001").unwrap();
                state.sponsor_stats.insert(
                    default_sponsor_id,
                    SponsorStats {
                        account_id: default_sponsor_id,
                        tier: "King".to_string(),
                        cycle_count: 5,
                        sponsored_count: 0,
                    },
                );
                state.sponsor_pool.push(default_sponsor_id);
                state
            };

            Arc::new(RwLock::new(initial_state))
        })
        .clone()
}

pub fn save_state(state: &RfnState) {
    let path_str = get_storage_path();
    let path = Path::new(&path_str);

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            let _ = fs::create_dir_all(parent);
        }
    }

    if let Ok(content) = serde_json::to_string_pretty(state) {
        let _ = fs::write(path, content);
    }
}

// ----------------------------------------------------------------------------
// Saga Core and Progression Logic (Sync implementation of AccountAggregator)
// ----------------------------------------------------------------------------

pub struct SagaCoordinator;

impl SagaCoordinator {
    /// Forces points progression. Triggers graduation and cascading outbox checks.
    pub fn award_points(state: &mut RfnState, account_id: Uuid, points: u32) -> Result<(), String> {
        let account = state
            .flushline_accounts
            .get_mut(&account_id)
            .ok_or_else(|| format!("Flushline account {} not found", account_id))?;

        account.current_pts += points as i32;
        if account.current_pts >= 15 && !account.graduated {
            account.graduated = true;
            account.cycle_count += 1;

            // Trigger Coordination: Flushline Graduated
            let coord = state
                .coordination_states
                .entry(account_id)
                .or_insert_with(|| CoordinationState {
                    account_id,
                    is_flushline_graduated: false,
                    is_matrix_cycled: false,
                    new_account_spawned: false,
                });
            coord.is_flushline_graduated = true;

            // Trigger PotBonus graduation count
            if let Some(user_id) = state.pot_bonus_registrations.get(&account_id) {
                println!(
                    "PotBonus: User {} account {} graduated!",
                    user_id, account_id
                );
            }
        }

        // Save progress
        save_state(state);

        // Check if qualifications for new free account are met
        Self::check_and_spawn_free_account(state, account_id)?;

        Ok(())
    }

    /// Recursively places an account into the sponsor's filling matrix tree.
    pub fn place_in_matrix(
        state: &mut RfnState,
        account_id: Uuid,
        sponsor_id: Uuid,
        _username: &str,
    ) -> Result<(), String> {
        // Find sponsor's active matrix
        let sponsor_matrix_id = state
            .matrices
            .iter()
            .find(|(_, m)| m.owner_id == sponsor_id && m.status == "Filling")
            .map(|(id, _)| *id);

        if let Some(matrix_id) = sponsor_matrix_id {
            // Find currently occupied slots
            let occupied_slots: Vec<i32> = state
                .matrix_slots
                .iter()
                .filter(|s| s.matrix_id == matrix_id)
                .map(|s| s.slot_number)
                .collect();

            // Find next free slot (1 to 7)
            let next_slot = (1..=7).find(|slot| !occupied_slots.contains(slot));

            if let Some(slot) = next_slot {
                state.matrix_slots.push(MatrixSlot {
                    matrix_id,
                    slot_number: slot,
                    account_id,
                });

                if slot == 7 {
                    // Matrix is now FULL (cycled!)
                    if let Some(matrix) = state.matrices.get_mut(&matrix_id) {
                        matrix.status = "Cycled".to_string();
                    }

                    // Increment sponsor's cycle stats
                    if let Some(stats) = state.sponsor_stats.get_mut(&sponsor_id) {
                        stats.cycle_count += 1;
                    }

                    // Trigger Coordination: Matrix Cycled
                    let coord = state
                        .coordination_states
                        .entry(sponsor_id)
                        .or_insert_with(|| CoordinationState {
                            account_id: sponsor_id,
                            is_flushline_graduated: false,
                            is_matrix_cycled: false,
                            new_account_spawned: false,
                        });
                    coord.is_matrix_cycled = true;

                    // Award 9 points to the sponsor in Flushline
                    let _ = Self::award_points(state, sponsor_id, 9);

                    // Distribute 6 points to Queen line (mocked representation)
                    println!("Matrix: Cardline distribution -> +6 Queen points from matrix cycle");

                    // Spawn a fresh matrix for the sponsor
                    let new_matrix_id = Uuid::new_v4();
                    state.matrices.insert(
                        new_matrix_id,
                        Matrix {
                            id: new_matrix_id,
                            owner_id: sponsor_id,
                            status: "Filling".to_string(),
                        },
                    );
                    state.matrix_slots.push(MatrixSlot {
                        matrix_id: new_matrix_id,
                        slot_number: 1,
                        account_id: sponsor_id,
                    });
                }
            }
        }

        save_state(state);
        Ok(())
    }

    /// Saga: checks coordination state and spawns a free account if qualified.
    pub fn check_and_spawn_free_account(
        state: &mut RfnState,
        account_id: Uuid,
    ) -> Result<Option<Uuid>, String> {
        let coord = match state.coordination_states.get(&account_id) {
            Some(c) => c.clone(),
            None => return Ok(None),
        };

        if coord.is_flushline_graduated && coord.is_matrix_cycled && !coord.new_account_spawned {
            // Allocate a sponsor
            let sponsor_id = Self::allocate_sponsor(state)?;

            // Mark spawned to avoid duplicate loops
            if let Some(c) = state.coordination_states.get_mut(&account_id) {
                c.new_account_spawned = true;
                c.is_flushline_graduated = false;
                c.is_matrix_cycled = false;
            }

            // Create new free account ID
            let new_account_id = Uuid::new_v4();
            let free_username = format!(
                "FreeAccount_{}",
                new_account_id.to_string()[..8].to_string()
            );

            // 1. Initialize in Flushline accounts
            state.flushline_accounts.insert(
                new_account_id,
                FlushlineAccount {
                    id: new_account_id,
                    owner: free_username.clone(),
                    tier: "Ten".to_string(),
                    current_pts: 0,
                    cycle_count: 0,
                    graduated: false,
                },
            );

            // 2. Map to user ID (same user owns the free account)
            if let Some(user_id) = state.pot_bonus_registrations.get(&account_id).cloned() {
                state
                    .pot_bonus_registrations
                    .insert(new_account_id, user_id);
            }

            // 3. Create a new matrix for the free account
            let new_matrix_id = Uuid::new_v4();
            state.matrices.insert(
                new_matrix_id,
                Matrix {
                    id: new_matrix_id,
                    owner_id: new_account_id,
                    status: "Filling".to_string(),
                },
            );
            state.matrix_slots.push(MatrixSlot {
                matrix_id: new_matrix_id,
                slot_number: 1,
                account_id: new_account_id,
            });

            // 4. Place the free account in the allocated sponsor's matrix
            Self::place_in_matrix(state, new_account_id, sponsor_id, &free_username)?;

            // Save final state
            save_state(state);

            println!(
                "Saga: Successfully spawned free account {} under sponsor {}",
                new_account_id, sponsor_id
            );
            Ok(Some(new_account_id))
        } else {
            Ok(None)
        }
    }

    /// Selects a sponsor from the sponsor pool.
    fn allocate_sponsor(state: &mut RfnState) -> Result<Uuid, String> {
        if state.sponsor_pool.is_empty() {
            return Err("Sponsor pool is empty".to_string());
        }

        // Find sponsor in pool with < 10 allocations
        for sponsor_id in &state.sponsor_pool {
            let stats = state
                .sponsor_stats
                .entry(*sponsor_id)
                .or_insert_with(|| SponsorStats {
                    account_id: *sponsor_id,
                    tier: "Ten".to_string(),
                    cycle_count: 0,
                    sponsored_count: 0,
                });

            if stats.sponsored_count < 10 {
                stats.sponsored_count += 1;
                save_state(state);
                return Ok(*sponsor_id);
            }
        }

        // Fallback: round-robin rotating the first sponsor in the pool
        let fallback_id = state.sponsor_pool[0];
        if let Some(stats) = state.sponsor_stats.get_mut(&fallback_id) {
            stats.sponsored_count += 1;
        }
        save_state(state);
        Ok(fallback_id)
    }
}
