mod error;
pub mod health;
pub mod rule_set_versions;
pub mod rule_sets;
pub mod rules;
pub mod scan_sessions;
pub mod scans;
mod whiteboard;

pub use error::ErrorBody;

use crate::db::Db;
use axum::{Router, extract::FromRef, routing::get};
use std::sync::Arc;
use tokio::sync::Semaphore;

/// How many scans may run at once. Scans run on this machine's CPU alongside the API, so extra
/// requests wait their turn instead of all competing at the same time.
pub const MAX_CONCURRENT_SCANS: usize = 4;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub scan_permits: Arc<Semaphore>,
}

impl AppState {
    pub fn new(db: Db) -> Self {
        Self {
            db,
            scan_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_SCANS)),
        }
    }
}

/// Lets handlers that only need the database take `State<Db>`.
impl FromRef<AppState> for Db {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
}

pub fn router(db: Db) -> Router {
    let state = AppState::new(db);
    Router::new()
        .route("/api/health", get(health::health))
        .nest("/api/rules", rules::router())
        .nest("/api/rule-sets", rule_sets::router())
        .nest("/api/rule-set-versions", rule_set_versions::router())
        .nest(
            "/api/scan-sessions",
            scan_sessions::router().merge(scans::router()),
        )
        .nest("/api/whiteboards", whiteboard::router())
        .nest_service("/mcp", crate::mcp::service(state.clone()))
        .with_state(state)
}
