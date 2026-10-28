pub mod health;
pub mod scans;
mod whiteboard;

use crate::db::Db;
use axum::{Router, routing::get};
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

pub fn router(db: Db) -> Router {
    Router::new()
        .route("/api/health", get(health::health))
        .nest("/api/whiteboards", whiteboard::router())
        .nest("/api/scan-sessions", scans::router())
        .with_state(AppState::new(db))
}
