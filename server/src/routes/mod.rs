mod error;
pub mod health;
pub mod rule_set_versions;
pub mod rules;
pub mod scan_sessions;
mod whiteboard;

pub use error::ErrorBody;

use crate::db::Db;
use axum::{Router, routing::get};

pub fn router(db: Db) -> Router {
    Router::new()
        .route("/api/health", get(health::health))
        .nest("/api/rules", rules::router())
        .nest("/api/rule-set-versions", rule_set_versions::router())
        .nest("/api/scan-sessions", scan_sessions::router())
        .nest("/api/whiteboards", whiteboard::router())
        .with_state(db)
}
