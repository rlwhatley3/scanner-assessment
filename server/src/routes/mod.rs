pub mod health;
mod whiteboard;

use crate::db::Db;
use axum::{Router, routing::get};

pub fn router(db: Db) -> Router {
    Router::new()
        .route("/api/health", get(health::health))
        .nest("/api/whiteboards", whiteboard::router())
        .with_state(db)
}
