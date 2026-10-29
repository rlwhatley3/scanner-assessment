pub mod checksums;
mod error;
pub mod health;
pub mod models;
pub mod rule_set_versions;
pub mod rule_sets;
pub mod rules;
pub mod scan_sessions;
pub mod scans;
pub mod suppressions;
pub mod testing;
mod whiteboard;

pub use error::ErrorBody;

use crate::db::Db;
use axum::{Router, extract::FromRef, routing::get};
use secrets_scanner_engine::{FingerprintKey, Models, SECRET_DETECTOR_ONNX, VALUE_CLASSIFIER_ONNX};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// The models the API ships with and loads at startup, by readable name.
const BUNDLED_MODELS: &[(&str, &[u8])] = &[
    ("value-classifier", VALUE_CLASSIFIER_ONNX),
    ("secret-detector", SECRET_DETECTOR_ONNX),
];

/// How many scans may run at once. Scans run on this machine's CPU alongside the API, so extra
/// requests wait their turn instead of all competing at the same time.
pub const MAX_CONCURRENT_SCANS: usize = 4;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub scan_permits: Arc<Semaphore>,
    /// The models model rules can run, loaded once at startup.
    pub models: Arc<Models>,
    /// Each loaded model's readable name, by SHA-256.
    pub model_names: Arc<HashMap<String, String>>,
    /// Fingerprints matched values for suppressions. See `crate::fingerprint_key`.
    pub fingerprint_key: Arc<FingerprintKey>,
}

impl AppState {
    pub fn new(db: Db, fingerprint_key: FingerprintKey) -> Self {
        let mut models = Models::new();
        let mut model_names = HashMap::new();
        for &(name, bytes) in BUNDLED_MODELS {
            let sha256 = models
                .load(bytes)
                .unwrap_or_else(|error| panic!("the bundled model {name} should load: {error}"));
            model_names.insert(sha256, name.to_owned());
        }
        Self {
            db,
            scan_permits: Arc::new(Semaphore::new(MAX_CONCURRENT_SCANS)),
            models: Arc::new(models),
            model_names: Arc::new(model_names),
            fingerprint_key: Arc::new(fingerprint_key),
        }
    }
}

/// Lets handlers that only need the database take `State<Db>`.
impl FromRef<AppState> for Db {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
}

pub fn router(db: Db, fingerprint_key: FingerprintKey) -> Router {
    let state = AppState::new(db, fingerprint_key);
    Router::new()
        .route("/api/health", get(health::health))
        .route("/api/models", get(models::list))
        .route("/api/mcp", get(crate::mcp::describe))
        .nest("/api/rules", rules::router())
        .nest("/api/checksums", checksums::router())
        .nest("/api/rule-sets", rule_sets::router())
        .nest(
            "/api/rule-set-versions",
            rule_set_versions::router().merge(testing::version_router()),
        )
        .nest(
            "/api/scan-sessions",
            scan_sessions::router()
                .merge(scans::router())
                .merge(suppressions::router())
                .merge(testing::session_router()),
        )
        .nest("/api/whiteboards", whiteboard::router())
        .nest_service("/mcp", crate::mcp::service(state.clone()))
        .with_state(state)
}
