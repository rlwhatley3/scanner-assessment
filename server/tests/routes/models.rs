use crate::{app, send};
use axum::http::StatusCode;
use secrets_scanner_engine::VALUE_CLASSIFIER_SHA256;
use serde_json::json;

#[tokio::test]
async fn lists_the_loaded_models_and_the_rule_types_they_fit() {
    let (status, models) = send(&app(), "GET", "/api/models", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        models,
        json!([{
            "id": "value-classifier",
            "sha256": VALUE_CLASSIFIER_SHA256,
            "inputLength": 128,
            "detectionTypes": ["model_assessment"],
        }])
    );
}
