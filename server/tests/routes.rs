#[path = "routes/health.rs"]
mod health;
#[path = "routes/rule_set_versions.rs"]
mod rule_set_versions;
#[path = "routes/rules.rs"]
mod rules;
#[path = "routes/scan_sessions.rs"]
mod scan_sessions;
#[path = "routes/scans.rs"]
mod scans;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use secrets_scanner_api::{db::Db, routes};
use serde_json::{Value, json};
use tower::ServiceExt;

/// A router over a fresh in-memory database.
pub fn app() -> Router {
    routes::router(Db::open_in_memory().expect("in-memory database should open"))
}

/// Sends one request and returns the status and JSON body (null when empty).
pub async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let request = Request::builder().method(method).uri(uri);
    let request = match body {
        Some(body) => request
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
        None => request.body(Body::empty()),
    }
    .expect("request should build");
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("router should respond");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should read");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("body should be JSON")
    };
    (status, body)
}

pub fn valid_definition(name: &str) -> Value {
    json!({
        "name": name,
        "detectionType": "direct_credential",
        "severity": "high",
        "pattern": "AKIA[0-9A-Z]{16}",
        "prefix": "AKIA",
        "remediation": "Rotate the key."
    })
}

/// Creates a rule with `definition` and returns its id.
pub async fn create_rule(app: &Router, definition: Value) -> i64 {
    let (status, rule) = send(
        app,
        "POST",
        "/api/rules",
        Some(json!({ "definition": definition })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    rule["id"].as_i64().expect("rule should have an id")
}

/// Creates a version from `rule_ids` and returns its id.
pub async fn create_version(app: &Router, rule_ids: &[i64]) -> i64 {
    let (status, version) = send(
        app,
        "POST",
        "/api/rule-set-versions",
        Some(json!({ "ruleIds": rule_ids })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{version}");
    version["id"].as_i64().expect("version should have an id")
}
