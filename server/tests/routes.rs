#[path = "routes/health.rs"]
mod health;
#[path = "routes/rule_set_versions.rs"]
mod rule_set_versions;
#[path = "routes/rule_sets.rs"]
mod rule_sets;
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
    // Axum's own rejections (e.g. a malformed body) are plain text, so read those as null.
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
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

/// Creates an empty rule set named `name` and returns its id.
pub async fn create_rule_set(app: &Router, name: &str) -> i64 {
    let (status, rule_set) =
        send(app, "POST", "/api/rule-sets", Some(json!({ "name": name }))).await;
    assert_eq!(status, StatusCode::CREATED, "{rule_set}");
    rule_set["id"].as_i64().expect("rule set should have an id")
}

/// Creates a version of `rule_set_id` from `rule_ids` and returns its id.
pub async fn create_version_in(app: &Router, rule_set_id: i64, rule_ids: &[i64]) -> i64 {
    let (status, version) = send(
        app,
        "POST",
        "/api/rule-set-versions",
        Some(json!({ "ruleSetId": rule_set_id, "ruleIds": rule_ids })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{version}");
    version["id"].as_i64().expect("version should have an id")
}

/// Creates a version from `rule_ids` in a new rule set of its own and returns the version's id.
pub async fn create_version(app: &Router, rule_ids: &[i64]) -> i64 {
    static NEXT_SET: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
    let number = NEXT_SET.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let rule_set_id = create_rule_set(app, &format!("Test set {number}")).await;
    create_version_in(app, rule_set_id, rule_ids).await
}
