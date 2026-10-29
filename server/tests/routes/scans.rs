use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use secrets_scanner_api::{db::Db, routes, seed::seed_default_rule_set};
use serde_json::{Value, json};
use tower::ServiceExt;

const AWS_KEY: &str = "AKIAZ7Q3LMN4XWY2PRT6";

/// An app on a fresh database with the built-in rule set seeded and scan session 1 on it.
async fn app() -> (Router, Db) {
    let db = Db::open_in_memory().expect("in-memory database should open");
    seed_default_rule_set(&db).await.expect("seed should run");
    db.call(|connection| {
        connection.execute(
            "INSERT INTO scan_sessions (rule_set_version_id) VALUES (1)",
            [],
        )
    })
    .await
    .expect("scan session should insert");
    (routes::router(db.clone()), db)
}

async fn post_scan(app: &Router, session: i64, body: Value) -> (StatusCode, Value) {
    let request = Request::post(format!("/api/scan-sessions/{session}/scans"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request should build");
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("request should run");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should read");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn count(db: &Db, sql: &'static str) -> i64 {
    db.call(move |connection| connection.query_row(sql, [], |row| row.get(0)))
        .await
        .expect("count should run")
}

/// Rewrites every rule snapshot in rule set version 1 with a JSON patch.
async fn patch_rules(db: &Db, sql: &'static str) {
    db.call(move |connection| connection.execute(sql, []))
        .await
        .expect("rule snapshots should update");
}

#[tokio::test]
async fn seeding_twice_leaves_one_built_in_rule_set() {
    let (_, db) = app().await;
    seed_default_rule_set(&db)
        .await
        .expect("seed should run again");
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM rule_set_versions").await,
        1
    );
    let built_in = secrets_scanner_api::seed::built_in_rules().len() as i64;
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM rules WHERE drafting = 0").await,
        built_in
    );
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM rule_set_version_rules").await,
        built_in
    );
}

#[tokio::test]
async fn a_scan_is_saved_with_its_findings_and_the_session_is_marked_as_run() {
    let (app, db) = app().await;
    let (status, body) = post_scan(&app, 1, json!({ "text": format!("aws = {AWS_KEY}") })).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["scanId"], 1);
    assert_eq!(body["scanSessionId"], 1);
    assert_eq!(body["truncated"], false);
    assert_eq!(body["partial"], false);
    let findings = body["findings"]
        .as_array()
        .expect("findings should be a list");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["kind"], "match");
    assert_eq!(findings[0]["ruleId"], 1);
    assert_eq!(findings[0]["violation"]["ruleName"], "AWS access key");
    assert_eq!(findings[0]["violation"]["location"]["startColumn"], 7);
    assert_eq!(
        findings[0]["violationPretty"],
        "AWS access key (high) at line 1, column 7"
    );

    assert_eq!(count(&db, "SELECT COUNT(*) FROM scans").await, 1);
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM findings WHERE scan_id = 1 AND kind = 'match'"
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM scan_sessions WHERE last_ran IS NOT NULL"
        )
        .await,
        1
    );
}

#[tokio::test]
async fn neither_the_response_nor_the_database_contains_the_secret() {
    let (app, db) = app().await;
    let (status, body) = post_scan(&app, 1, json!({ "text": format!("aws = {AWS_KEY}") })).await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(!body.to_string().contains(AWS_KEY));

    let stored: String = db
        .call(|connection| {
            connection.query_row(
                "SELECT group_concat(violation || violation_pretty) FROM findings",
                [],
                |row| row.get(0),
            )
        })
        .await
        .expect("findings should read");
    assert!(!stored.contains(AWS_KEY));
}

#[tokio::test]
async fn a_broken_rule_is_saved_as_a_rule_error_and_the_scan_is_partial() {
    let (app, db) = app().await;
    patch_rules(
        &db,
        "UPDATE rule_set_version_rules SET definition = json_set(definition, '$.pattern', 'AKIA(')
         WHERE rule_id = 1",
    )
    .await;
    let (status, body) = post_scan(&app, 1, json!({ "text": "nothing to see" })).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["partial"], true);
    assert_eq!(body["findings"][0]["kind"], "rule_error");
    assert_eq!(body["findings"][0]["violation"]["field"], "pattern");
    assert_eq!(body["findings"][0]["violation"]["code"], "invalid_regex");
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM findings WHERE kind = 'rule_error'"
        )
        .await,
        1
    );
}

#[tokio::test]
async fn more_findings_than_the_cap_are_cut_short_and_marked_truncated() {
    let (app, db) = app().await;
    let text = format!("k = {AWS_KEY}\n").repeat(250);
    let (status, body) = post_scan(&app, 1, json!({ "text": text })).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["truncated"], true);
    assert_eq!(body["findings"].as_array().map(Vec::len), Some(200));
    assert_eq!(count(&db, "SELECT COUNT(*) FROM findings").await, 200);
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM scans WHERE truncated = 1").await,
        1
    );
}

#[tokio::test]
async fn an_unknown_session_is_not_found_and_nothing_is_saved() {
    let (app, db) = app().await;
    let (status, body) = post_scan(&app, 99, json!({ "text": "aws" })).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["error"].as_str().is_some());
    assert_eq!(count(&db, "SELECT COUNT(*) FROM scans").await, 0);
}

#[tokio::test]
async fn rejected_scans_are_not_saved() {
    let (app, db) = app().await;

    let (status, _) = post_scan(&app, 1, json!({ "text": "   \n" })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let too_large = "a".repeat(1024 * 1024 + 1);
    let (status, _) = post_scan(&app, 1, json!({ "text": too_large })).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    patch_rules(
        &db,
        "UPDATE rule_set_version_rules SET definition = json_set(definition, '$.enabled', json('false'))",
    )
    .await;
    let (status, body) = post_scan(&app, 1, json!({ "text": "aws" })).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"], "No rules are enabled in this rule set.");

    assert_eq!(count(&db, "SELECT COUNT(*) FROM scans").await, 0);
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM scan_sessions WHERE last_ran IS NULL"
        )
        .await,
        1
    );
}

#[tokio::test]
async fn a_request_with_unknown_fields_is_rejected() {
    let (app, db) = app().await;
    let (status, _) = post_scan(&app, 1, json!({ "text": "aws", "ruleSet": {} })).await;
    assert!(status.is_client_error());
    assert_eq!(count(&db, "SELECT COUNT(*) FROM scans").await, 0);
}

#[test]
fn scans_are_capped_at_a_fixed_number_running_at_once() {
    let state = routes::AppState::new(Db::open_in_memory().expect("database should open"));
    assert_eq!(
        state.scan_permits.available_permits(),
        routes::MAX_CONCURRENT_SCANS
    );
}

#[tokio::test]
async fn the_value_classifier_lowers_confidence_for_a_hash_under_a_secret_name() {
    let (app, _) = app().await;
    let text =
        "password_hash: sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n";
    let (status, body) = post_scan(&app, 1, json!({ "text": text })).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["partial"], false);
    let violation = &body["findings"][0]["violation"];
    assert_eq!(violation["valueClass"]["label"], "non_secret");
    assert_eq!(violation["confidence"], 30);
}
