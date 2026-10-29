use super::{app, create_rule, create_version, send, valid_definition};
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn a_session_starts_on_a_version_with_no_scans() {
    let app = app();
    let rule = create_rule(&app, valid_definition("AWS key")).await;
    let version = create_version(&app, &[rule]).await;

    let (status, session) = send(
        &app,
        "POST",
        "/api/scan-sessions",
        Some(json!({ "ruleSetVersionId": version })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(session["ruleSetVersionId"], version);
    assert_eq!(session["lastRan"], json!(null));
    assert_eq!(session["scanCount"], 0);

    let id = session["id"].as_i64().unwrap();
    let (status, reopened) = send(&app, "GET", &format!("/api/scan-sessions/{id}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reopened["scanCount"], 0);

    let (_, versions) = send(&app, "GET", "/api/rule-set-versions", None).await;
    assert_eq!(versions[0]["scanSessionCount"], 1);
}

#[tokio::test]
async fn a_session_needs_a_live_version() {
    let app = app();
    let (status, _) = send(
        &app,
        "POST",
        "/api/scan-sessions",
        Some(json!({ "ruleSetVersionId": 7 })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let rule = create_rule(&app, valid_definition("AWS key")).await;
    let version = create_version(&app, &[rule]).await;
    send(
        &app,
        "PATCH",
        &format!("/api/rule-set-versions/{version}"),
        Some(json!({ "archived": true })),
    )
    .await;
    let (status, body) = send(
        &app,
        "POST",
        "/api/scan-sessions",
        Some(json!({ "ruleSetVersionId": version })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body["error"].as_str().unwrap().contains("archived"));
}

#[tokio::test]
async fn sessions_list_newest_first() {
    let app = app();
    let rule = create_rule(&app, valid_definition("AWS key")).await;
    let version = create_version(&app, &[rule]).await;
    for _ in 0..2 {
        send(
            &app,
            "POST",
            "/api/scan-sessions",
            Some(json!({ "ruleSetVersionId": version })),
        )
        .await;
    }

    let (_, sessions) = send(&app, "GET", "/api/scan-sessions", None).await;
    let ids: Vec<_> = sessions
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids, [2, 1]);
}

#[tokio::test]
async fn a_reopened_session_lists_each_scan_with_its_findings() {
    let db = secrets_scanner_api::db::Db::open_in_memory().expect("database should open");
    secrets_scanner_api::seed::seed_default_rule_set(&db)
        .await
        .expect("seed should run");
    let app =
        secrets_scanner_api::routes::router(db, secrets_scanner_api::fingerprint_key::generate());
    let (_, session) = send(
        &app,
        "POST",
        "/api/scan-sessions",
        Some(json!({ "ruleSetVersionId": 1 })),
    )
    .await;
    let id = session["id"].as_i64().unwrap();
    let (status, _) = send(
        &app,
        "POST",
        &format!("/api/scan-sessions/{id}/scans"),
        Some(json!({ "text": "aws_access_key_id = AKIAZ7Q3LMN4XWY2PRT6\n" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (_, reopened) = send(&app, "GET", &format!("/api/scan-sessions/{id}"), None).await;
    let scan = &reopened["scans"][0];
    assert_eq!(reopened["scanCount"], 1);
    assert_eq!(scan["partial"], false);
    assert_eq!(
        scan["matchCount"],
        scan["findings"].as_array().unwrap().len()
    );
    assert!(
        scan["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["violation"]["ruleName"] == "AWS access key")
    );
    assert!(!reopened.to_string().contains("AKIAZ7Q3LMN4XWY2PRT6"));
}
