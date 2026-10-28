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
        Some(json!({ "rule_set_version_id": version })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(session["rule_set_version_id"], version);
    assert_eq!(session["last_ran"], json!(null));
    assert_eq!(session["scans"], json!([]));

    let id = session["id"].as_i64().unwrap();
    let (status, reopened) = send(&app, "GET", &format!("/api/scan-sessions/{id}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reopened["scan_count"], 0);

    let (_, versions) = send(&app, "GET", "/api/rule-set-versions", None).await;
    assert_eq!(versions[0]["scan_session_count"], 1);
}

#[tokio::test]
async fn a_session_needs_a_live_version() {
    let app = app();
    let (status, _) = send(
        &app,
        "POST",
        "/api/scan-sessions",
        Some(json!({ "rule_set_version_id": 7 })),
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
        Some(json!({ "rule_set_version_id": version })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body["message"].as_str().unwrap().contains("archived"));
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
            Some(json!({ "rule_set_version_id": version })),
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
