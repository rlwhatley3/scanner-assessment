use super::{app, create_rule, create_version, send, valid_definition};
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn saving_a_version_snapshots_rules_and_clears_drafting() {
    let app = app();
    let id = create_rule(&app, valid_definition("AWS key")).await;
    let version = create_version(&app, &[id, id]).await;

    let (_, rule) = send(&app, "GET", &format!("/api/rules/{id}"), None).await;
    assert_eq!(rule["drafting"], false);
    assert_eq!(rule["version_ids"], json!([version]));

    let mut edited = valid_definition("AWS key");
    edited["pattern"] = json!("AKIA[0-9A-Z]{20}");
    let (status, _) = send(
        &app,
        "PUT",
        &format!("/api/rules/{id}"),
        Some(json!({ "definition": edited })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, detail) = send(
        &app,
        "GET",
        &format!("/api/rule-set-versions/{version}"),
        None,
    )
    .await;
    assert_eq!(detail["rule_count"], 1);
    assert_eq!(
        detail["rules"][0]["definition"]["pattern"],
        "AKIA[0-9A-Z]{16}"
    );
}

#[tokio::test]
async fn an_invalid_rule_blocks_the_whole_version() {
    let app = app();
    let good = create_rule(&app, valid_definition("AWS key")).await;
    let bad = create_rule(&app, json!({ "name": "Broken" })).await;

    let (status, body) = send(
        &app,
        "POST",
        "/api/rule-set-versions",
        Some(json!({ "rule_ids": [good, bad] })),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let errors = body["errors"].as_array().expect("errors should be listed");
    assert!(errors.iter().all(|error| error["rule_id"] == bad));
    let (_, versions) = send(&app, "GET", "/api/rule-set-versions", None).await;
    assert_eq!(versions, json!([]));
    let (_, rule) = send(&app, "GET", &format!("/api/rules/{good}"), None).await;
    assert_eq!(rule["drafting"], true);
}

#[tokio::test]
async fn two_rules_in_a_version_cannot_share_a_name() {
    let app = app();
    let first = create_rule(&app, valid_definition("AWS key")).await;
    let second = create_rule(&app, valid_definition("aws KEY ")).await;

    let (status, body) = send(
        &app,
        "POST",
        "/api/rule-set-versions",
        Some(json!({ "rule_ids": [first, second] })),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["errors"][0]["code"], "duplicate_name");
    assert_eq!(body["errors"][0]["rule_id"], second);
}

#[tokio::test]
async fn a_version_needs_rules_that_exist() {
    let app = app();
    let (status, _) = send(
        &app,
        "POST",
        "/api/rule-set-versions",
        Some(json!({ "rule_ids": [] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _) = send(
        &app,
        "POST",
        "/api/rule-set-versions",
        Some(json!({ "rule_ids": [42] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn archived_versions_are_hidden_unless_asked_for() {
    let app = app();
    let id = create_rule(&app, valid_definition("AWS key")).await;
    let first = create_version(&app, &[id]).await;
    let (status, second) = send(
        &app,
        "POST",
        "/api/rule-set-versions",
        Some(json!({ "parent_id": first, "rule_ids": [id] })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(second["parent_id"], first);

    let (status, archived) = send(
        &app,
        "PATCH",
        &format!("/api/rule-set-versions/{first}"),
        Some(json!({ "archived": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(archived["archived"], true);

    let (_, visible) = send(&app, "GET", "/api/rule-set-versions", None).await;
    assert_eq!(visible.as_array().map(Vec::len), Some(1));
    let (_, all) = send(
        &app,
        "GET",
        "/api/rule-set-versions?include_archived=true",
        None,
    )
    .await;
    assert_eq!(all.as_array().map(Vec::len), Some(2));
}
