use super::{
    app, create_rule, create_rule_set, create_version, create_version_in, send, valid_definition,
};
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn saving_a_version_snapshots_rules_and_clears_drafting() {
    let app = app();
    let id = create_rule(&app, valid_definition("AWS key")).await;
    let version = create_version(&app, &[id]).await;

    let (_, rule) = send(&app, "GET", &format!("/api/rules/{id}"), None).await;
    assert_eq!(rule["drafting"], false);
    assert_eq!(rule["versionIds"], json!([version]));

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
    assert_eq!(detail["ruleCount"], 1);
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
        Some(json!({ "ruleSetId": create_rule_set(&app, "Team").await, "ruleIds": [good, bad] })),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let errors = body["errors"].as_array().expect("errors should be listed");
    assert!(errors.iter().all(|error| error["ruleId"] == bad));
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
        Some(
            json!({ "ruleSetId": create_rule_set(&app, "Team").await, "ruleIds": [first, second] }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["errors"][0]["code"], "duplicate_name");
    assert_eq!(body["errors"][0]["ruleId"], second);
}

#[tokio::test]
async fn a_version_rejects_a_rule_listed_twice() {
    let app = app();
    let id = create_rule(&app, valid_definition("AWS key")).await;
    let (status, body) = send(
        &app,
        "POST",
        "/api/rule-set-versions",
        Some(json!({ "ruleSetId": create_rule_set(&app, "Team").await, "ruleIds": [id, id] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body["error"].as_str().unwrap().contains("more than once"));
}

#[tokio::test]
async fn a_version_needs_rules_that_exist() {
    let app = app();
    let (status, _) = send(
        &app,
        "POST",
        "/api/rule-set-versions",
        Some(json!({ "ruleSetId": create_rule_set(&app, "Team").await, "ruleIds": [] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _) = send(
        &app,
        "POST",
        "/api/rule-set-versions",
        Some(json!({ "ruleSetId": create_rule_set(&app, "Other team").await, "ruleIds": [42] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn archived_versions_are_hidden_unless_asked_for() {
    let app = app();
    let id = create_rule(&app, valid_definition("AWS key")).await;
    let rule_set = create_rule_set(&app, "Team").await;
    let first = create_version_in(&app, rule_set, &[id]).await;
    let (status, second) = send(
        &app,
        "POST",
        "/api/rule-set-versions",
        Some(json!({ "ruleSetId": rule_set, "parentId": first, "ruleIds": [id] })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(second["parentId"], first);

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
        "/api/rule-set-versions?includeArchived=true",
        None,
    )
    .await;
    assert_eq!(all.as_array().map(Vec::len), Some(2));
}

#[tokio::test]
async fn the_seeded_built_in_rules_save_as_a_new_version() {
    let db = secrets_scanner_api::db::Db::open_in_memory().expect("database should open");
    secrets_scanner_api::seed::seed_default_rule_set(&db)
        .await
        .expect("seed should run");
    let app = secrets_scanner_api::routes::router(db);

    let (_, rules) = send(&app, "GET", "/api/rules", None).await;
    let ids: Vec<_> = rules
        .as_array()
        .expect("rules should list")
        .iter()
        .map(|rule| rule["id"].as_i64().unwrap())
        .collect();
    let (status, version) = send(
        &app,
        "POST",
        "/api/rule-set-versions",
        Some(json!({ "ruleSetId": 1, "parentId": 1, "ruleIds": ids })),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "{version}");
    assert_eq!(version["ruleCount"], ids.len());
}
