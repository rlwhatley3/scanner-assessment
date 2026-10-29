use super::{app, create_rule, create_rule_set, create_version_in, send, valid_definition};
use axum::{Router, http::StatusCode};
use serde_json::json;

async fn seeded_app() -> Router {
    let db = secrets_scanner_api::db::Db::open_in_memory().expect("database should open");
    secrets_scanner_api::seed::seed_default_rule_set(&db)
        .await
        .expect("seed should run");
    secrets_scanner_api::routes::router(db, secrets_scanner_api::fingerprint_key::generate())
}

#[tokio::test]
async fn the_built_in_rules_are_seeded_as_a_named_rule_set() {
    let app = seeded_app().await;
    let (_, rule_sets) = send(&app, "GET", "/api/rule-sets", None).await;
    assert_eq!(rule_sets.as_array().map(Vec::len), Some(1));
    assert_eq!(rule_sets[0]["name"], "Built-in rules");
    assert_eq!(rule_sets[0]["versionCount"], 1);
    assert_eq!(rule_sets[0]["latestVersionId"], 1);

    let (_, version) = send(&app, "GET", "/api/rule-set-versions/1", None).await;
    assert_eq!(version["ruleSetId"], 1);
    assert_eq!(version["ruleSetName"], "Built-in rules");
    assert_eq!(version["number"], 1);
}

#[tokio::test]
async fn a_rule_set_needs_a_name_no_other_set_uses() {
    let app = app();
    let (status, created) = send(
        &app,
        "POST",
        "/api/rule-sets",
        Some(json!({ "name": "  Payments  ", "description": "Card data" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["name"], "Payments");
    assert_eq!(created["description"], "Card data");
    assert_eq!(created["versions"], json!([]));

    for name in ["", "   ", "payments", &"x".repeat(81)] {
        let (status, body) = send(
            &app,
            "POST",
            "/api/rule-sets",
            Some(json!({ "name": name })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{name:?}: {body}");
    }
}

#[tokio::test]
async fn a_rule_set_can_be_renamed_but_not_to_a_taken_name() {
    let app = app();
    let first = create_rule_set(&app, "Payments").await;
    create_rule_set(&app, "Identity").await;

    let (status, renamed) = send(
        &app,
        "PATCH",
        &format!("/api/rule-sets/{first}"),
        Some(json!({ "name": "Payments team", "description": "Owned by payments" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(renamed["name"], "Payments team");
    assert_eq!(renamed["description"], "Owned by payments");

    // Renaming a set to its own name, in another case, is fine; taking another set's isn't.
    let (status, _) = send(
        &app,
        "PATCH",
        &format!("/api/rule-sets/{first}"),
        Some(json!({ "name": "PAYMENTS TEAM" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = send(
        &app,
        "PATCH",
        &format!("/api/rule-sets/{first}"),
        Some(json!({ "name": "identity" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body["error"].as_str().unwrap().contains("already exists"));
}

#[tokio::test]
async fn versions_are_numbered_within_their_rule_set() {
    let app = app();
    let rule = create_rule(&app, valid_definition("AWS key")).await;
    let payments = create_rule_set(&app, "Payments").await;
    let identity = create_rule_set(&app, "Identity").await;
    let p1 = create_version_in(&app, payments, &[rule]).await;
    let i1 = create_version_in(&app, identity, &[rule]).await;
    let p2 = create_version_in(&app, payments, &[rule]).await;

    let (_, payments_set) = send(&app, "GET", &format!("/api/rule-sets/{payments}"), None).await;
    let numbers: Vec<_> = payments_set["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|version| {
            (
                version["id"].as_i64().unwrap(),
                version["number"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(numbers, [(p1, 1), (p2, 2)]);
    assert_eq!(payments_set["latestVersionId"], p2);

    let (_, identity_versions) = send(
        &app,
        "GET",
        &format!("/api/rule-set-versions?ruleSetId={identity}"),
        None,
    )
    .await;
    assert_eq!(identity_versions[0]["id"], i1);
    assert_eq!(identity_versions[0]["number"], 1);
    assert_eq!(identity_versions[0]["ruleSetName"], "Identity");
}

#[tokio::test]
async fn a_new_rule_set_can_start_as_a_copy_of_any_version() {
    let app = seeded_app().await;
    let (status, copy) = send(
        &app,
        "POST",
        "/api/rule-sets",
        Some(json!({ "name": "Strict", "fromVersionId": 1 })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{copy}");
    let version = &copy["versions"][0];
    assert_eq!(version["number"], 1);
    assert_eq!(version["parentId"], 1);
    let copy_id = version["id"].as_i64().unwrap();

    let (_, original) = send(&app, "GET", "/api/rule-set-versions/1", None).await;
    let (_, copied) = send(
        &app,
        "GET",
        &format!("/api/rule-set-versions/{copy_id}"),
        None,
    )
    .await;
    assert_eq!(copied["rules"], original["rules"]);
    assert_eq!(copied["ruleSetName"], "Strict");

    let (status, _) = send(
        &app,
        "POST",
        "/api/rule-sets",
        Some(json!({ "name": "Ghost", "fromVersionId": 99 })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn a_version_can_only_build_on_a_version_of_its_own_set() {
    let app = app();
    let rule = create_rule(&app, valid_definition("AWS key")).await;
    let payments = create_rule_set(&app, "Payments").await;
    let identity = create_rule_set(&app, "Identity").await;
    let payments_v1 = create_version_in(&app, payments, &[rule]).await;

    let (status, body) = send(
        &app,
        "POST",
        "/api/rule-set-versions",
        Some(json!({ "ruleSetId": identity, "parentId": payments_v1, "ruleIds": [rule] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body["error"].as_str().unwrap().contains("another rule set"));
}

#[tokio::test]
async fn an_archived_rule_set_is_hidden_and_takes_no_new_versions_or_sessions() {
    let app = app();
    let rule = create_rule(&app, valid_definition("AWS key")).await;
    let rule_set = create_rule_set(&app, "Old team").await;
    let version = create_version_in(&app, rule_set, &[rule]).await;
    let (status, archived) = send(
        &app,
        "PATCH",
        &format!("/api/rule-sets/{rule_set}"),
        Some(json!({ "archived": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(archived["archived"], true);

    let (_, visible) = send(&app, "GET", "/api/rule-sets", None).await;
    assert_eq!(visible, json!([]));
    let (_, all) = send(&app, "GET", "/api/rule-sets?includeArchived=true", None).await;
    assert_eq!(all.as_array().map(Vec::len), Some(1));

    let (status, body) = send(
        &app,
        "POST",
        "/api/rule-set-versions",
        Some(json!({ "ruleSetId": rule_set, "ruleIds": [rule] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body["error"].as_str().unwrap().contains("archived"));
    let (status, _) = send(
        &app,
        "POST",
        "/api/scan-sessions",
        Some(json!({ "ruleSetVersionId": version })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    send(
        &app,
        "PATCH",
        &format!("/api/rule-sets/{rule_set}"),
        Some(json!({ "archived": false })),
    )
    .await;
    let (status, session) = send(
        &app,
        "POST",
        "/api/scan-sessions",
        Some(json!({ "ruleSetVersionId": version })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(session["ruleSetName"], "Old team");
    assert_eq!(session["versionNumber"], 1);
}
