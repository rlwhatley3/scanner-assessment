use super::{app, create_rule, create_version, send, valid_definition};
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn a_new_rule_is_stored_as_a_draft_with_an_empty_definition() {
    let app = app();
    let (status, rule) = send(&app, "POST", "/api/rules", Some(json!({}))).await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(rule["drafting"], true);
    // Stored in the engine's canonical shape: every field present, unset ones null.
    assert_eq!(rule["definition"]["name"], json!(null));
    assert_eq!(rule["definition"]["pattern"], json!(null));
    assert_eq!(rule["versionIds"], json!([]));

    let (_, rules) = send(&app, "GET", "/api/rules", None).await;
    assert_eq!(rules.as_array().map(Vec::len), Some(1));
}

#[tokio::test]
async fn a_draft_saves_without_validation() {
    let app = app();
    let id = create_rule(&app, json!({})).await;
    let (status, rule) = send(
        &app,
        "PUT",
        &format!("/api/rules/{id}"),
        Some(json!({ "definition": { "pattern": "(unclosed" } })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(rule["definition"]["pattern"], "(unclosed");
}

#[tokio::test]
async fn a_rule_in_a_version_must_stay_valid_when_saved() {
    let app = app();
    let id = create_rule(&app, valid_definition("AWS key")).await;
    create_version(&app, &[id]).await;

    let (status, body) = send(
        &app,
        "PUT",
        &format!("/api/rules/{id}"),
        Some(json!({ "definition": { "name": "AWS key", "pattern": "(unclosed" } })),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let errors = body["errors"].as_array().expect("errors should be listed");
    assert!(errors.iter().any(|error| error["field"] == "pattern"
        && error["code"] == "invalid_regex"
        && error["ruleId"] == id));
    assert!(errors.iter().any(|error| error["field"] == "severity"));
}

#[tokio::test]
async fn check_reports_errors_and_warnings_without_saving() {
    let app = app();
    let id = create_rule(&app, json!({})).await;
    let (status, check) = send(
        &app,
        "POST",
        &format!("/api/rules/{id}/check"),
        Some(json!({ "definition": { "pattern": "a*", "minEntropy": 9 } })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let codes: Vec<_> = check["errors"]
        .as_array()
        .expect("errors should be listed")
        .iter()
        .map(|error| {
            (
                error["field"].as_str().unwrap(),
                error["code"].as_str().unwrap(),
            )
        })
        .collect();
    assert!(codes.contains(&("name", "required")));
    assert!(codes.contains(&("min_entropy", "out_of_range")));
    assert_eq!(check["warnings"][0]["code"], "matches_empty");

    let (_, rule) = send(&app, "GET", &format!("/api/rules/{id}"), None).await;
    assert_eq!(rule["definition"]["pattern"], json!(null));
}

#[tokio::test]
async fn only_a_rule_in_no_version_can_be_deleted() {
    let app = app();
    let loose = create_rule(&app, json!({})).await;
    let used = create_rule(&app, valid_definition("AWS key")).await;
    create_version(&app, &[used]).await;

    let (status, _) = send(&app, "DELETE", &format!("/api/rules/{loose}"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = send(&app, "GET", &format!("/api/rules/{loose}"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, body) = send(&app, "DELETE", &format!("/api/rules/{used}"), None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body["error"].as_str().is_some());
}

#[tokio::test]
async fn a_definition_must_fit_the_rule_shape() {
    let app = app();
    let (status, _) = send(
        &app,
        "POST",
        "/api/rules",
        Some(json!({ "definition": [] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, body) = send(
        &app,
        "POST",
        "/api/rules",
        Some(json!({ "definition": { "nmae": "Typo" } })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body["error"].as_str().unwrap().contains("nmae"));
}

#[tokio::test]
async fn check_set_checks_rules_together_without_saving() {
    let app = app();
    let first = create_rule(&app, valid_definition("AWS key")).await;
    let second = create_rule(&app, valid_definition("aws key")).await;
    let other = create_rule(&app, valid_definition("Another key")).await;

    let (status, check) = send(
        &app,
        "POST",
        "/api/rules/check",
        Some(json!({ "ruleIds": [first, second] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let errors = check["errors"].as_array().expect("errors should be listed");
    assert!(!errors.is_empty());
    assert!(errors.iter().all(|error| error["code"] == "duplicate_name"));

    let (status, check) = send(
        &app,
        "POST",
        "/api/rules/check",
        Some(json!({ "ruleIds": [first, other] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(check["errors"], json!([]));

    // Nothing was saved: the rules are still drafts in no version.
    let (_, rule) = send(&app, "GET", &format!("/api/rules/{first}"), None).await;
    assert_eq!(rule["drafting"], true);
    assert_eq!(rule["versionIds"], json!([]));
}

#[tokio::test]
async fn check_set_rejects_unknown_and_repeated_rules() {
    let app = app();
    let id = create_rule(&app, valid_definition("AWS key")).await;

    let (status, _) = send(
        &app,
        "POST",
        "/api/rules/check",
        Some(json!({ "ruleIds": [id, 999] })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = send(
        &app,
        "POST",
        "/api/rules/check",
        Some(json!({ "ruleIds": [id, id] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn try_runs_an_unsaved_definition_on_sample_text_and_saves_nothing() {
    let app = app();
    let id = create_rule(&app, json!({})).await;
    let mut definition = valid_definition("AWS key");
    definition["enabled"] = json!(false);

    let (status, body) = send(
        &app,
        "POST",
        &format!("/api/rules/{id}/try"),
        Some(json!({ "definition": definition, "text": "key = AKIAABCDEFGHIJKLMNOP\n" })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let findings = body["findings"]
        .as_array()
        .expect("findings should be listed");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["kind"], "match");
    assert_eq!(findings[0]["violation"]["location"]["startLine"], 1);
    assert!(findings[0].get("id").is_none());
    assert!(!body.to_string().contains("ABCDEFGHIJKLMNOP"));

    // Neither the rule nor any session changed.
    let (_, rule) = send(&app, "GET", &format!("/api/rules/{id}"), None).await;
    assert_eq!(rule["definition"]["pattern"], json!(null));
    let (_, sessions) = send(&app, "GET", "/api/scan-sessions", None).await;
    assert_eq!(sessions, json!([]));
}

#[tokio::test]
async fn try_reports_a_broken_pattern_as_a_rule_error() {
    let app = app();
    let id = create_rule(&app, json!({})).await;
    let mut definition = valid_definition("AWS key");
    definition["pattern"] = json!("(unclosed");

    let (status, body) = send(
        &app,
        "POST",
        &format!("/api/rules/{id}/try"),
        Some(json!({ "definition": definition, "text": "anything" })),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["findings"][0]["kind"], "rule_error");
}

#[tokio::test]
async fn try_rejects_empty_text_and_unknown_rules() {
    let app = app();
    let id = create_rule(&app, json!({})).await;
    let definition = valid_definition("AWS key");

    let (status, _) = send(
        &app,
        "POST",
        &format!("/api/rules/{id}/try"),
        Some(json!({ "definition": definition, "text": "  " })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = send(
        &app,
        "POST",
        "/api/rules/9999/try",
        Some(json!({ "definition": definition, "text": "AKIAABCDEFGHIJKLMNOP" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
