use super::{create_rule, create_version, send, valid_definition};
use axum::{Router, http::StatusCode};
use secrets_scanner_api::{db::Db, fingerprint_key, routes, seed::seed_default_rule_set};
use secrets_scanner_engine::VALUE_CLASSIFIER_SHA256;
use serde_json::{Value, json};

const AWS_KEY: &str = "AKIAZ7Q3LMN4XWY2PRT6";

/// An app on a fresh database with the built-in rule set seeded as version 1.
async fn app() -> (Router, Db) {
    let db = Db::open_in_memory().expect("in-memory database should open");
    seed_default_rule_set(&db).await.expect("seed should run");
    (routes::router(db.clone(), fingerprint_key::generate()), db)
}

async fn count(db: &Db, sql: &'static str) -> i64 {
    db.call(move |connection| connection.query_row(sql, [], |row| row.get(0)))
        .await
        .expect("count should run")
}

async fn session(app: &Router, version_id: i64) -> i64 {
    let (status, session) = send(
        app,
        "POST",
        "/api/scan-sessions",
        Some(json!({ "ruleSetVersionId": version_id })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{session}");
    session["id"].as_i64().unwrap()
}

async fn run(app: &Router, session_id: i64, body: Value) -> (StatusCode, Value) {
    send(
        app,
        "POST",
        &format!("/api/scan-sessions/{session_id}/test-runs"),
        Some(body),
    )
    .await
}

/// Every case result in a report, by id.
fn case<'r>(report: &'r Value, id: &str) -> &'r Value {
    report["documents"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|document| document["cases"].as_array().unwrap())
        .find(|case| case["id"] == id)
        .unwrap_or_else(|| panic!("no case {id} in {report}"))
}

fn diagnostic<'r>(report: &'r Value, code: &str) -> Option<&'r Value> {
    report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|diagnostic| diagnostic["code"] == code)
}

/// A random-looking value made at runtime, so no secret-shaped string sits in the source.
fn token(length: usize) -> String {
    "Zq7Lm2Xc9Vb4Nn6Tt1Rr8Pp3Kk5Hh0Wd"
        .chars()
        .cycle()
        .skip(5)
        .take(length)
        .collect()
}

#[tokio::test]
async fn generates_the_same_labeled_data_for_a_seed_and_stores_nothing() {
    let (app, db) = app().await;
    let rules_before = count(&db, "SELECT COUNT(*) FROM rules").await;
    let (status, data) = send(
        &app,
        "POST",
        "/api/rule-set-versions/1/test-data",
        Some(json!({ "seed": 7 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{data}");
    assert_eq!(data["seed"], 7);
    let documents = data["documents"].as_array().unwrap();
    assert!(documents.len() >= 4);
    for document in documents {
        let text = document["text"].as_str().unwrap();
        for case in document["cases"].as_array().unwrap() {
            let (start, end) = (
                case["start"].as_u64().unwrap() as usize,
                case["end"].as_u64().unwrap() as usize,
            );
            assert_eq!(case["value"], text[start..end], "{}", case["id"]);
        }
    }
    let lookalikes = documents
        .iter()
        .find(|document| document["name"] == "lookalikes.yaml")
        .expect("a lookalikes file");
    assert!(
        lookalikes["cases"]
            .as_array()
            .unwrap()
            .iter()
            .all(|case| case["expect"] == "not_secret" && case["ruleId"].is_null())
    );

    let (_, again) = send(
        &app,
        "POST",
        "/api/rule-set-versions/1/test-data",
        Some(json!({ "seed": 7 })),
    )
    .await;
    assert_eq!(again, data);
    assert_eq!(count(&db, "SELECT COUNT(*) FROM scans").await, 0);
    assert_eq!(count(&db, "SELECT COUNT(*) FROM rules").await, rules_before);

    let (status, only) = send(
        &app,
        "POST",
        "/api/rule-set-versions/1/test-data",
        Some(json!({ "ruleIds": [2] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(only["seed"], 1);
    assert!(
        only["documents"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|document| document["cases"].as_array().unwrap())
            .all(|case| case["ruleId"] == 2 || case["ruleId"].is_null())
    );

    let (status, _) = send(
        &app,
        "POST",
        "/api/rule-set-versions/99/test-data",
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = send(
        &app,
        "POST",
        "/api/rule-set-versions/1/test-data",
        Some(json!({ "ruleIds": [999] })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
}

#[tokio::test]
async fn a_generated_run_scans_each_document_in_the_session_without_storing_its_text() {
    let (app, db) = app().await;
    let session_id = session(&app, 1).await;
    let (_, data) = send(
        &app,
        "POST",
        "/api/rule-set-versions/1/test-data",
        Some(json!({ "seed": 3 })),
    )
    .await;
    let (status, report) = run(&app, session_id, json!({ "generated": { "seed": 3 } })).await;
    assert_eq!(status, StatusCode::CREATED, "{report}");
    assert_eq!(report["seed"], 3);
    assert_eq!(report["ruleSetVersionId"], 1);

    let documents = report["documents"].as_array().unwrap();
    assert_eq!(documents.len(), data["documents"].as_array().unwrap().len());
    assert_eq!(
        count(&db, "SELECT COUNT(*) FROM scans WHERE scan_session_id = 1").await,
        documents.len() as i64
    );
    let summary = &report["summary"];
    assert_eq!(summary["missed"], 0, "{report}");
    assert!(summary["caught"].as_u64().unwrap() >= 39);
    assert_eq!(summary["ruleErrors"], 0);
    assert_eq!(case(&report, "r1-positive")["outcome"], "caught");
    assert_eq!(case(&report, "r1-wrong-prefix")["outcome"], "ignored");
    let broken = case(&report, "r2-broken-checksum");
    assert_eq!(broken["outcome"], "flagged_as_example");
    assert_eq!(broken["findings"][0]["checksumValid"], false);

    // A broken token under a token name: the assignment rule scores it as real while the
    // checksum rule marks it an example.
    let assigned = case(&report, "r2-broken-checksum-env");
    assert_eq!(assigned["outcome"], "scored_as_real");
    let scored = diagnostic(&report, "example_scored_as_real").expect("a diagnostic");
    assert_eq!(scored["ruleId"], 4);
    assert!(
        scored["caseIds"]
            .as_array()
            .unwrap()
            .contains(&json!("r2-broken-checksum-env"))
    );
    // The value classifier lowers ordinary values under secret-sounding names to 30 but keeps
    // them.
    let lowered = case(&report, "lookalike-session-token-id");
    assert_eq!(lowered["outcome"], "false_alarm");
    assert_eq!(lowered["findings"][0]["confidence"], 30);
    assert!(diagnostic(&report, "classifier_only_lowered").is_some());

    // Neither the text nor any generated value reaches the database.
    let stored: Vec<String> = db
        .call(|connection| {
            let mut statement =
                connection.prepare("SELECT violation || violation_pretty FROM findings")?;
            let rows = statement
                .query_map([], |row| row.get(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?;
            Ok(rows)
        })
        .await
        .unwrap();
    for document in data["documents"].as_array().unwrap() {
        for case in document["cases"].as_array().unwrap() {
            let value = case["value"].as_str().unwrap();
            if value.len() >= 8 {
                assert!(
                    stored.iter().all(|row| !row.contains(value)),
                    "{} was stored",
                    case["id"]
                );
            }
        }
    }
}

#[tokio::test]
async fn labels_documents_of_your_own_by_value() {
    let (app, _) = app().await;
    let aws = create_rule(&app, valid_definition("AWS key")).await;
    let version = create_version(&app, &[aws]).await;
    let session_id = session(&app, version).await;
    let lookalike = AWS_KEY.replacen("AKIA", "AKIB", 1);
    let text = format!(
        "# deploy settings\nAWS_ACCESS_KEY_ID={AWS_KEY}\nOLD_KEY={lookalike}\nBACKUP_KEY={AWS_KEY}\n"
    );
    let (status, report) = run(
        &app,
        session_id,
        json!({
            "documents": [{
                "name": ".env",
                "text": text,
                "cases": [
                    {"id": "live", "value": AWS_KEY, "expect": "secret", "ruleName": "aws KEY"},
                    {"value": lookalike, "expect": "not_secret", "note": "Prefix is AKIB"},
                    {"id": "backup", "value": AWS_KEY, "occurrence": 2, "expect": "example", "ruleId": aws}
                ]
            }]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{report}");
    assert_eq!(report["seed"], Value::Null);
    let live = case(&report, "live");
    assert_eq!(live["outcome"], "caught");
    assert_eq!(live["kind"], "custom");
    assert_eq!(live["line"], 2);
    assert_eq!(live["findings"][0]["ruleName"], "AWS key");
    let unnamed = case(&report, ".env#2");
    assert_eq!(unnamed["outcome"], "ignored");
    assert_eq!(unnamed["note"], "Prefix is AKIB");
    assert_eq!(case(&report, "backup")["outcome"], "scored_as_real");
    let summary = &report["summary"];
    assert_eq!(summary["cases"], 3);
    assert_eq!(summary["unlabeledFindings"], 0);
    assert_eq!(report["rules"][0]["caught"], 1);
    assert!(report["rules"][0]["caughtConfidence"].is_array());

    // A finding on no case is listed as unlabeled.
    let (_, report) = run(
        &app,
        session_id,
        json!({ "documents": [{ "name": ".env", "text": text, "cases": [] }] }),
    )
    .await;
    assert_eq!(report["summary"]["unlabeledFindings"], 2);
    assert_eq!(
        report["documents"][0]["unlabeled"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn rejects_runs_it_cannot_label_before_scanning_anything() {
    let (app, db) = app().await;
    let session_id = session(&app, 1).await;
    let document = |cases: Value| json!({ "documents": [{ "name": "a.txt", "text": format!("key {AWS_KEY}"), "cases": cases }] });
    let cases = [
        (json!({}), StatusCode::BAD_REQUEST),
        (
            json!({ "documents": [{ "name": "a.txt", "text": "  " }] }),
            StatusCode::BAD_REQUEST,
        ),
        (
            document(json!([{ "value": "not in it", "expect": "secret" }])),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            document(json!([{ "value": AWS_KEY, "occurrence": 2, "expect": "secret" }])),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            document(json!([{ "value": AWS_KEY, "expect": "secret", "ruleName": "No such rule" }])),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            document(
                json!([{ "value": AWS_KEY, "expect": "secret", "ruleId": 1, "ruleName": "AWS access key" }]),
            ),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            document(json!([
                { "id": "same", "value": AWS_KEY, "expect": "secret" },
                { "id": "same", "value": "key", "expect": "not_secret" }
            ])),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            json!({ "documents": (0..21).map(|index| json!({ "name": format!("{index}.txt"), "text": "x" })).collect::<Vec<_>>() }),
            StatusCode::BAD_REQUEST,
        ),
        (
            document(json!([{ "value": AWS_KEY, "expect": "maybe" }])),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ];
    for (body, expected) in cases {
        let (status, response) = run(&app, session_id, body.clone()).await;
        assert_eq!(status, expected, "{body} gave {response}");
        // Errors never echo the text back.
        assert!(!response.to_string().contains(AWS_KEY), "{response}");
    }
    let (status, _) = run(&app, 99, json!({ "generated": {} })).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(count(&db, "SELECT COUNT(*) FROM scans").await, 0);
}

#[tokio::test]
async fn diagnoses_key_names_that_reach_parsed_pairs_and_patterns_without_a_value_group() {
    let (app, _) = app().await;
    let query = create_rule(
        &app,
        json!({
            "name": "Token in a URL query",
            "detectionType": "likely_credential",
            "severity": "high",
            "pattern": "[?&](?P<key>[a-z_]*token)=(?P<value>[A-Za-z0-9]{16,})",
            "keyNames": ["token"],
            "minEntropy": 3.0
        }),
    )
    .await;
    let whole = create_rule(
        &app,
        json!({
            "name": "Service account key",
            "detectionType": "direct_credential",
            "severity": "high",
            "pattern": "\"type\":\\s*\"service_account\"[^}]*\"private_key\":\\s*\"[^\"]+\""
        }),
    )
    .await;
    let version = create_version(&app, &[query, whole]).await;
    let session_id = session(&app, version).await;
    let env_value = token(24);
    let key_body = format!(
        "-----BEGIN PRIVATE KEY-----\\n{}\\n-----END PRIVATE KEY-----\\n",
        token(64)
    );
    let service_account = format!(
        "{{\n  \"type\": \"service_account\",\n  \"project_id\": \"demo-project\",\n  \"private_key\": \"{key_body}\"\n}}\n"
    );
    let (status, report) = run(
        &app,
        session_id,
        json!({
            "documents": [
                {
                    "name": ".env",
                    "text": format!("API_TOKEN={env_value}\nREGION=us-east-1\n"),
                    "cases": [{ "id": "plain-env", "value": env_value, "expect": "not_secret", "ruleId": query }]
                },
                {
                    "name": "service-account.json",
                    "text": service_account,
                    "cases": [{ "id": "sa-key", "value": key_body, "expect": "secret", "ruleId": whole }]
                }
            ]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{report}");

    let plain = case(&report, "plain-env");
    assert_eq!(plain["outcome"], "false_alarm");
    assert_eq!(plain["findings"][0]["fromParsedPair"], true);
    let parsed = diagnostic(&report, "parsed_pair_only").expect("a parsed pair diagnostic");
    assert_eq!(parsed["ruleId"], query);
    assert_eq!(parsed["caseIds"], json!(["plain-env"]));

    let sa = case(&report, "sa-key");
    assert_eq!(sa["outcome"], "caught");
    assert!(
        sa["findings"][0]["confidence"].as_u64().unwrap() < 80,
        "{sa}"
    );
    let diluted = diagnostic(&report, "no_value_group").expect("a value group diagnostic");
    assert_eq!(diluted["ruleId"], whole);
}

#[tokio::test]
async fn names_the_loaded_model_when_a_rule_s_classifier_hash_is_stale() {
    let (app, _) = app().await;
    let mut definition = valid_definition("AWS key");
    definition["valueClassifier"] = json!({
        "model": { "id": "value-classifier", "sha256": "0".repeat(64) },
        "minScore": 50
    });
    let rule = create_rule(&app, definition).await;
    let fine = create_rule(&app, valid_definition("Other AWS key")).await;
    let version = create_version(&app, &[rule, fine]).await;
    let session_id = session(&app, version).await;
    let (status, report) = run(&app, session_id, json!({ "generated": {} })).await;
    assert_eq!(status, StatusCode::CREATED, "{report}");
    assert_eq!(report["summary"]["ruleErrors"], 1);
    let stale = diagnostic(&report, "model_unavailable").expect("a model diagnostic");
    assert_eq!(stale["ruleId"], rule);
    assert!(
        stale["message"]
            .as_str()
            .unwrap()
            .contains(VALUE_CLASSIFIER_SHA256),
        "{stale}"
    );
    assert_eq!(
        report["documents"][0]["ruleErrors"][0]["code"],
        "model_unavailable"
    );
}

#[tokio::test]
async fn says_when_suppressions_hid_matches_from_a_run() {
    let (app, db) = app().await;
    let expires_at: String = db
        .call(|connection| {
            connection.query_row(
                "SELECT strftime('%Y-%m-%d', 'now', '+30 days')",
                [],
                |row| row.get(0),
            )
        })
        .await
        .unwrap();
    let aws = create_rule(&app, valid_definition("AWS key")).await;
    let version = create_version(&app, &[aws]).await;
    let session_id = session(&app, version).await;
    let body = json!({ "documents": [{
        "name": "notes.txt",
        "text": format!("key {AWS_KEY}"),
        "cases": [{ "value": AWS_KEY, "expect": "secret" }]
    }]});
    let (_, first) = run(&app, session_id, body.clone()).await;
    let finding_id = case(&first, "notes.txt#1")["findings"][0]["findingId"].clone();
    let (status, _) = send(
        &app,
        "POST",
        &format!("/api/scan-sessions/{session_id}/suppressions"),
        Some(
            json!({ "findingId": finding_id, "reason": "Known test key", "expiresAt": expires_at }),
        ),
    )
    .await;
    assert!(status.is_success(), "{status}");
    let (_, second) = run(&app, session_id, body).await;
    assert_eq!(case(&second, "notes.txt#1")["outcome"], "missed");
    assert!(diagnostic(&second, "suppressed").is_some(), "{second}");
}
