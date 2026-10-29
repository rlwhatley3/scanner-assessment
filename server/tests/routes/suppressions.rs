use super::send;
use axum::{Router, http::StatusCode};
use secrets_scanner_api::{
    db::Db, fingerprint_key, routes, seed::seed_default_rule_set, store::MAX_SUPPRESSION_DAYS,
};
use secrets_scanner_engine::FingerprintKey;
use serde_json::{Value, json};

const AWS_KEY: &str = "AKIAZ7Q3LMN4XWY2PRT6";
const OTHER_AWS_KEY: &str = "AKIAQ4M8VXN2LKP7RT3W";
const REASON: &str = "Example key from our onboarding doc";

/// A database with the built-in rule set seeded and scan sessions 1 and 2 on it.
async fn database() -> Db {
    let db = Db::open_in_memory().expect("in-memory database should open");
    seed_default_rule_set(&db).await.expect("seed should run");
    db.call(|connection| {
        connection.execute_batch(
            "INSERT INTO scan_sessions (rule_set_version_id) VALUES (1);
             INSERT INTO scan_sessions (rule_set_version_id) VALUES (1);",
        )
    })
    .await
    .expect("scan sessions should insert");
    db
}

async fn app() -> (Router, Db) {
    let db = database().await;
    (routes::router(db.clone(), fingerprint_key::generate()), db)
}

/// A time `days` from now, in the stored format.
async fn in_days(db: &Db, days: i64) -> String {
    db.call(move |connection| {
        connection.query_row(
            "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
            [format!("{days:+} days")],
            |row| row.get(0),
        )
    })
    .await
    .expect("time should compute")
}

async fn scan(app: &Router, session: i64, text: String) -> Value {
    let (status, body) = send(
        app,
        "POST",
        &format!("/api/scan-sessions/{session}/scans"),
        Some(json!({ "text": text })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body
}

/// Scans `text` in session 1 and suppresses its first finding for 30 days. Returns the scan and
/// the suppression.
async fn scan_and_suppress(app: &Router, db: &Db, text: String) -> (Value, Value) {
    let scanned = scan(app, 1, text).await;
    let expires_at = in_days(db, 30).await;
    let (status, suppression) = send(
        app,
        "POST",
        "/api/scan-sessions/1/suppressions",
        Some(json!({
            "findingId": scanned["findings"][0]["id"],
            "reason": REASON,
            "expiresAt": expires_at,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{suppression}");
    (scanned, suppression)
}

fn suppression_ids(scan: &Value) -> Vec<Value> {
    scan["findings"]
        .as_array()
        .expect("findings should be a list")
        .iter()
        .map(|finding| finding["suppression"]["id"].clone())
        .collect()
}

#[tokio::test]
async fn the_same_value_in_a_later_scan_is_marked_suppressed_and_still_counted() {
    let (app, db) = app().await;
    let (first, suppression) = scan_and_suppress(&app, &db, format!("aws = {AWS_KEY}\n")).await;
    assert_eq!(suppression["scanSessionId"], 1);
    assert_eq!(suppression["ruleId"], 1);
    assert_eq!(suppression["ruleName"], "AWS access key");
    assert_eq!(suppression["findingId"], first["findings"][0]["id"]);
    assert_eq!(suppression["reason"], REASON);
    assert_eq!(suppression["status"], "active");

    // The value moved and the text around it changed; it is the same value.
    let later = scan(&app, 1, format!("# config\nother: {AWS_KEY}\n")).await;
    assert_eq!(later["findings"].as_array().map(Vec::len), Some(1));
    let marked = &later["findings"][0]["suppression"];
    assert_eq!(marked["id"], suppression["id"]);
    assert_eq!(marked["reason"], REASON);
    assert_eq!(marked["expiresAt"], suppression["expiresAt"]);

    // The scan it was made from is marked too, and saved scans read back marked.
    let (_, reread) = send(&app, "GET", "/api/scan-sessions/1/scans/1", None).await;
    assert_eq!(suppression_ids(&reread), [suppression["id"].clone()]);
    let (_, reread) = send(&app, "GET", "/api/scan-sessions/1/scans/2", None).await;
    assert_eq!(reread, later);

    // Suppressed findings still count as matches.
    let (_, session) = send(&app, "GET", "/api/scan-sessions/1", None).await;
    assert_eq!(session["activeSuppressionCount"], 1);
    for scan in session["scans"].as_array().expect("scans should be a list") {
        assert_eq!(scan["matchCount"], 1);
        assert_eq!(scan["suppressedCount"], 1);
    }
    let (_, list) = send(&app, "GET", "/api/scan-sessions/1/suppressions", None).await;
    assert_eq!(list[0]["suppressedCount"], 2);
}

#[tokio::test]
async fn a_changed_value_is_not_suppressed() {
    let (app, db) = app().await;
    let (_, suppression) = scan_and_suppress(&app, &db, format!("aws = {AWS_KEY}\n")).await;

    let changed = scan(&app, 1, format!("aws = {OTHER_AWS_KEY}\n")).await;
    assert_eq!(suppression_ids(&changed), [Value::Null]);

    // Side by side, only the suppressed value is marked.
    let both = scan(&app, 1, format!("a = {AWS_KEY}\nb = {OTHER_AWS_KEY}\n")).await;
    assert_eq!(
        suppression_ids(&both),
        [suppression["id"].clone(), Value::Null]
    );
}

#[tokio::test]
async fn another_session_is_unaffected() {
    let (app, db) = app().await;
    scan_and_suppress(&app, &db, format!("aws = {AWS_KEY}\n")).await;

    let other = scan(&app, 2, format!("aws = {AWS_KEY}\n")).await;
    assert_eq!(suppression_ids(&other), [Value::Null]);
    let (_, list) = send(&app, "GET", "/api/scan-sessions/2/suppressions", None).await;
    assert_eq!(list, json!([]));
    let (status, _) = send(&app, "DELETE", "/api/scan-sessions/2/suppressions/1", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_expired_suppression_does_not_apply() {
    let (app, db) = app().await;
    scan_and_suppress(&app, &db, format!("aws = {AWS_KEY}\n")).await;
    let past = in_days(&db, -1).await;
    db.call(move |connection| {
        connection.execute("UPDATE suppressions SET expires_at = ?1", [past])
    })
    .await
    .expect("suppression should update");

    let later = scan(&app, 1, format!("aws = {AWS_KEY}\n")).await;
    assert_eq!(suppression_ids(&later), [Value::Null]);
    let (_, list) = send(&app, "GET", "/api/scan-sessions/1/suppressions", None).await;
    assert_eq!(list[0]["status"], "expired");
    let (_, session) = send(&app, "GET", "/api/scan-sessions/1", None).await;
    assert_eq!(session["activeSuppressionCount"], 0);
}

#[tokio::test]
async fn a_removed_suppression_stops_applying_but_past_scans_keep_it() {
    let (app, db) = app().await;
    let (_, suppression) = scan_and_suppress(&app, &db, format!("aws = {AWS_KEY}\n")).await;
    let id = suppression["id"]
        .as_i64()
        .expect("suppression should have an id");

    let uri = format!("/api/scan-sessions/1/suppressions/{id}");
    let (status, removed) = send(&app, "DELETE", &uri, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(removed["status"], "removed");
    assert!(removed["removedAt"].is_string());
    // Removing it again changes nothing.
    let (status, again) = send(&app, "DELETE", &uri, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["removedAt"], removed["removedAt"]);

    let later = scan(&app, 1, format!("aws = {AWS_KEY}\n")).await;
    assert_eq!(suppression_ids(&later), [Value::Null]);
    let (_, first) = send(&app, "GET", "/api/scan-sessions/1/scans/1", None).await;
    assert_eq!(first["findings"][0]["suppression"]["reason"], REASON);
}

#[tokio::test]
async fn a_new_key_ends_every_suppression() {
    let db = database().await;
    let app = routes::router(db.clone(), FingerprintKey::new([1; 32]));
    scan_and_suppress(&app, &db, format!("aws = {AWS_KEY}\n")).await;

    // A lost key is replaced by a new one: nothing matches, so the findings come back.
    let restarted = routes::router(db.clone(), FingerprintKey::new([2; 32]));
    let later = scan(&restarted, 1, format!("aws = {AWS_KEY}\n")).await;
    assert_eq!(suppression_ids(&later), [Value::Null]);
}

/// Every value in every row of every table, as text.
async fn every_stored_value(db: &Db) -> String {
    db.call(|connection| {
        let tables: Vec<String> = connection
            .prepare("SELECT name FROM sqlite_schema WHERE type = 'table'")?
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut stored = String::new();
        for table in tables {
            let mut statement = connection.prepare(&format!("SELECT * FROM \"{table}\""))?;
            let columns = statement.column_count();
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                for index in 0..columns {
                    let value: rusqlite::types::Value = row.get(index)?;
                    stored.push_str(&format!("{value:?}\n"));
                }
            }
        }
        Ok(stored)
    })
    .await
    .expect("every table should read")
}

#[tokio::test]
async fn no_value_text_or_fingerprint_is_returned_and_no_value_or_text_is_stored() {
    let (app, db) = app().await;
    let text = format!("aws_access_key_id = {AWS_KEY}\n");
    let (first, suppression) = scan_and_suppress(&app, &db, text.clone()).await;
    let later = scan(&app, 1, text.clone()).await;
    let (_, list) = send(&app, "GET", "/api/scan-sessions/1/suppressions", None).await;
    let (_, session) = send(&app, "GET", "/api/scan-sessions/1", None).await;
    let (_, removed) = send(&app, "DELETE", "/api/scan-sessions/1/suppressions/1", None).await;
    let responses =
        [first, suppression, later, list, session, removed].map(|body| body.to_string());

    let fingerprint: String = db
        .call(|connection| {
            connection.query_row("SELECT fingerprint FROM suppressions", [], |row| row.get(0))
        })
        .await
        .expect("the suppression should have a fingerprint");
    assert_eq!(fingerprint.len(), 64);

    for response in &responses {
        assert!(!response.contains(AWS_KEY), "{response}");
        assert!(!response.contains(text.trim()), "{response}");
        assert!(!response.contains(&fingerprint), "{response}");
    }
    let stored = every_stored_value(&db).await;
    assert!(!stored.contains(AWS_KEY));
    assert!(!stored.contains(text.trim()));
}

#[tokio::test]
async fn a_suppression_needs_a_match_in_the_session_a_reason_and_an_expiry_in_range() {
    let (app, db) = app().await;
    let scanned = scan(&app, 1, format!("aws = {AWS_KEY}\n")).await;
    let finding_id = scanned["findings"][0]["id"].clone();
    let other = scan(&app, 2, format!("aws = {AWS_KEY}\n")).await;
    let soon = in_days(&db, 30).await;

    let create = |session: i64, body: Value| {
        let app = app.clone();
        async move {
            send(
                &app,
                "POST",
                &format!("/api/scan-sessions/{session}/suppressions"),
                Some(body),
            )
            .await
        }
    };
    let rejected = [
        json!({ "findingId": finding_id, "reason": "  ", "expiresAt": soon }),
        json!({ "findingId": finding_id, "reason": "x".repeat(501), "expiresAt": soon }),
        json!({ "findingId": finding_id, "reason": REASON, "expiresAt": in_days(&db, -1).await }),
        json!({
            "findingId": finding_id,
            "reason": REASON,
            "expiresAt": in_days(&db, MAX_SUPPRESSION_DAYS + 1).await,
        }),
        json!({ "findingId": finding_id, "reason": REASON, "expiresAt": "next week" }),
        json!({ "findingId": finding_id, "reason": REASON, "expiresAt": "" }),
        // A finding from another session.
        json!({ "findingId": other["findings"][0]["id"], "reason": REASON, "expiresAt": soon }),
        json!({ "findingId": 999, "reason": REASON, "expiresAt": soon }),
    ];
    for body in rejected {
        let (status, error) = create(1, body.clone()).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{body} -> {error}"
        );
        assert!(error["error"].is_string());
    }
    let (status, _) = create(1, json!({ "findingId": finding_id, "reason": REASON })).await;
    assert!(status.is_client_error());

    // A date alone is midnight UTC at its start.
    let date = &in_days(&db, 30).await[..10];
    let (status, created) = create(
        1,
        json!({ "findingId": finding_id, "reason": REASON, "expiresAt": date }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["expiresAt"], format!("{date}T00:00:00.000Z"));

    // One active suppression per value and rule.
    let (status, error) = create(
        1,
        json!({ "findingId": finding_id, "reason": REASON, "expiresAt": soon }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        error["error"]
            .as_str()
            .unwrap_or_default()
            .contains("already suppressed")
    );

    let (status, _) = create(
        99,
        json!({ "findingId": finding_id, "reason": REASON, "expiresAt": soon }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(&app, "GET", "/api/scan-sessions/99/suppressions", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_rule_error_cannot_be_suppressed() {
    let (app, db) = app().await;
    db.call(|connection| {
        connection.execute(
            "UPDATE rule_set_version_rules SET definition = json_set(definition, '$.pattern', 'AKIA(')
             WHERE rule_id = 1",
            [],
        )
    })
    .await
    .expect("rule snapshot should update");
    let scanned = scan(&app, 1, "nothing to see".to_owned()).await;
    assert_eq!(scanned["findings"][0]["kind"], "rule_error");
    let (status, _) = send(
        &app,
        "POST",
        "/api/scan-sessions/1/suppressions",
        Some(json!({
            "findingId": scanned["findings"][0]["id"],
            "reason": REASON,
            "expiresAt": in_days(&db, 30).await,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[test]
fn the_key_is_created_once_and_read_back() {
    let directory = std::env::temp_dir().join(format!(
        "fingerprint-key-test-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
    ));
    std::fs::create_dir_all(&directory).expect("temp directory should be created");
    let path = directory.join("fingerprint.key");

    let created = fingerprint_key::load_or_create(&path).expect("key should be created");
    let read = fingerprint_key::load_or_create(&path).expect("key should be read");
    assert_eq!(created.fingerprint(b"value"), read.fingerprint(b"value"));
    assert_eq!(std::fs::read(&path).map(|bytes| bytes.len()).ok(), Some(32));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("key file exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // A damaged key file is an error, never silently replaced.
    std::fs::write(&path, b"short").expect("key file should write");
    assert!(fingerprint_key::load_or_create(&path).is_err());
    std::fs::remove_dir_all(&directory).expect("temp directory should be removed");
}
