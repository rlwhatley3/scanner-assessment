//! Drives the MCP server over HTTP through the API router, the way an MCP client would.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use secrets_scanner_api::{db::Db, routes, seed::seed_default_rule_set};
use serde_json::{Value, json};
use tower::ServiceExt;

const PROTOCOL_VERSION: &str = "2025-06-18";
const AWS_KEY: &str = "AKIAZ7Q3LMN4XWY2PRT6";

/// An app on a fresh database with the built-in rule set seeded as version 1.
async fn app() -> (Router, Db) {
    let db = Db::open_in_memory().expect("in-memory database should open");
    seed_default_rule_set(&db).await.expect("seed should run");
    (
        routes::router(db.clone(), secrets_scanner_api::fingerprint_key::generate()),
        db,
    )
}

async fn post(app: &Router, body: Value, origin: Option<&str>) -> (StatusCode, Value) {
    let mut request = Request::post("/mcp")
        .header("host", "127.0.0.1:3001")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", PROTOCOL_VERSION);
    if let Some(origin) = origin {
        request = request.header("origin", origin);
    }
    let request = request
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

async fn rpc(app: &Router, method: &str, params: Value) -> Value {
    let (status, body) = post(
        app,
        json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{method} failed: {body}");
    body
}

/// Calls a tool and returns its structured result, or its error text when the tool failed.
async fn call(app: &Router, tool: &str, arguments: Value) -> Result<Value, String> {
    let body = rpc(
        app,
        "tools/call",
        json!({"name": tool, "arguments": arguments}),
    )
    .await;
    let result = &body["result"];
    assert!(result.is_object(), "{tool} returned no result: {body}");
    if result["isError"] == json!(true) {
        Err(result["content"][0]["text"]
            .as_str()
            .expect("a tool error has text")
            .to_string())
    } else {
        Ok(result["structuredContent"].clone())
    }
}

async fn ok(app: &Router, tool: &str, arguments: Value) -> Value {
    call(app, tool, arguments)
        .await
        .unwrap_or_else(|error| panic!("{tool} failed: {error}"))
}

async fn err(app: &Router, tool: &str, arguments: Value) -> String {
    match call(app, tool, arguments).await {
        Ok(result) => panic!("{tool} should have failed, got {result}"),
        Err(error) => error,
    }
}

fn aws_rule(name: &str) -> Value {
    json!({
        "name": name,
        "detectionType": "direct_credential",
        "severity": "high",
        "pattern": "AKIA[0-9A-Z]{16}",
        "prefix": "AKIA",
        "remediation": "Rotate the key."
    })
}

#[tokio::test]
async fn initializes_and_lists_every_tool() {
    let (app, _) = app().await;
    let init = rpc(
        &app,
        "initialize",
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        }),
    )
    .await;
    assert!(init["result"]["capabilities"]["tools"].is_object());
    assert!(init["result"]["instructions"].is_string());
    assert_eq!(init["result"]["serverInfo"]["name"], "secrets-scanner");

    let tools = rpc(&app, "tools/list", json!({})).await;
    let tools = tools["result"]["tools"]
        .as_array()
        .expect("tools should be a list");
    for tool in tools {
        // Clients check structured results against this, so every tool must declare one.
        assert_eq!(tool["outputSchema"]["type"], "object", "{}", tool["name"]);
    }
    let mut names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("a tool has a name"))
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "check_rules",
            "create_rule",
            "create_rule_set",
            "create_rule_set_version",
            "create_scan_session",
            "create_suppression",
            "delete_rule",
            "generate_test_data",
            "get_rule",
            "get_rule_set",
            "get_rule_set_version",
            "get_scan",
            "get_scan_session",
            "list_models",
            "list_rule_set_versions",
            "list_rule_sets",
            "list_rules",
            "list_scan_sessions",
            "list_suppressions",
            "remove_suppression",
            "rule_authoring_guide",
            "run_scan",
            "run_test_suite",
            "set_rule_set_version_archived",
            "update_rule",
            "update_rule_set",
        ]
    );
}

/// The docs page reads `/api/mcp`, so it must say exactly what `/mcp` says, and a browser may
/// read it.
#[tokio::test]
async fn describes_itself_to_the_docs_page_as_it_does_to_clients() {
    let (app, _) = app().await;
    let init = rpc(
        &app,
        "initialize",
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        }),
    )
    .await;
    let tools = rpc(&app, "tools/list", json!({})).await;

    let request = Request::get("/api/mcp")
        .header("origin", "http://127.0.0.1:5173")
        .body(Body::empty())
        .expect("request should build");
    let response = app.oneshot(request).await.expect("request should run");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should read");
    let description: Value = serde_json::from_slice(&bytes).expect("body should be JSON");

    for field in ["capabilities", "serverInfo", "instructions"] {
        assert_eq!(
            description["initialize"][field], init["result"][field],
            "{field}"
        );
    }
    assert_eq!(description["tools"], tools["result"]["tools"]);
}

#[tokio::test]
async fn rejects_browser_origins() {
    let (app, _) = app().await;
    let (status, _) = post(
        &app,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
        Some("http://127.0.0.1:5173"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn reads_the_seeded_rules_and_version() {
    let (app, _) = app().await;
    let built_in = secrets_scanner_api::seed::built_in_rules().len();

    let rules = ok(&app, "list_rules", json!({})).await;
    assert_eq!(rules["rules"].as_array().unwrap().len(), built_in);
    let drafts = ok(&app, "list_rules", json!({"drafting": true})).await;
    assert_eq!(drafts["rules"], json!([]));

    let versions = ok(&app, "list_rule_set_versions", json!({})).await;
    assert_eq!(versions["versions"][0]["id"], 1);
    assert_eq!(versions["versions"][0]["ruleCount"], built_in);

    let version = ok(&app, "get_rule_set_version", json!({"versionId": 1})).await;
    assert_eq!(version["rules"].as_array().unwrap().len(), built_in);

    let rule = ok(&app, "get_rule", json!({"ruleId": 1})).await;
    assert_eq!(rule["drafting"], false);
    assert_eq!(rule["ruleSetVersionIds"], json!([1]));
}

#[tokio::test]
async fn drafts_are_stored_unvalidated_and_can_be_deleted() {
    let (app, _) = app().await;
    let draft = ok(&app, "create_rule", json!({})).await;
    assert_eq!(draft["drafting"], true);
    let id = draft["id"].as_i64().unwrap();

    let updated = ok(
        &app,
        "update_rule",
        json!({"ruleId": id, "definition": {"name": "Half done", "pattern": "("}}),
    )
    .await;
    assert_eq!(updated["definition"]["name"], "Half done");

    let check = ok(&app, "check_rules", json!({"ruleIds": [id]})).await;
    assert_eq!(check["valid"], false);
    let fields: Vec<&str> = check["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|error| error["field"].as_str().unwrap())
        .collect();
    assert!(fields.contains(&"pattern"));
    assert!(fields.contains(&"detection_type"));

    ok(&app, "delete_rule", json!({"ruleId": id})).await;
    let error = err(&app, "get_rule", json!({"ruleId": id})).await;
    assert_eq!(error, format!("Rule {id} not found."));
}

#[tokio::test]
async fn rejects_unknown_definition_fields() {
    let (app, _) = app().await;
    let error = err(&app, "create_rule", json!({"definition": {"nmae": "Typo"}})).await;
    assert!(error.contains("unknown field `nmae`"), "{error}");
}

#[tokio::test]
async fn rules_in_a_version_cannot_be_deleted() {
    let (app, _) = app().await;
    let error = err(&app, "delete_rule", json!({"ruleId": 1})).await;
    assert!(error.contains("is in a rule set version"), "{error}");
}

#[tokio::test]
async fn a_rule_in_a_version_must_stay_valid_when_updated() {
    let (app, _) = app().await;
    let before = ok(&app, "get_rule", json!({"ruleId": 1})).await;

    let error = err(
        &app,
        "update_rule",
        json!({"ruleId": 1, "definition": {"name": "Broken", "pattern": "(unclosed"}}),
    )
    .await;
    assert!(error.contains("nothing was saved"), "{error}");
    assert!(error.contains("invalid_regex"), "{error}");

    let after = ok(&app, "get_rule", json!({"ruleId": 1})).await;
    assert_eq!(after["definition"], before["definition"]);
}

#[tokio::test]
async fn an_invalid_rule_set_saves_no_version() {
    let (app, db) = app().await;
    let draft = ok(
        &app,
        "create_rule",
        json!({"definition": {"name": "Broken"}}),
    )
    .await;
    let id = draft["id"].as_i64().unwrap();

    let error = err(
        &app,
        "create_rule_set_version",
        json!({"ruleSetId": 1, "parentId": 1, "ruleIds": [1, id]}),
    )
    .await;
    assert!(error.contains("nothing was saved"), "{error}");
    assert!(error.contains(&format!("\"ruleId\": {id}")), "{error}");

    let versions: i64 = db
        .call(|connection| {
            connection.query_row("SELECT COUNT(*) FROM rule_set_versions", [], |row| {
                row.get(0)
            })
        })
        .await
        .unwrap();
    assert_eq!(versions, 1);
    let rule = ok(&app, "get_rule", json!({"ruleId": id})).await;
    assert_eq!(rule["drafting"], true);
}

#[tokio::test]
async fn duplicate_names_block_a_version() {
    let (app, _) = app().await;
    let first = ok(&app, "create_rule", json!({"definition": aws_rule("AWS")})).await;
    let second = ok(&app, "create_rule", json!({"definition": aws_rule("aws ")})).await;
    let error = err(
        &app,
        "create_rule_set_version",
        json!({"ruleSetId": 1, "ruleIds": [first["id"], second["id"]]}),
    )
    .await;
    assert!(error.contains("duplicate_name"), "{error}");
}

#[tokio::test]
async fn a_version_snapshots_rules_and_later_edits_do_not_change_it() {
    let (app, _) = app().await;
    let draft = ok(
        &app,
        "create_rule",
        json!({"definition": aws_rule("Only AWS")}),
    )
    .await;
    let id = draft["id"].as_i64().unwrap();

    let created = ok(
        &app,
        "create_rule_set_version",
        json!({"ruleSetId": 1, "parentId": 1, "ruleIds": [id]}),
    )
    .await;
    let version = &created["version"];
    let version_id = version["id"].as_i64().unwrap();
    assert_eq!(version["parentId"], 1);
    assert_eq!(version["ruleCount"], 1);
    assert_eq!(version["rules"][0]["definition"]["name"], "Only AWS");
    assert_eq!(
        ok(&app, "get_rule", json!({"ruleId": id})).await["drafting"],
        false
    );

    ok(
        &app,
        "update_rule",
        json!({"ruleId": id, "definition": aws_rule("Renamed")}),
    )
    .await;
    let saved = ok(
        &app,
        "get_rule_set_version",
        json!({"versionId": version_id}),
    )
    .await;
    assert_eq!(saved["rules"][0]["definition"]["name"], "Only AWS");
}

#[tokio::test]
async fn archived_versions_are_hidden_and_cannot_start_sessions() {
    let (app, _) = app().await;
    let archived = ok(
        &app,
        "set_rule_set_version_archived",
        json!({"versionId": 1, "archived": true}),
    )
    .await;
    assert_eq!(archived["archived"], true);

    let timeline = ok(&app, "list_rule_set_versions", json!({})).await;
    assert_eq!(timeline["versions"], json!([]));
    let all = ok(
        &app,
        "list_rule_set_versions",
        json!({"includeArchived": true}),
    )
    .await;
    assert_eq!(all["versions"].as_array().unwrap().len(), 1);

    let error = err(&app, "create_scan_session", json!({"ruleSetVersionId": 1})).await;
    assert!(error.contains("is archived"), "{error}");

    ok(
        &app,
        "set_rule_set_version_archived",
        json!({"versionId": 1, "archived": false}),
    )
    .await;
    ok(&app, "create_scan_session", json!({"ruleSetVersionId": 1})).await;
}

#[tokio::test]
async fn runs_scans_in_a_session_and_reads_them_back() {
    let (app, _) = app().await;
    let session = ok(&app, "create_scan_session", json!({"ruleSetVersionId": 1})).await;
    let session_id = session["id"].as_i64().unwrap();
    assert_eq!(session["lastRan"], Value::Null);

    let scan = ok(
        &app,
        "run_scan",
        json!({"sessionId": session_id, "text": format!("aws_access_key_id = {AWS_KEY}\n")}),
    )
    .await;
    let scan_id = scan["scanId"].as_i64().unwrap();
    assert!(!scan["findings"].as_array().unwrap().is_empty());
    assert!(!scan.to_string().contains(AWS_KEY));

    assert_eq!(ok(&app, "get_scan", json!({"scanId": scan_id})).await, scan);

    let reopened = ok(&app, "get_scan_session", json!({"sessionId": session_id})).await;
    assert!(reopened["lastRan"].is_string());
    assert_eq!(reopened["scanCount"], 1);
    assert_eq!(reopened["scans"][0]["id"], scan_id);
    assert_eq!(reopened["scans"][0]["partial"], false);

    let sessions = ok(&app, "list_scan_sessions", json!({})).await;
    assert_eq!(sessions["sessions"][0]["id"], session_id);
}

#[tokio::test]
async fn scan_errors_come_back_as_tool_errors() {
    let (app, _) = app().await;
    let error = err(&app, "run_scan", json!({"sessionId": 99, "text": "x"})).await;
    assert_eq!(error, "Scan session 99 not found.");

    let session = ok(&app, "create_scan_session", json!({"ruleSetVersionId": 1})).await;
    let error = err(
        &app,
        "run_scan",
        json!({"sessionId": session["id"], "text": ""}),
    )
    .await;
    assert!(!error.is_empty());

    let error = err(&app, "get_scan", json!({"scanId": 42})).await;
    assert_eq!(error, "Scan 42 not found.");
}

#[tokio::test]
async fn rule_sets_are_named_and_can_start_from_a_copy() {
    let (app, _) = app().await;
    let rule_sets = ok(&app, "list_rule_sets", json!({})).await;
    assert_eq!(rule_sets["ruleSets"][0]["name"], "Built-in rules");

    let copy = ok(
        &app,
        "create_rule_set",
        json!({"name": "Strict", "description": "Tighter rules", "fromVersionId": 1}),
    )
    .await;
    assert_eq!(copy["versions"][0]["number"], 1);
    assert_eq!(copy["versions"][0]["parentId"], 1);

    let taken = err(&app, "create_rule_set", json!({"name": "strict"})).await;
    assert!(taken.contains("already exists"), "{taken}");

    let id = copy["id"].as_i64().unwrap();
    let renamed = ok(
        &app,
        "update_rule_set",
        json!({"ruleSetId": id, "name": "Strict v2"}),
    )
    .await;
    assert_eq!(renamed["name"], "Strict v2");
    let versions = ok(&app, "list_rule_set_versions", json!({"ruleSetId": id})).await;
    assert_eq!(versions["versions"][0]["ruleSetName"], "Strict v2");
}

#[tokio::test]
async fn lists_the_loaded_models() {
    let (app, _) = app().await;
    let models = ok(&app, "list_models", json!({})).await;
    assert_eq!(models["models"][0]["id"], "value-classifier");
    assert_eq!(
        models["models"][0]["sha256"],
        secrets_scanner_engine::VALUE_CLASSIFIER_SHA256
    );
    assert_eq!(models["models"][0]["uses"], json!(["value_classifier"]));
}

#[tokio::test]
async fn the_scan_tools_explain_findings_and_the_rule_tools_list_every_field() {
    let (app, _) = app().await;
    let tools = rpc(&app, "tools/list", json!({})).await;
    let tools = tools["result"]["tools"].as_array().unwrap();
    let tool = |name: &str| {
        tools
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap_or_else(|| panic!("{name} should be listed"))
            .to_string()
    };
    for name in ["get_scan", "run_scan"] {
        let schema = tool(name);
        for field in [
            "confidence",
            "valueClass",
            "placeholderScore",
            "modelAssessments",
        ] {
            assert!(schema.contains(field), "{name} should explain {field}");
        }
    }
    for name in ["create_rule", "update_rule"] {
        let schema = tool(name);
        for field in ["passwordShape", "valueClassifier", "checksum"] {
            assert!(schema.contains(field), "{name} should list {field}");
        }
    }
}

#[tokio::test]
async fn the_rule_authoring_guide_covers_every_mechanism_by_topic() {
    let (app, _) = app().await;
    let whole = ok(&app, "rule_authoring_guide", json!({})).await;
    assert_eq!(
        whole["topics"],
        json!([
            "overview",
            "workflow",
            "testing",
            "detection-types",
            "patterns",
            "key-names",
            "entropy",
            "checksums",
            "password-shape",
            "placeholders",
            "models",
            "scoring",
            "parsing",
            "validation",
            "recipes",
            "pitfalls"
        ])
    );
    let text = whole["text"].as_str().expect("the guide is text");
    // Every definition field is explained somewhere in it.
    for field in [
        "name",
        "enabled",
        "detectionType",
        "severity",
        "pattern",
        "prefix",
        "keyNames",
        "minEntropy",
        "checksum",
        "passwordShape",
        "remediation",
        "model",
        "threshold",
        "valueClassifier",
    ] {
        assert!(
            text.contains(&format!("`{field}`")),
            "{field} is not documented"
        );
    }

    let section = ok(&app, "rule_authoring_guide", json!({"topic": "checksums"})).await;
    let section_text = section["text"].as_str().expect("a section is text");
    assert!(section_text.starts_with("## Checksums"));
    assert!(section_text.contains("prefixLength"));
    assert!(!section_text.contains("## Password shape"));

    let error = err(&app, "rule_authoring_guide", json!({"topic": "regex"})).await;
    assert!(
        error.contains("There is no guide section \"regex\""),
        "{error}"
    );
    assert!(error.contains("detection-types"), "{error}");
}

#[tokio::test]
async fn creates_lists_and_removes_suppressions_and_a_suppressed_match_is_not_flagged() {
    let (app, db) = app().await;
    let session = ok(&app, "create_scan_session", json!({"ruleSetVersionId": 1})).await;
    let session_id = session["id"].as_i64().unwrap();
    let other = ok(&app, "create_scan_session", json!({"ruleSetVersionId": 1})).await;
    let text = format!("aws_access_key_id = {AWS_KEY}\n");
    let scan = ok(
        &app,
        "run_scan",
        json!({"sessionId": session_id, "text": text}),
    )
    .await;
    let finding_id = scan["findings"][0]["id"].clone();
    assert_eq!(scan["suppressedCount"], 0);

    let expires_at: String = db
        .call(|connection| {
            connection.query_row(
                "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+7 days')",
                [],
                |row| row.get(0),
            )
        })
        .await
        .unwrap();

    // Create: a reason and an expiry are required.
    let error = err(
        &app,
        "create_suppression",
        json!({"sessionId": session_id, "findingId": finding_id, "reason": "", "expiresAt": expires_at}),
    )
    .await;
    assert!(error.contains("reason"), "{error}");
    let suppression = ok(
        &app,
        "create_suppression",
        json!({"sessionId": session_id, "findingId": finding_id, "reason": "Test fixture", "expiresAt": expires_at}),
    )
    .await;
    assert_eq!(suppression["status"], "active");
    assert_eq!(suppression["ruleName"], "AWS access key");
    assert!(suppression["createdAt"].is_string());
    assert!(!suppression.to_string().contains("fingerprint"));

    // List.
    let listed = ok(&app, "list_suppressions", json!({"sessionId": session_id})).await;
    assert_eq!(listed["suppressions"].as_array().map(Vec::len), Some(1));
    assert_eq!(listed["suppressions"][0]["id"], suppression["id"]);
    assert_eq!(listed["suppressions"][0]["reason"], "Test fixture");

    // A suppressed match is not flagged by run_scan or get_scan, but is in another session.
    let later = ok(
        &app,
        "run_scan",
        json!({"sessionId": session_id, "text": text}),
    )
    .await;
    assert_eq!(later["findings"], json!([]));
    assert_eq!(later["suppressedCount"], 1);
    assert!(!later.to_string().contains(AWS_KEY));
    assert_eq!(
        ok(&app, "get_scan", json!({"scanId": later["scanId"]})).await,
        later
    );
    let elsewhere = ok(
        &app,
        "run_scan",
        json!({"sessionId": other["id"], "text": text}),
    )
    .await;
    assert_eq!(elsewhere["findings"].as_array().map(Vec::len), Some(1));

    // Remove: the value is flagged again.
    let removed = ok(
        &app,
        "remove_suppression",
        json!({"sessionId": session_id, "suppressionId": suppression["id"]}),
    )
    .await;
    assert_eq!(removed["status"], "removed");
    let after = ok(
        &app,
        "run_scan",
        json!({"sessionId": session_id, "text": text}),
    )
    .await;
    assert_eq!(after["findings"].as_array().map(Vec::len), Some(1));
    assert_eq!(after["suppressedCount"], 0);
}

#[tokio::test]
async fn generates_test_data_and_runs_it_with_documents_of_your_own() {
    let (app, db) = app().await;
    let data = ok(
        &app,
        "generate_test_data",
        json!({"versionId": 1, "seed": 5, "ruleIds": [1]}),
    )
    .await;
    assert_eq!(data["ruleSetVersionId"], 1);
    let positive = data["documents"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|document| document["cases"].as_array().unwrap())
        .find(|case| case["id"] == "r1-positive")
        .expect("a positive for the AWS key rule")
        .clone();
    assert_eq!(positive["expect"], "secret");
    assert_eq!(positive["ruleName"], "AWS access key");

    let session = ok(&app, "create_scan_session", json!({"ruleSetVersionId": 1})).await;
    let readme =
        format!("## Setup\n\nExport your key:\n\n    export AWS_ACCESS_KEY_ID={AWS_KEY}\n");
    let report = ok(
        &app,
        "run_test_suite",
        json!({
            "sessionId": session["id"],
            "generated": {"seed": 5, "ruleIds": [1]},
            "documents": [{
                "name": "README.md",
                "text": readme,
                "cases": [{"id": "readme-key", "value": AWS_KEY, "expect": "secret", "ruleId": 1}]
            }]
        }),
    )
    .await;
    assert_eq!(report["seed"], 5);
    let cases: Vec<&Value> = report["documents"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|document| document["cases"].as_array().unwrap())
        .collect();
    let outcome = |id: &str| {
        cases
            .iter()
            .find(|case| case["id"] == id)
            .map(|case| case["outcome"].clone())
    };
    assert_eq!(outcome("r1-positive"), Some(json!("caught")));
    assert_eq!(outcome("readme-key"), Some(json!("caught")));
    assert_eq!(report["summary"]["missed"], 0);

    // Each document was saved as a scan in the session, and get_scan reads it back.
    let scan_id = report["documents"][0]["scanId"].clone();
    let scan = ok(&app, "get_scan", json!({"scanId": scan_id})).await;
    assert_eq!(scan["scanSessionId"], session["id"]);
    let scans: i64 = db
        .call(|connection| connection.query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0)))
        .await
        .unwrap();
    assert_eq!(scans, report["documents"].as_array().unwrap().len() as i64);

    let error = err(
        &app,
        "run_test_suite",
        json!({"sessionId": session["id"], "documents": [{"name": "a", "text": "abc", "cases": [{"value": "zzz", "expect": "secret"}]}]}),
    )
    .await;
    assert!(error.contains("doesn't occur"), "{error}");
    let error = err(&app, "generate_test_data", json!({"versionId": 99})).await;
    assert!(error.contains("99"), "{error}");
}
