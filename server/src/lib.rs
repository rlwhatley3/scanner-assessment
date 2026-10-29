pub mod db;
pub mod fingerprint_key;
pub mod mcp;
pub mod routes;
pub mod seed;
pub mod store;

use routes::{
    health, models, rule_set_versions, rule_sets, rules, scan_sessions, scans, suppressions,
    testing,
};

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        health::health,
        models::list,
        rules::list,
        rules::create,
        rules::fetch,
        rules::update,
        rules::remove,
        rules::check,
        rules::check_set,
        rule_sets::list,
        rule_sets::create,
        rule_sets::fetch,
        rule_sets::update,
        rule_set_versions::list,
        rule_set_versions::create,
        rule_set_versions::fetch,
        rule_set_versions::update,
        scan_sessions::list,
        scan_sessions::create,
        scan_sessions::fetch,
        scans::create_scan,
        scans::fetch_scan,
        suppressions::list,
        suppressions::create,
        suppressions::remove,
        testing::create_test_data,
        testing::create_test_run,
        mcp::describe,
    ),
    components(schemas(
        health::HealthResponse,
        models::ModelResponse,
        routes::ErrorBody,
        scans::CreateScanRequest,
        scans::ScanResponse,
        scans::FindingResponse,
        scans::ErrorResponse,
        suppressions::CreateSuppression,
        store::SuppressionRecord,
        store::SuppressionStatus,
        testing::GenerateTestData,
        testing::TestData,
        testing::RunTestSuite,
        testing::TestRunReport,
        mcp::McpDescription
    )),
    tags(
        (name = "API", description = "API for managing and scanning secrets"),
        (name = "Models", description = "Models that model rules can run"),
        (name = "Rules", description = "Detection rules, drafts included"),
        (name = "Rule sets", description = "Named lines of rule set versions"),
        (name = "Rule set versions", description = "Saved, immutable sets of rule snapshots"),
        (name = "Scan sessions", description = "Scans grouped under one rule set version"),
        (name = "Suppressions", description = "Known-safe values, suppressed within one scan session"),
        (name = "Testing", description = "Generated test data and labeled test runs for rule sets"),
        (name = "MCP", description = "The MCP server mounted at /mcp")
    )
)]
pub struct ApiDoc;
