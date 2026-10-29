pub mod db;
pub mod mcp;
pub mod routes;
pub mod seed;
pub mod store;

use routes::{health, models, rule_set_versions, rule_sets, rules, scan_sessions, scans};

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
    ),
    components(schemas(
        health::HealthResponse,
        models::ModelResponse,
        routes::ErrorBody,
        scans::CreateScanRequest,
        scans::ScanResponse,
        scans::FindingResponse,
        scans::ErrorResponse
    )),
    tags(
        (name = "API", description = "API for managing and scanning secrets"),
        (name = "Models", description = "Models that model rules can run"),
        (name = "Rules", description = "Detection rules, drafts included"),
        (name = "Rule sets", description = "Named lines of rule set versions"),
        (name = "Rule set versions", description = "Saved, immutable sets of rule snapshots"),
        (name = "Scan sessions", description = "Scans grouped under one rule set version")
    )
)]
pub struct ApiDoc;
