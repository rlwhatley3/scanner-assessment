pub mod db;
pub mod mcp;
pub mod routes;
pub mod seed;
pub mod store;
pub mod validation;

use routes::{health, rule_set_versions, rules, scan_sessions, scans};

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        health::health,
        rules::list,
        rules::create,
        rules::fetch,
        rules::update,
        rules::remove,
        rules::check,
        rule_set_versions::list,
        rule_set_versions::create,
        rule_set_versions::fetch,
        rule_set_versions::update,
        scan_sessions::list,
        scan_sessions::create,
        scan_sessions::fetch,
        scans::create_scan,
    ),
    components(schemas(
        health::HealthResponse,
        routes::ErrorBody,
        scans::CreateScanRequest,
        scans::ScanResponse,
        scans::FindingResponse,
        scans::ErrorResponse
    )),
    tags(
        (name = "API", description = "API for managing and scanning secrets"),
        (name = "Rules", description = "Detection rules, drafts included"),
        (name = "Rule set versions", description = "Saved, immutable sets of rule snapshots"),
        (name = "Scan sessions", description = "Scans grouped under one rule set version")
    )
)]
pub struct ApiDoc;
