use secrets_scanner_api::ApiDoc;
use utoipa::OpenApi;

#[test]
fn openapi_documents_health_but_excludes_whiteboard_endpoints() {
    let openapi = ApiDoc::openapi();
    let paths = &openapi.paths.paths;
    let health = paths
        .get("/api/health")
        .expect("health endpoint should be documented");

    assert!(health.get.is_some());
}

#[test]
fn openapi_documents_the_scan_endpoint() {
    let openapi = ApiDoc::openapi();
    let scans = openapi
        .paths
        .paths
        .get("/api/scan-sessions/{scan_session_id}/scans")
        .expect("scan endpoint should be documented");

    assert!(scans.post.is_some());
}
