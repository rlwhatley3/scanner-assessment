use secrets_scanner_api::ApiDoc;
use utoipa::OpenApi;

#[test]
fn openapi_documents_the_api_but_excludes_whiteboard_endpoints() {
    let openapi = ApiDoc::openapi();
    let paths = &openapi.paths.paths;

    assert!(paths["/api/health"].get.is_some());
    assert!(paths["/api/rules"].post.is_some());
    assert!(paths["/api/rules/{id}"].put.is_some());
    assert!(paths["/api/rule-set-versions"].post.is_some());
    assert!(paths["/api/rule-set-versions/{id}"].patch.is_some());
    assert!(paths["/api/scan-sessions/{id}"].get.is_some());
    assert!(!paths.keys().any(|path| path.contains("whiteboard")));
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
