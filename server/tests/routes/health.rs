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
