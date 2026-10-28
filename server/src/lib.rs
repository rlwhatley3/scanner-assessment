pub mod db;
pub mod mcp;
pub mod routes;
pub mod seed;
pub mod store;

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(routes::health::health, routes::scans::create_scan),
    components(schemas(
        routes::health::HealthResponse,
        routes::scans::CreateScanRequest,
        routes::scans::ScanResponse,
        routes::scans::FindingResponse,
        routes::scans::ErrorResponse
    )),
    tags((name = "API", description = "API for managing and scanning secrets"))
)]
pub struct ApiDoc;
