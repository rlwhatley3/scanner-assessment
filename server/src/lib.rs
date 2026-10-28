pub mod db;
pub mod routes;

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(routes::health::health),
    components(schemas(routes::health::HealthResponse)),
    tags((name = "API", description = "API for managing and scanning secrets"))
)]
pub struct ApiDoc;
