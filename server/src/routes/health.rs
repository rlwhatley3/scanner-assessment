use axum::Json;

#[utoipa::path(
    get,
    path = "/api/health",
    tag = "API",
    summary = "Check API health",
    description = "Returns a simple status response to confirm the API is available.",
    responses(
        (status = 200, description = "API is healthy", body = HealthResponse)
    )
)]
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_owned(),
    })
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    status: String,
}
