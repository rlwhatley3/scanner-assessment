//! REST routes for scan sessions. The storage rules live in `crate::store`, shared with the MCP
//! server; findings come from the scan routes' `load_scan`, as the MCP `get_scan` tool does.

use super::{
    AppState,
    error::{ApiError, ErrorBody},
    scans::{self, FindingResponse},
};
use crate::{
    db::Db,
    store::{self, ScanSessionSummary, ScanSummary, StoreError},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use rusqlite::Connection;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list).post(create))
        .route("/{id}", get(fetch))
}

/// A past scan with its findings. Findings never hold scan text or a matched value.
#[derive(serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SessionScan {
    #[serde(flatten)]
    scan: ScanSummary,
    findings: Vec<FindingResponse>,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScanSessionDetail {
    #[serde(flatten)]
    session: ScanSessionSummary,
    /// Oldest first.
    scans: Vec<SessionScan>,
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateSession {
    rule_set_version_id: i64,
}

fn load_detail(connection: &Connection, id: i64) -> Result<ScanSessionDetail, StoreError> {
    let session = store::get_session(connection, id)?;
    let scans = session
        .scans
        .into_iter()
        .map(|scan| {
            let findings = scans::load_scan(connection, scan.id)?
                .map(|saved| saved.findings)
                .unwrap_or_default();
            Ok(SessionScan { scan, findings })
        })
        .collect::<Result<_, StoreError>>()?;
    Ok(ScanSessionDetail {
        session: session.summary,
        scans,
    })
}

#[utoipa::path(
    get,
    path = "/api/scan-sessions",
    tag = "Scan sessions",
    summary = "List scan sessions",
    description = "Newest first.",
    responses((status = 200, body = [ScanSessionSummary]))
)]
pub async fn list(State(db): State<Db>) -> Result<Json<Vec<ScanSessionSummary>>, ApiError> {
    let sessions = db
        .call(|connection| Ok(store::list_sessions(connection)))
        .await??;
    Ok(Json(sessions))
}

#[utoipa::path(
    post,
    path = "/api/scan-sessions",
    tag = "Scan sessions",
    summary = "Start a scan session",
    description = "A session scans with one rule set version, which must exist and not be archived.",
    request_body = CreateSession,
    responses(
        (status = 201, body = ScanSessionSummary),
        (status = 422, description = "Unknown or archived rule set version", body = ErrorBody)
    )
)]
pub async fn create(
    State(db): State<Db>,
    Json(body): Json<CreateSession>,
) -> Result<(StatusCode, Json<ScanSessionSummary>), ApiError> {
    let session = db
        .call(move |connection| Ok(store::create_session(connection, body.rule_set_version_id)))
        .await?
        .map_err(|error| match error {
            // The version is named in the request body, so a missing one makes it invalid.
            StoreError::NotFound(message) => ApiError::invalid(message),
            error => error.into(),
        })?;
    Ok((StatusCode::CREATED, Json(session)))
}

#[utoipa::path(
    get,
    path = "/api/scan-sessions/{id}",
    tag = "Scan sessions",
    summary = "Reopen a scan session",
    description = "The session with every scan and its findings. Scan text is never stored, so \
                   this has locations and rule details only.",
    params(("id" = i64, Path, description = "Scan session id")),
    responses((status = 200, body = ScanSessionDetail), (status = 404, body = ErrorBody))
)]
pub async fn fetch(
    State(db): State<Db>,
    Path(id): Path<i64>,
) -> Result<Json<ScanSessionDetail>, ApiError> {
    let detail = db
        .call(move |connection| Ok(load_detail(connection, id)))
        .await??;
    Ok(Json(detail))
}
