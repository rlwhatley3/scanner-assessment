//! REST routes for a scan session's suppressions. The storage rules live in `crate::store`,
//! shared with the MCP server's suppression tools.

use super::{
    AppState,
    error::{ApiError, ErrorBody},
};
use crate::{
    db::Db,
    store::{self, SuppressionRecord},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get},
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/{scan_session_id}/suppressions", get(list).post(create))
        .route(
            "/{scan_session_id}/suppressions/{suppression_id}",
            delete(remove),
        )
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateSuppression {
    /// A match from one of this session's scans. Its rule and the fingerprint of its value are
    /// what the suppression covers.
    finding_id: i64,
    /// Why the value is safe to leave, e.g. "Documented example key from the AWS docs".
    reason: String,
    /// An ISO 8601 date or date-time, after now and at most 365 days ahead.
    expires_at: String,
}

#[utoipa::path(
    get,
    path = "/api/scan-sessions/{scan_session_id}/suppressions",
    tag = "Suppressions",
    summary = "List a scan session's suppressions",
    description = "Newest first, with each one's status: active, expired, or removed. \
                   Fingerprints are never returned.",
    params(("scan_session_id" = i64, Path, description = "Scan session id")),
    responses((status = 200, body = [SuppressionRecord]), (status = 404, body = ErrorBody))
)]
pub async fn list(
    State(db): State<Db>,
    Path(scan_session_id): Path<i64>,
) -> Result<Json<Vec<SuppressionRecord>>, ApiError> {
    let suppressions = db
        .call(move |connection| Ok(store::list_suppressions(connection, scan_session_id)))
        .await??;
    Ok(Json(suppressions))
}

#[utoipa::path(
    post,
    path = "/api/scan-sessions/{scan_session_id}/suppressions",
    tag = "Suppressions",
    summary = "Suppress a finding's value",
    description = "Marks one value found by one rule as known to be safe in this session, until \
                   it expires or is removed. Later scans in the session still return and count \
                   a finding of that value, marked with the suppression; a changed value isn't \
                   covered, and other sessions are never affected. The value is recognized by \
                   an HMAC-SHA256 fingerprint keyed with a local secret, never stored itself. \
                   The finding it was made from, and the same value from the same rule in that \
                   scan, are marked too.",
    params(("scan_session_id" = i64, Path, description = "Scan session id")),
    request_body = CreateSuppression,
    responses(
        (status = 201, body = SuppressionRecord),
        (status = 404, description = "No such scan session", body = ErrorBody),
        (status = 422, description = "Not a match in this session, no reason, an expiry \
                                      outside the allowed window, or already suppressed",
         body = ErrorBody)
    )
)]
pub async fn create(
    State(db): State<Db>,
    Path(scan_session_id): Path<i64>,
    Json(body): Json<CreateSuppression>,
) -> Result<(StatusCode, Json<SuppressionRecord>), ApiError> {
    let suppression = db
        .call(move |connection| {
            Ok(store::create_suppression(
                connection,
                scan_session_id,
                body.finding_id,
                &body.reason,
                &body.expires_at,
            ))
        })
        .await??;
    Ok((StatusCode::CREATED, Json(suppression)))
}

#[utoipa::path(
    delete,
    path = "/api/scan-sessions/{scan_session_id}/suppressions/{suppression_id}",
    tag = "Suppressions",
    summary = "Remove a suppression",
    description = "Later scans stop applying it, so its value's findings come back unmarked. \
                   The suppression is kept, marked removed, so past scans still show why their \
                   findings were suppressed.",
    params(
        ("scan_session_id" = i64, Path, description = "Scan session id"),
        ("suppression_id" = i64, Path, description = "Suppression id")
    ),
    responses((status = 200, body = SuppressionRecord), (status = 404, body = ErrorBody))
)]
pub async fn remove(
    State(db): State<Db>,
    Path((scan_session_id, suppression_id)): Path<(i64, i64)>,
) -> Result<Json<SuppressionRecord>, ApiError> {
    let suppression = db
        .call(move |connection| {
            Ok(store::remove_suppression(
                connection,
                scan_session_id,
                suppression_id,
            ))
        })
        .await??;
    Ok(Json(suppression))
}
