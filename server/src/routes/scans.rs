use super::AppState;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use rusqlite::{Connection, OptionalExtension};
use secrets_scanner_engine::{
    Finding, FindingKind, Rule, RuleDefinition, RuleSet, ScanError, ScanResult, scan,
};
use serde::{Deserialize, Serialize};

pub fn router() -> Router<AppState> {
    Router::new().route("/{scan_session_id}/scans", post(create_scan))
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateScanRequest {
    /// The text to scan. It is never stored or logged.
    text: String,
}

#[derive(Serialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScanResponse {
    scan_id: i64,
    scan_session_id: i64,
    /// True when there were more findings than the cap and the rest were not saved.
    truncated: bool,
    /// True when at least one rule could not run.
    partial: bool,
    findings: Vec<FindingResponse>,
}

#[derive(Serialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FindingResponse {
    id: i64,
    rule_id: i64,
    /// `match` or `rule_error`.
    kind: String,
    /// Match details or the rule error, exactly as stored. Never contains the matched text.
    #[schema(value_type = Object)]
    violation: serde_json::Value,
    violation_pretty: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct ErrorResponse {
    error: String,
}

pub enum ApiError {
    NotFound(String),
    BadRequest(String),
    TooLarge(String),
    Unprocessable(String),
    Internal(String),
}

impl ApiError {
    /// The message sent back to the caller.
    pub fn message(&self) -> &str {
        match self {
            ApiError::NotFound(error)
            | ApiError::BadRequest(error)
            | ApiError::TooLarge(error)
            | ApiError::Unprocessable(error)
            | ApiError::Internal(error) => error,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error) = match self {
            ApiError::NotFound(error) => (StatusCode::NOT_FOUND, error),
            ApiError::BadRequest(error) => (StatusCode::BAD_REQUEST, error),
            ApiError::TooLarge(error) => (StatusCode::PAYLOAD_TOO_LARGE, error),
            ApiError::Unprocessable(error) => (StatusCode::UNPROCESSABLE_ENTITY, error),
            ApiError::Internal(error) => (StatusCode::INTERNAL_SERVER_ERROR, error),
        };
        (status, Json(ErrorResponse { error })).into_response()
    }
}

impl From<ScanError> for ApiError {
    fn from(error: ScanError) -> Self {
        let message = error.to_string();
        match error {
            ScanError::Empty => ApiError::BadRequest(message),
            ScanError::TooLarge { .. } => ApiError::TooLarge(message),
            ScanError::NoRulesEnabled => ApiError::Unprocessable(message),
        }
    }
}

fn internal(error: impl std::fmt::Display) -> ApiError {
    ApiError::Internal(format!("Internal error: {error}"))
}

#[utoipa::path(
    post,
    path = "/api/scan-sessions/{scan_session_id}/scans",
    tag = "API",
    summary = "Scan text in a scan session",
    description = "Scans the text with the session's rule set version and saves the scan and its findings. \
                   The text itself is never stored or logged. Findings are capped at 200.",
    params(("scan_session_id" = i64, Path, description = "The scan session to add this scan to")),
    request_body = CreateScanRequest,
    responses(
        (status = 201, description = "Scan saved", body = ScanResponse),
        (status = 400, description = "No text to scan", body = ErrorResponse),
        (status = 404, description = "No such scan session", body = ErrorResponse),
        (status = 413, description = "Text is over 1 MB", body = ErrorResponse),
        (status = 422, description = "The rule set has no enabled rules", body = ErrorResponse)
    )
)]
pub async fn create_scan(
    State(state): State<AppState>,
    Path(scan_session_id): Path<i64>,
    Json(request): Json<CreateScanRequest>,
) -> Result<(StatusCode, Json<ScanResponse>), ApiError> {
    let response = scan_in_session(&state, scan_session_id, request.text).await?;
    Ok((StatusCode::CREATED, Json(response)))
}

/// Scans `text` with the session's rule set version and saves the scan and its findings. Shared
/// by the REST endpoint and the MCP `run_scan` tool. The text itself is never stored or logged.
pub async fn scan_in_session(
    state: &AppState,
    scan_session_id: i64,
    text: String,
) -> Result<ScanResponse, ApiError> {
    let rule_set = state
        .db
        .call(move |connection| load_rule_set(connection, scan_session_id))
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::NotFound(format!("Scan session {scan_session_id} not found.")))?;

    // The scan row is created first so its id can tag the engine's log events. If the engine
    // rejects the scan, the row is removed again: failed scans are not stored.
    let scan_id = state
        .db
        .call(move |connection| {
            connection.execute(
                "INSERT INTO scans (scan_session_id) VALUES (?1)",
                [scan_session_id],
            )?;
            Ok(connection.last_insert_rowid())
        })
        .await
        .map_err(internal)?;

    let result = run_scan(state, scan_id, text, rule_set).await;
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            state
                .db
                .call(move |connection| {
                    connection.execute("DELETE FROM scans WHERE id = ?1", [scan_id])
                })
                .await
                .map_err(internal)?;
            return Err(error);
        }
    };

    for event in &result.log {
        eprintln!("[scan {}] {}", event.scan_id, event.message);
    }

    save_results(state, scan_session_id, scan_id, result).await
}

/// Runs the engine off the async runtime, behind the concurrency cap.
async fn run_scan(
    state: &AppState,
    scan_id: i64,
    text: String,
    rule_set: RuleSet,
) -> Result<ScanResult, ApiError> {
    let _permit = state
        .scan_permits
        .clone()
        .acquire_owned()
        .await
        .map_err(internal)?;
    tokio::task::spawn_blocking(move || scan(scan_id, &text, &rule_set))
        .await
        .map_err(internal)?
        .map_err(ApiError::from)
}

async fn save_results(
    state: &AppState,
    scan_session_id: i64,
    scan_id: i64,
    result: ScanResult,
) -> Result<ScanResponse, ApiError> {
    let truncated = result.truncated;
    let rows = result
        .findings
        .into_iter()
        .map(|finding| {
            let violation = serde_json::to_value(&finding.violation).map_err(internal)?;
            Ok((finding, violation))
        })
        .collect::<Result<Vec<(Finding, serde_json::Value)>, ApiError>>()?;

    state
        .db
        .call(move |connection| {
            let transaction = connection.transaction()?;
            let mut findings = Vec::with_capacity(rows.len());
            for (finding, violation) in rows {
                let kind = match finding.kind {
                    FindingKind::Match => "match",
                    FindingKind::RuleError => "rule_error",
                };
                transaction.execute(
                    "INSERT INTO findings (scan_id, rule_id, kind, violation, violation_pretty)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        scan_id,
                        finding.rule_id,
                        kind,
                        violation.to_string(),
                        finding.violation_pretty
                    ],
                )?;
                findings.push(FindingResponse {
                    id: transaction.last_insert_rowid(),
                    rule_id: finding.rule_id,
                    kind: kind.to_string(),
                    violation,
                    violation_pretty: finding.violation_pretty,
                });
            }
            transaction.execute(
                "UPDATE scans SET truncated = ?1,
                     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?2",
                rusqlite::params![truncated, scan_id],
            )?;
            transaction.execute(
                "UPDATE scan_sessions SET last_ran = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?1",
                [scan_session_id],
            )?;
            transaction.commit()?;
            Ok(ScanResponse {
                scan_id,
                scan_session_id,
                truncated,
                partial: findings.iter().any(|finding| finding.kind == "rule_error"),
                findings,
            })
        })
        .await
        .map_err(internal)
}

/// A saved scan and its findings, in the same shape the scan endpoint returns. `None` if the
/// scan doesn't exist.
pub fn load_scan(connection: &Connection, scan_id: i64) -> rusqlite::Result<Option<ScanResponse>> {
    let Some((scan_session_id, truncated)) = connection
        .query_row(
            "SELECT scan_session_id, truncated FROM scans WHERE id = ?1",
            [scan_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, bool>(1)?)),
        )
        .optional()?
    else {
        return Ok(None);
    };
    let mut statement = connection.prepare(
        "SELECT id, rule_id, kind, violation, violation_pretty FROM findings
         WHERE scan_id = ?1 ORDER BY id",
    )?;
    let findings = statement
        .query_map([scan_id], |row| {
            let violation: String = row.get(3)?;
            Ok(FindingResponse {
                id: row.get(0)?,
                rule_id: row.get(1)?,
                kind: row.get(2)?,
                violation: serde_json::from_str(&violation).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        3,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
                violation_pretty: row.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Some(ScanResponse {
        scan_id,
        scan_session_id,
        truncated,
        partial: findings.iter().any(|finding| finding.kind == "rule_error"),
        findings,
    }))
}

/// The session's rule set version, in the engine's contract shape. `None` if the session
/// doesn't exist.
fn load_rule_set(
    connection: &mut Connection,
    scan_session_id: i64,
) -> rusqlite::Result<Option<RuleSet>> {
    let Some(version_id) = connection
        .query_row(
            "SELECT rule_set_version_id FROM scan_sessions WHERE id = ?1",
            [scan_session_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
    else {
        return Ok(None);
    };
    let mut statement = connection.prepare(
        "SELECT rule_id, definition FROM rule_set_version_rules
         WHERE rule_set_version_id = ?1 ORDER BY rule_id",
    )?;
    let rules = statement
        .query_map([version_id], |row| {
            let id: i64 = row.get(0)?;
            let definition: String = row.get(1)?;
            let definition: RuleDefinition =
                serde_json::from_str(&definition).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        format!("rule {id} in rule set version {version_id}: {error}").into(),
                    )
                })?;
            Ok(Rule { id, definition })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Some(RuleSet { rules }))
}
