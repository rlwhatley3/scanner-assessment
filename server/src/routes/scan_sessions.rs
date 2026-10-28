use super::AppState;
use super::{
    error::{ApiError, ErrorBody, json_column},
    rule_set_versions,
};
use crate::db::Db;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list).post(create))
        .route("/{id}", get(fetch))
}

#[derive(serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScanSession {
    id: i64,
    rule_set_version_id: i64,
    /// When the session's latest scan ran; null until the first one.
    last_ran: Option<String>,
    scan_count: i64,
    created_at: String,
    updated_at: String,
}

/// A stored finding. It holds no scan text and no matched value.
#[derive(serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StoredFinding {
    id: i64,
    rule_id: i64,
    /// `match` or `rule_error`.
    kind: String,
    #[schema(value_type = Object)]
    violation: Value,
    violation_pretty: String,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct StoredScan {
    id: i64,
    /// True when the scan hit the findings cap and the rest were not saved.
    truncated: bool,
    created_at: String,
    findings: Vec<StoredFinding>,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScanSessionDetail {
    #[serde(flatten)]
    session: ScanSession,
    /// Oldest first.
    scans: Vec<StoredScan>,
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateSession {
    rule_set_version_id: i64,
}

const SELECT_SESSION: &str = "SELECT id, rule_set_version_id, last_ran, created_at, updated_at,
        (SELECT COUNT(*) FROM scans WHERE scan_session_id = s.id)
    FROM scan_sessions s";

fn read_session(row: &rusqlite::Row) -> rusqlite::Result<ScanSession> {
    Ok(ScanSession {
        id: row.get(0)?,
        rule_set_version_id: row.get(1)?,
        last_ran: row.get(2)?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
        scan_count: row.get(5)?,
    })
}

fn load_session(connection: &Connection, id: i64) -> rusqlite::Result<Option<ScanSession>> {
    connection
        .query_row(
            &format!("{SELECT_SESSION} WHERE id = ?1"),
            [id],
            read_session,
        )
        .optional()
}

fn load_detail(connection: &Connection, id: i64) -> rusqlite::Result<Option<ScanSessionDetail>> {
    let Some(session) = load_session(connection, id)? else {
        return Ok(None);
    };
    let mut scans_statement = connection.prepare(
        "SELECT id, truncated, created_at FROM scans WHERE scan_session_id = ?1 ORDER BY id",
    )?;
    let mut findings_statement = connection.prepare(
        "SELECT id, rule_id, kind, violation, violation_pretty FROM findings
         WHERE scan_id = ?1 ORDER BY id",
    )?;
    let mut scans = scans_statement
        .query_map([id], |row| {
            Ok(StoredScan {
                id: row.get(0)?,
                truncated: row.get(1)?,
                created_at: row.get(2)?,
                findings: Vec::new(),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for scan in &mut scans {
        scan.findings = findings_statement
            .query_map([scan.id], |row| {
                Ok(StoredFinding {
                    id: row.get(0)?,
                    rule_id: row.get(1)?,
                    kind: row.get(2)?,
                    violation: json_column(row, 3)?,
                    violation_pretty: row.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
    }
    Ok(Some(ScanSessionDetail { session, scans }))
}

#[utoipa::path(
    get,
    path = "/api/scan-sessions",
    tag = "Scan sessions",
    summary = "List scan sessions",
    description = "Newest first.",
    responses((status = 200, body = [ScanSession]))
)]
pub async fn list(State(db): State<Db>) -> Result<Json<Vec<ScanSession>>, ApiError> {
    let sessions = db
        .call(|connection| {
            let mut statement =
                connection.prepare(&format!("{SELECT_SESSION} ORDER BY id DESC"))?;
            statement
                .query_map([], read_session)?
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .await?;
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
        (status = 201, body = ScanSessionDetail),
        (status = 422, description = "Unknown or archived rule set version", body = ErrorBody)
    )
)]
pub async fn create(
    State(db): State<Db>,
    Json(body): Json<CreateSession>,
) -> Result<(StatusCode, Json<ScanSessionDetail>), ApiError> {
    let version_id = body.rule_set_version_id;
    let detail = db
        .call(move |connection| {
            let Some(version) = rule_set_versions::load_version(connection, version_id)? else {
                return Ok(Err(ApiError::invalid(format!(
                    "Rule set version {version_id} does not exist."
                ))));
            };
            if version.is_archived() {
                return Ok(Err(ApiError::invalid(format!(
                    "Rule set version {version_id} is archived. Restore it or pick another."
                ))));
            }
            connection.execute(
                "INSERT INTO scan_sessions (rule_set_version_id) VALUES (?1)",
                [version_id],
            )?;
            let id = connection.last_insert_rowid();
            load_detail(connection, id).map(|detail| Ok(detail.expect("new session should exist")))
        })
        .await??;
    Ok((StatusCode::CREATED, Json(detail)))
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
    db.call(move |connection| load_detail(connection, id))
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::NotFound(format!("Scan session {id} does not exist.")))
}
