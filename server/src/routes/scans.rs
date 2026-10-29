use super::AppState;
use crate::store::{self, RuleTimingRecord, SlowRule};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rusqlite::{Connection, OptionalExtension};
use secrets_scanner_engine::{
    Finding, FindingKind, Rule, RuleDefinition, RuleSet, ScanError, ScanOptions, ScanResult,
    scan_with_options,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use tokio::sync::oneshot;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/{scan_session_id}/scans", post(create_scan))
        .route("/{scan_session_id}/scans/{scan_id}", get(fetch_scan))
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
    pub scan_id: i64,
    pub scan_session_id: i64,
    /// `completed` once the findings are saved. `running` while the engine runs, and
    /// `interrupted` when the scan ended before its findings were saved (the request was
    /// cancelled or cut off, or the server stopped), so they are missing: an interrupted scan
    /// with no findings is not clean.
    pub status: String,
    /// True when there were more findings than the cap and the rest were not saved.
    pub truncated: bool,
    /// True when at least one rule could not run.
    pub partial: bool,
    /// Matches left out because one of the session's active suppressions covers their value: the
    /// same rule found the same value. They are neither returned nor saved.
    pub suppressed_count: i64,
    pub findings: Vec<FindingResponse>,
    /// Rules that matched so much of the text that they slowed the scan, each with a message
    /// saying what to change. Empty for most scans.
    pub slow_rules: Vec<SlowRule>,
    /// What each rule that ran cost the scan, in the order they ran. Empty for a scan that
    /// didn't finish.
    pub rule_timings: Vec<RuleTimingRecord>,
}

/// How to read a finding's violation, for API docs and MCP clients.
const VIOLATION_HELP: &str = "Each match's violation holds ruleName, detectionType, severity, \
location (byte offsets plus 1-based line and column), and redactedPreview (the rule's prefix only). \
confidence (0-100) is how likely the match is what its rule describes, from the evidence about \
that match, weighed the same whatever the rule's type: every match starts at 50, and a passing \
or failing checksum, the format's prefix, a secret-sounding key name, required syntax around the \
value, how random the value is for its length (or its password shape), and, for a match with no \
value, whether the secret name it mentions is code or only a word in a quoted message and whether \
it's commented out each move it up or down, between 1 and 99; whyFlagged lists the evidence. \
model_detection matches the model's score. A rule's value classifier lowers it to 30 when the \
credential score is below its minScore, or raises it halfway toward a higher credential score, up \
to 95. placeholderScore (0-100, higher = more likely an example; null for unsafe handling). \
valueClass (null unless the rule has a value classifier): label credential, non_secret, or \
placeholder, with a 0-100 score for each. modelAssessments: each model_assessment rule's score \
and verdict. checksumValid and inComment are true, false, or null. Matches with the same \
overlapGroup cover overlapping text. whyFlagged explains the scores from signals only. A finding \
of kind rule_error names the rule, field, and code of a rule that couldn't run; partial is true \
when there is one.";

#[derive(Serialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FindingResponse {
    pub id: i64,
    pub rule_id: i64,
    /// `match` or `rule_error`.
    pub kind: String,
    /// Match details or the rule error, exactly as stored. Never contains the matched text.
    #[schema(value_type = Object)]
    #[schemars(description = VIOLATION_HELP)]
    pub violation: serde_json::Value,
    pub violation_pretty: String,
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
                   The text itself is never stored or logged. Findings are capped at 200. A match \
                   whose value one of the session's active suppressions covers is not reported \
                   or saved; suppressedCount says how many were left out. ruleTimings gives \
                   each rule's time and match count, and slowRules names rules that matched so \
                   much of the text that they slowed the scan.",
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

#[utoipa::path(
    get,
    path = "/api/scan-sessions/{scan_session_id}/scans/{scan_id}",
    tag = "API",
    summary = "Get a saved scan",
    description = "A saved scan and its findings, in the same shape the scan endpoint returns. \
                   Findings never contain the matched text. status is interrupted when the scan \
                   ended before its findings were saved, so they are missing.",
    params(
        ("scan_session_id" = i64, Path, description = "The scan session the scan belongs to"),
        ("scan_id" = i64, Path, description = "Scan id")
    ),
    responses(
        (status = 200, description = "The scan and its findings", body = ScanResponse),
        (status = 404, description = "No such scan in this scan session", body = ErrorResponse)
    )
)]
pub async fn fetch_scan(
    State(state): State<AppState>,
    Path((scan_session_id, scan_id)): Path<(i64, i64)>,
) -> Result<Json<ScanResponse>, ApiError> {
    state
        .db
        .call(move |connection| load_scan(connection, scan_id))
        .await
        .map_err(internal)?
        .filter(|scan| scan.scan_session_id == scan_session_id)
        .map(Json)
        .ok_or_else(|| {
            ApiError::NotFound(format!(
                "Scan {scan_id} not found in scan session {scan_session_id}."
            ))
        })
}

/// Scans `text` with the session's rule set version and saves the scan and its findings. Shared
/// by the REST endpoint and the MCP `run_scan` tool. The text itself is never stored or logged.
///
/// The scan runs as its own task, so it always settles: completed, interrupted, or removed. A
/// request's future is dropped when its caller disconnects, and code after the await that was
/// running would never run. Dropping this future only tells the task its caller left.
pub async fn scan_in_session(
    state: &AppState,
    scan_session_id: i64,
    text: String,
) -> Result<ScanResponse, ApiError> {
    let (_caller, caller_left) = oneshot::channel::<()>();
    let state = state.clone();
    tokio::spawn(async move { scan_and_save(&state, scan_session_id, text, caller_left).await })
        .await
        .map_err(internal)?
}

/// The task behind [`scan_in_session`]. `caller_left` resolves when the request is dropped.
async fn scan_and_save(
    state: &AppState,
    scan_session_id: i64,
    text: String,
    mut caller_left: oneshot::Receiver<()>,
) -> Result<ScanResponse, ApiError> {
    let rule_set = state
        .db
        .call(move |connection| load_rule_set(connection, scan_session_id))
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::NotFound(format!("Scan session {scan_session_id} not found.")))?;
    let names = rule_names(&rule_set);

    // The scan row is created first so its id can tag the engine's log events. If the engine
    // rejects the scan, the row is removed again: failed scans are not stored.
    let text_bytes = i64::try_from(text.len()).unwrap_or(i64::MAX);
    let scan_id = state
        .db
        .call(move |connection| {
            connection.execute(
                "INSERT INTO scans (scan_session_id, status, text_bytes) VALUES (?1, 'running', ?2)",
                [scan_session_id, text_bytes],
            )?;
            Ok(connection.last_insert_rowid())
        })
        .await
        .map_err(internal)?;

    // If the caller leaves first, the scan stops waiting for the engine (which can't be stopped
    // midway, so it finishes and its results are dropped) and is marked interrupted.
    let result = tokio::select! {
        result = run_scan(state, scan_id, text, rule_set, true) => result,
        _ = &mut caller_left => {
            interrupt(state, scan_id).await;
            return Err(ApiError::Internal("The caller left before the scan finished.".into()));
        }
    };
    let result = match result {
        Ok(result) => result,
        Err(error @ ApiError::Internal(_)) => {
            interrupt(state, scan_id).await;
            return Err(error);
        }
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

    let saved = save_results(state, scan_session_id, scan_id, text_bytes, result, &names).await;
    if saved.is_err() {
        interrupt(state, scan_id).await;
    }
    saved
}

/// Each rule's name for messages, or "Rule <id>" when it has none.
fn rule_names(rule_set: &RuleSet) -> HashMap<i64, String> {
    rule_set
        .rules
        .iter()
        .map(|rule| {
            let name = rule
                .definition
                .name
                .as_deref()
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map_or_else(|| format!("Rule {}", rule.id), String::from);
            (rule.id, name)
        })
        .collect()
}

/// The engine's rule timings, named.
fn timing_records(result: &ScanResult, names: &HashMap<i64, String>) -> Vec<RuleTimingRecord> {
    result
        .rule_timings
        .iter()
        .map(|timing| RuleTimingRecord {
            rule_id: timing.rule_id,
            rule_name: names
                .get(&timing.rule_id)
                .cloned()
                .unwrap_or_else(|| format!("Rule {}", timing.rule_id)),
            micros: timing.micros,
            matches: timing.matches,
            floods: timing.floods,
        })
        .collect()
}

/// Marks a scan that ended before its findings were saved as interrupted. If even that fails,
/// the scan stays running until the server next starts and marks it.
async fn interrupt(state: &AppState, scan_id: i64) {
    let marked = state
        .db
        .call(move |connection| store::interrupt_running_scans(connection, Some(scan_id)))
        .await;
    if let Err(error) = marked {
        eprintln!("[scan {scan_id}] could not be marked interrupted: {error}");
    }
}

/// Runs the engine off the async runtime, behind the concurrency cap. `fingerprint` is false
/// when nothing will be saved, so no value needs recognizing later.
async fn run_scan(
    state: &AppState,
    scan_id: i64,
    text: String,
    rule_set: RuleSet,
    fingerprint: bool,
) -> Result<ScanResult, ApiError> {
    let _permit = state
        .scan_permits
        .clone()
        .acquire_owned()
        .await
        .map_err(internal)?;
    let models = state.models.clone();
    let fingerprint_key = state.fingerprint_key.clone();
    tokio::task::spawn_blocking(move || {
        let options = ScanOptions {
            models: Some(&models),
            fingerprint_key: fingerprint.then_some(&*fingerprint_key),
        };
        scan_with_options(scan_id, &text, &rule_set, options)
    })
    .await
    .map_err(internal)?
    .map_err(ApiError::from)
}

async fn save_results(
    state: &AppState,
    scan_session_id: i64,
    scan_id: i64,
    text_bytes: i64,
    result: ScanResult,
    names: &HashMap<i64, String>,
) -> Result<ScanResponse, ApiError> {
    let truncated = result.truncated;
    let rule_timings = timing_records(&result, names);
    let timings_json = serde_json::to_string(&rule_timings).map_err(internal)?;
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
            // The rule and fingerprint each of the session's active suppressions covers. An
            // expired or removed one is left out, so its value is reported again.
            let suppressed: HashSet<(i64, String)> =
                store::active_suppressions(&transaction, scan_session_id)?
                    .into_iter()
                    .map(|active| (active.rule_id, active.fingerprint))
                    .collect();
            let mut findings = Vec::with_capacity(rows.len());
            let mut suppressed_count = 0;
            for (finding, violation) in rows {
                if let Some(fingerprint) = &finding.fingerprint
                    && suppressed.contains(&(finding.rule_id, fingerprint.clone()))
                {
                    suppressed_count += 1;
                    continue;
                }
                let kind = match finding.kind {
                    FindingKind::Match => "match",
                    FindingKind::RuleError => "rule_error",
                };
                transaction.execute(
                    "INSERT INTO findings
                         (scan_id, rule_id, kind, violation, violation_pretty, fingerprint)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        scan_id,
                        finding.rule_id,
                        kind,
                        violation.to_string(),
                        finding.violation_pretty,
                        finding.fingerprint
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
                "UPDATE scans SET truncated = ?1, suppressed_count = ?2, status = 'completed',
                     rule_timings = ?3, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?4",
                rusqlite::params![truncated, suppressed_count, timings_json, scan_id],
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
                status: "completed".to_string(),
                truncated,
                partial: findings.iter().any(|finding| finding.kind == "rule_error"),
                suppressed_count,
                findings,
                slow_rules: store::slow_rules(&rule_timings, Some(text_bytes)),
                rule_timings,
            })
        })
        .await
        .map_err(internal)
}

/// A saved scan and its findings, in the same shape the scan endpoint returns. `None` if the
/// scan doesn't exist.
pub fn load_scan(connection: &Connection, scan_id: i64) -> rusqlite::Result<Option<ScanResponse>> {
    let Some((scan_session_id, truncated, suppressed_count, status, timings, text_bytes)) =
        connection
            .query_row(
                "SELECT scan_session_id, truncated, suppressed_count, status, rule_timings,
                     text_bytes
                 FROM scans WHERE id = ?1",
                [scan_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                    ))
                },
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
    let rule_timings = store::parse_rule_timings(&timings);
    Ok(Some(ScanResponse {
        scan_id,
        scan_session_id,
        status,
        truncated,
        partial: findings.iter().any(|finding| finding.kind == "rule_error"),
        suppressed_count,
        findings,
        slow_rules: store::slow_rules(&rule_timings, text_bytes),
        rule_timings,
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

fn store_error(error: store::StoreError) -> ApiError {
    match error {
        store::StoreError::NotFound(message) => ApiError::NotFound(message),
        store::StoreError::Invalid(message) => ApiError::Unprocessable(message),
        store::StoreError::RulesInvalid(_) => {
            ApiError::Unprocessable("The rule is invalid.".into())
        }
        store::StoreError::Database(error) => internal(error),
    }
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TryRuleRequest {
    /// The rule's definition as it stands in the editor, saved or not.
    #[schema(value_type = Object)]
    definition: serde_json::Value,
    /// Sample text to try it on. It is never stored or logged.
    text: String,
}

#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TryRuleResponse {
    /// True when there were more findings than the cap and the rest were dropped.
    truncated: bool,
    /// Matches, or the rule error that stopped the rule from running. Never contain the matched
    /// text, and have no ids: nothing is saved.
    #[schema(value_type = Vec<Object>)]
    findings: Vec<TriedFinding>,
    /// The rule, if it matched so much of the text that it would slow every scan.
    slow_rules: Vec<SlowRule>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TriedFinding {
    rule_id: i64,
    kind: FindingKind,
    violation: serde_json::Value,
    violation_pretty: String,
}

#[utoipa::path(
    post,
    path = "/api/rules/{id}/try",
    tag = "Rules",
    summary = "Try a rule on sample text",
    description = "Runs one rule definition, saved or not, on sample text and returns what it \
                   finds. Nothing is saved: not the text, the scan, or its findings, so this \
                   needs no rule set version or scan session. The rule runs even when its \
                   definition is disabled. Rules that only adjust other findings (placeholder \
                   vs. real, model assessment) find nothing on their own and are rejected. \
                   slowRules holds the rule if it matched so much of the text that it would \
                   slow every scan.",
    params(("id" = i64, Path, description = "Rule id")),
    request_body = TryRuleRequest,
    responses(
        (status = 200, description = "What the rule found", body = TryRuleResponse),
        (status = 400, description = "No text to try", body = ErrorResponse),
        (status = 404, description = "No such rule", body = ErrorResponse),
        (status = 413, description = "Text is over 1 MB", body = ErrorResponse),
        (status = 422, description = "Mistyped fields, or a rule that creates no findings", body = ErrorResponse)
    )
)]
pub async fn try_rule(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(request): Json<TryRuleRequest>,
) -> Result<Json<TryRuleResponse>, ApiError> {
    state
        .db
        .call(move |connection| Ok(store::get_rule(connection, id).map(|_| ())))
        .await
        .map_err(internal)?
        .map_err(store_error)?;
    let mut definition = store::parse_definition(request.definition).map_err(store_error)?;
    definition.enabled = Some(true);
    let rule_set = RuleSet {
        rules: vec![Rule { id, definition }],
    };
    let names = rule_names(&rule_set);
    let text_bytes = i64::try_from(request.text.len()).unwrap_or(i64::MAX);
    let result = run_scan(&state, 0, request.text, rule_set, false).await?;
    let slow_rules = store::slow_rules(&timing_records(&result, &names), Some(text_bytes));
    let findings = result
        .findings
        .into_iter()
        .map(|finding| {
            Ok(TriedFinding {
                rule_id: finding.rule_id,
                kind: finding.kind,
                violation: serde_json::to_value(&finding.violation).map_err(internal)?,
                violation_pretty: finding.violation_pretty,
            })
        })
        .collect::<Result<_, ApiError>>()?;
    Ok(Json(TryRuleResponse {
        truncated: result.truncated,
        findings,
        slow_rules,
    }))
}
