//! REST routes for rules. The storage rules live in `crate::store`, shared with the MCP server.

use super::{
    AppState,
    error::{ApiError, ErrorBody},
};
use crate::{
    db::Db,
    store::{self, RuleRecord, StoreError},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use rusqlite::Connection;
use secrets_scanner_engine::{Rule, RuleCheck, check_rule_set};
use serde_json::{Map, Value};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list).post(create))
        .route("/{id}", get(fetch).put(update).delete(remove))
        .route("/{id}/check", post(check))
}

/// A rule plus the rule set versions it has been added into.
#[derive(serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleResponse {
    #[serde(flatten)]
    rule: RuleRecord,
    /// The rule set versions holding a snapshot of this rule, oldest first.
    version_ids: Vec<i64>,
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleBody {
    /// Name, pattern, severity and the other rule fields. Unknown or mistyped fields are
    /// rejected; missing ones are fine for a draft.
    #[serde(default)]
    #[schema(value_type = Object)]
    definition: Map<String, Value>,
}

fn with_versions(connection: &Connection, rule: RuleRecord) -> Result<RuleResponse, StoreError> {
    let version_ids = store::rule_version_ids(connection, rule.id)?;
    Ok(RuleResponse { rule, version_ids })
}

/// Runs the engine's checks on one definition, as saving a version would.
fn check_definition(rule_id: i64, definition: Value) -> Result<RuleCheck, StoreError> {
    let definition = store::parse_definition(definition)?;
    Ok(check_rule_set(&[Rule {
        id: rule_id,
        definition,
    }]))
}

#[utoipa::path(
    get,
    path = "/api/rules",
    tag = "Rules",
    summary = "List rules",
    description = "Every rule, drafts included, oldest first.",
    responses((status = 200, body = [RuleResponse]))
)]
pub async fn list(State(db): State<Db>) -> Result<Json<Vec<RuleResponse>>, ApiError> {
    let rules = db
        .call(|connection| {
            Ok(store::list_rules(connection, None).and_then(|rules| {
                rules
                    .into_iter()
                    .map(|rule| with_versions(connection, rule))
                    .collect()
            }))
        })
        .await??;
    Ok(Json(rules))
}

#[utoipa::path(
    post,
    path = "/api/rules",
    tag = "Rules",
    summary = "Create a draft rule",
    description = "Stores a new rule right away as a draft, so it gets its real id and survives a \
                   reload. Drafts are not validated.",
    request_body = RuleBody,
    responses(
        (status = 201, body = RuleResponse),
        (status = 422, description = "Unknown or mistyped fields", body = ErrorBody)
    )
)]
pub async fn create(
    State(db): State<Db>,
    Json(body): Json<RuleBody>,
) -> Result<(StatusCode, Json<RuleResponse>), ApiError> {
    let definition = store::parse_definition(Value::Object(body.definition))?;
    let rule = db
        .call(move |connection| {
            Ok(store::create_rule(connection, &definition)
                .and_then(|rule| with_versions(connection, rule)))
        })
        .await??;
    Ok((StatusCode::CREATED, Json(rule)))
}

#[utoipa::path(
    get,
    path = "/api/rules/{id}",
    tag = "Rules",
    summary = "Get a rule",
    params(("id" = i64, Path, description = "Rule id")),
    responses((status = 200, body = RuleResponse), (status = 404, body = ErrorBody))
)]
pub async fn fetch(
    State(db): State<Db>,
    Path(id): Path<i64>,
) -> Result<Json<RuleResponse>, ApiError> {
    let rule = db
        .call(move |connection| {
            Ok(store::get_rule(connection, id).and_then(|rule| with_versions(connection, rule)))
        })
        .await??;
    Ok(Json(rule))
}

#[utoipa::path(
    put,
    path = "/api/rules/{id}",
    tag = "Rules",
    summary = "Save a rule",
    description = "Replaces the rule's definition. A draft saves as-is; a rule that has been \
                   added into a version must pass the engine's checks. Versions keep their own \
                   snapshot, so this never changes what an existing version scans with.",
    params(("id" = i64, Path, description = "Rule id")),
    request_body = RuleBody,
    responses(
        (status = 200, body = RuleResponse),
        (status = 404, body = ErrorBody),
        (status = 422, description = "Mistyped fields, or a non-draft rule that fails its checks", body = ErrorBody)
    )
)]
pub async fn update(
    State(db): State<Db>,
    Path(id): Path<i64>,
    Json(body): Json<RuleBody>,
) -> Result<Json<RuleResponse>, ApiError> {
    let definition = Value::Object(body.definition);
    let rule = db
        .call(move |connection| Ok(save(connection, id, definition)))
        .await??;
    Ok(Json(rule))
}

fn save(connection: &Connection, id: i64, definition: Value) -> Result<RuleResponse, ApiError> {
    let definition = store::parse_definition(definition)?;
    let rule = store::update_rule(connection, id, &definition).map_err(|error| match error {
        StoreError::RulesInvalid(check) => ApiError::Invalid {
            message: "Fix the rule's errors before saving.".to_owned(),
            errors: check.errors,
        },
        error => error.into(),
    })?;
    Ok(with_versions(connection, rule)?)
}

#[utoipa::path(
    delete,
    path = "/api/rules/{id}",
    tag = "Rules",
    summary = "Delete a draft rule",
    description = "Only a draft, which is in no rule set version, can be deleted. Its id is never \
                   reused.",
    params(("id" = i64, Path, description = "Rule id")),
    responses(
        (status = 204),
        (status = 404, body = ErrorBody),
        (status = 409, description = "The rule is in a rule set version", body = ErrorBody)
    )
)]
pub async fn remove(State(db): State<Db>, Path(id): Path<i64>) -> Result<StatusCode, ApiError> {
    db.call(move |connection| Ok(store::delete_draft_rule(connection, id)))
        .await?
        .map_err(|error| match error {
            StoreError::Invalid(message) => ApiError::Conflict(message),
            error => error.into(),
        })?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/rules/{id}/check",
    tag = "Rules",
    summary = "Check a rule definition",
    description = "Runs the engine's checks on a definition for this rule without saving it, for \
                   inline form errors.",
    params(("id" = i64, Path, description = "Rule id")),
    request_body = RuleBody,
    responses(
        (status = 200, description = "The engine's errors and warnings", body = Object),
        (status = 404, body = ErrorBody),
        (status = 422, description = "Unknown or mistyped fields", body = ErrorBody)
    )
)]
pub async fn check(
    State(db): State<Db>,
    Path(id): Path<i64>,
    Json(body): Json<RuleBody>,
) -> Result<Json<RuleCheck>, ApiError> {
    db.call(move |connection| Ok(store::get_rule(connection, id).map(|_| ())))
        .await??;
    Ok(Json(check_definition(id, Value::Object(body.definition))?))
}
