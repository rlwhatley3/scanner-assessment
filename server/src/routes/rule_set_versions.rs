//! REST routes for rule set versions. The storage rules live in `crate::store`, shared with the
//! MCP server.

use super::{
    AppState,
    error::{ApiError, ErrorBody},
};
use crate::{
    db::Db,
    store::{self, RuleSetVersionRecord, RuleSetVersionSummary, StoreError},
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list).post(create))
        .route("/{id}", get(fetch).patch(update))
}

#[derive(serde::Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(rename_all = "camelCase")]
pub struct ListQuery {
    /// Only this rule set's versions. Omit for every set's.
    rule_set_id: Option<i64>,
    /// Include archived versions. Defaults to false.
    #[serde(default)]
    include_archived: bool,
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateVersion {
    /// The rule set the version is added to.
    rule_set_id: i64,
    /// The version this one is based on, from the same rule set.
    parent_id: Option<i64>,
    /// The rules to add, by id, each listed once. Each one's current definition is snapshotted
    /// into the version.
    rule_ids: Vec<i64>,
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateVersion {
    archived: bool,
}

#[utoipa::path(
    get,
    path = "/api/rule-set-versions",
    tag = "Rule set versions",
    summary = "List rule set versions",
    description = "Versions oldest first, for every rule set or one. Archived versions are left out unless asked for.",
    params(ListQuery),
    responses((status = 200, body = [RuleSetVersionSummary]))
)]
pub async fn list(
    State(db): State<Db>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<RuleSetVersionSummary>>, ApiError> {
    let versions = db
        .call(move |connection| {
            Ok(store::list_versions(
                connection,
                query.rule_set_id,
                query.include_archived,
            ))
        })
        .await??;
    Ok(Json(versions))
}

#[utoipa::path(
    get,
    path = "/api/rule-set-versions/{id}",
    tag = "Rule set versions",
    summary = "Get a rule set version and its rules",
    params(("id" = i64, Path, description = "Rule set version id")),
    responses((status = 200, body = RuleSetVersionRecord), (status = 404, body = ErrorBody))
)]
pub async fn fetch(
    State(db): State<Db>,
    Path(id): Path<i64>,
) -> Result<Json<RuleSetVersionRecord>, ApiError> {
    let version = db
        .call(move |connection| Ok(store::get_version(connection, id)))
        .await??;
    Ok(Json(version))
}

#[utoipa::path(
    post,
    path = "/api/rule-set-versions",
    tag = "Rule set versions",
    summary = "Save a new version of a rule set",
    description = "Runs the engine's checks on the listed rules as one set, snapshots each one's \
                   current definition into the new version, and clears drafting on them. Nothing \
                   is saved if any rule fails, so every saved version is valid.",
    request_body = CreateVersion,
    responses(
        (status = 201, body = RuleSetVersionRecord),
        (status = 422, description = "No rules, a repeated or unknown rule, an unknown or archived rule set, a parent from another set, or rules that fail their checks", body = ErrorBody)
    )
)]
pub async fn create(
    State(db): State<Db>,
    Json(body): Json<CreateVersion>,
) -> Result<(StatusCode, Json<RuleSetVersionRecord>), ApiError> {
    let version = db
        .call(move |connection| {
            Ok(store::create_version(
                connection,
                body.rule_set_id,
                body.parent_id,
                &body.rule_ids,
            ))
        })
        .await?
        .map_err(|error| match error {
            // Ids in the request body that don't exist make the request invalid, not missing.
            StoreError::NotFound(message) => ApiError::invalid(message),
            error => error.into(),
        })?
        .0;
    Ok((StatusCode::CREATED, Json(version)))
}

#[utoipa::path(
    patch,
    path = "/api/rule-set-versions/{id}",
    tag = "Rule set versions",
    summary = "Archive or restore a rule set version",
    params(("id" = i64, Path, description = "Rule set version id")),
    request_body = UpdateVersion,
    responses((status = 200, body = RuleSetVersionSummary), (status = 404, body = ErrorBody))
)]
pub async fn update(
    State(db): State<Db>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateVersion>,
) -> Result<Json<RuleSetVersionSummary>, ApiError> {
    let version = db
        .call(move |connection| Ok(store::set_version_archived(connection, id, body.archived)))
        .await??;
    Ok(Json(version))
}
