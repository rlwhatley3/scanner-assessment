//! REST routes for rule sets: named lines of versions. The storage rules live in `crate::store`,
//! shared with the MCP server.

use super::{
    AppState,
    error::{ApiError, ErrorBody},
};
use crate::{
    db::Db,
    store::{self, RuleSetRecord, RuleSetSummary, StoreError},
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
    /// Include archived rule sets. Defaults to false.
    #[serde(default)]
    include_archived: bool,
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateRuleSet {
    /// Required, unique among rule sets ignoring case, at most 80 characters.
    name: String,
    #[serde(default)]
    description: String,
    /// Start the set with an exact copy of this version, from any rule set. Omit to start empty.
    from_version_id: Option<i64>,
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRuleSet {
    name: Option<String>,
    description: Option<String>,
    archived: Option<bool>,
}

#[utoipa::path(
    get,
    path = "/api/rule-sets",
    tag = "Rule sets",
    summary = "List rule sets",
    description = "In creation order. Archived sets are left out unless asked for.",
    params(ListQuery),
    responses((status = 200, body = [RuleSetSummary]))
)]
pub async fn list(
    State(db): State<Db>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<RuleSetSummary>>, ApiError> {
    let rule_sets = db
        .call(move |connection| Ok(store::list_rule_sets(connection, query.include_archived)))
        .await??;
    Ok(Json(rule_sets))
}

#[utoipa::path(
    get,
    path = "/api/rule-sets/{id}",
    tag = "Rule sets",
    summary = "Get a rule set and its versions",
    params(("id" = i64, Path, description = "Rule set id")),
    responses((status = 200, body = RuleSetRecord), (status = 404, body = ErrorBody))
)]
pub async fn fetch(
    State(db): State<Db>,
    Path(id): Path<i64>,
) -> Result<Json<RuleSetRecord>, ApiError> {
    let rule_set = db
        .call(move |connection| Ok(store::get_rule_set(connection, id)))
        .await??;
    Ok(Json(rule_set))
}

#[utoipa::path(
    post,
    path = "/api/rule-sets",
    tag = "Rule sets",
    summary = "Create a rule set",
    description = "A named rule set, empty or starting with an exact copy of another version.",
    request_body = CreateRuleSet,
    responses(
        (status = 201, body = RuleSetRecord),
        (status = 422, description = "A missing, too long, or taken name, or an unknown version to copy", body = ErrorBody)
    )
)]
pub async fn create(
    State(db): State<Db>,
    Json(body): Json<CreateRuleSet>,
) -> Result<(StatusCode, Json<RuleSetRecord>), ApiError> {
    let rule_set = db
        .call(move |connection| {
            Ok(store::create_rule_set(
                connection,
                &body.name,
                &body.description,
                body.from_version_id,
            ))
        })
        .await?
        .map_err(|error| match error {
            // The version to copy is named in the request body, so a missing one makes it invalid.
            StoreError::NotFound(message) => ApiError::invalid(message),
            error => error.into(),
        })?;
    Ok((StatusCode::CREATED, Json(rule_set)))
}

#[utoipa::path(
    patch,
    path = "/api/rule-sets/{id}",
    tag = "Rule sets",
    summary = "Rename, redescribe, archive, or restore a rule set",
    description = "Only the fields given change. A set's versions never change.",
    params(("id" = i64, Path, description = "Rule set id")),
    request_body = UpdateRuleSet,
    responses(
        (status = 200, body = RuleSetSummary),
        (status = 404, body = ErrorBody),
        (status = 422, description = "A missing, too long, or taken name", body = ErrorBody)
    )
)]
pub async fn update(
    State(db): State<Db>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateRuleSet>,
) -> Result<Json<RuleSetSummary>, ApiError> {
    let rule_set = db
        .call(move |connection| {
            Ok(store::update_rule_set(
                connection,
                id,
                body.name.as_deref(),
                body.description.as_deref(),
                body.archived,
            ))
        })
        .await??;
    Ok(Json(rule_set))
}
