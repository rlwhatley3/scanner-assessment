use super::AppState;
use super::{
    error::{ApiError, ErrorBody, json_column},
    rules,
};
use crate::{db::Db, validation};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list).post(create))
        .route("/{id}", get(fetch).patch(update))
}

#[derive(serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetVersion {
    id: i64,
    /// The version this one was based on, if any.
    parent_id: Option<i64>,
    /// Archived versions are hidden from the timeline, not deleted.
    archived: bool,
    rule_count: i64,
    scan_session_count: i64,
    created_at: String,
    updated_at: String,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VersionRule {
    rule_id: i64,
    /// The rule's definition as it was when added to this version.
    #[schema(value_type = Object)]
    definition: Value,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetVersionDetail {
    #[serde(flatten)]
    version: RuleSetVersion,
    rules: Vec<VersionRule>,
}

#[derive(serde::Deserialize, utoipa::IntoParams)]
#[serde(rename_all = "camelCase")]
#[into_params(rename_all = "camelCase")]
pub struct ListQuery {
    /// Include archived versions. Defaults to false.
    #[serde(default)]
    include_archived: bool,
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateVersion {
    /// The version this one is based on.
    parent_id: Option<i64>,
    /// The rules to add, by id. Each one's current definition is snapshotted into the version.
    rule_ids: Vec<i64>,
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateVersion {
    archived: bool,
}

const SELECT_VERSION: &str = "SELECT id, parent_id, archived, created_at, updated_at,
        (SELECT COUNT(*) FROM rule_set_version_rules WHERE rule_set_version_id = v.id),
        (SELECT COUNT(*) FROM scan_sessions WHERE rule_set_version_id = v.id)
    FROM rule_set_versions v";

fn read_version(row: &rusqlite::Row) -> rusqlite::Result<RuleSetVersion> {
    Ok(RuleSetVersion {
        id: row.get(0)?,
        parent_id: row.get(1)?,
        archived: row.get(2)?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
        rule_count: row.get(5)?,
        scan_session_count: row.get(6)?,
    })
}

impl RuleSetVersion {
    pub(crate) fn is_archived(&self) -> bool {
        self.archived
    }
}

pub(crate) fn load_version(
    connection: &Connection,
    id: i64,
) -> rusqlite::Result<Option<RuleSetVersion>> {
    connection
        .query_row(
            &format!("{SELECT_VERSION} WHERE id = ?1"),
            [id],
            read_version,
        )
        .optional()
}

fn load_detail(connection: &Connection, id: i64) -> rusqlite::Result<Option<RuleSetVersionDetail>> {
    let Some(version) = load_version(connection, id)? else {
        return Ok(None);
    };
    let mut statement = connection.prepare(
        "SELECT rule_id, definition FROM rule_set_version_rules
         WHERE rule_set_version_id = ?1 ORDER BY rule_id",
    )?;
    let rules = statement
        .query_map([id], |row| {
            Ok(VersionRule {
                rule_id: row.get(0)?,
                definition: json_column(row, 1)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Some(RuleSetVersionDetail { version, rules }))
}

fn not_found(id: i64) -> ApiError {
    ApiError::NotFound(format!("Rule set version {id} does not exist."))
}

#[utoipa::path(
    get,
    path = "/api/rule-set-versions",
    tag = "Rule set versions",
    summary = "List rule set versions",
    description = "The version timeline, oldest first. Archived versions are left out unless asked for.",
    params(ListQuery),
    responses((status = 200, body = [RuleSetVersion]))
)]
pub async fn list(
    State(db): State<Db>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<RuleSetVersion>>, ApiError> {
    let versions = db
        .call(move |connection| {
            let mut statement = connection.prepare(&format!(
                "{SELECT_VERSION} WHERE ?1 OR archived = 0 ORDER BY id"
            ))?;
            statement
                .query_map([query.include_archived], read_version)?
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .await?;
    Ok(Json(versions))
}

#[utoipa::path(
    get,
    path = "/api/rule-set-versions/{id}",
    tag = "Rule set versions",
    summary = "Get a rule set version and its rules",
    params(("id" = i64, Path, description = "Rule set version id")),
    responses((status = 200, body = RuleSetVersionDetail), (status = 404, body = ErrorBody))
)]
pub async fn fetch(
    State(db): State<Db>,
    Path(id): Path<i64>,
) -> Result<Json<RuleSetVersionDetail>, ApiError> {
    db.call(move |connection| load_detail(connection, id))
        .await?
        .map(Json)
        .ok_or_else(|| not_found(id))
}

#[utoipa::path(
    post,
    path = "/api/rule-set-versions",
    tag = "Rule set versions",
    summary = "Save a new rule set version",
    description = "Validates every listed rule, snapshots each one's current definition into the \
                   new version, and clears drafting on them. Nothing is saved if any rule is \
                   invalid, so every saved version is valid.",
    request_body = CreateVersion,
    responses(
        (status = 201, body = RuleSetVersionDetail),
        (status = 422, description = "No rules, an unknown rule or parent, or invalid rules", body = ErrorBody)
    )
)]
pub async fn create(
    State(db): State<Db>,
    Json(body): Json<CreateVersion>,
) -> Result<(StatusCode, Json<RuleSetVersionDetail>), ApiError> {
    let mut rule_ids = body.rule_ids;
    rule_ids.sort_unstable();
    rule_ids.dedup();
    if rule_ids.is_empty() {
        return Err(ApiError::invalid("Add at least one rule to the version."));
    }

    let detail = db
        .call(move |connection| {
            if let Some(parent_id) = body.parent_id
                && load_version(connection, parent_id)?.is_none()
            {
                return Ok(Err(ApiError::invalid(format!(
                    "Rule set version {parent_id} does not exist."
                ))));
            }

            let mut definitions = Vec::with_capacity(rule_ids.len());
            for &rule_id in &rule_ids {
                let Some(rule) = rules::load_rule(connection, rule_id)? else {
                    return Ok(Err(ApiError::invalid(format!(
                        "Rule {rule_id} does not exist."
                    ))));
                };
                definitions.push((rule_id, rule.definition().clone()));
            }

            let check = validation::check_rule_set(&definitions);
            if !check.errors.is_empty() {
                return Ok(Err(ApiError::Invalid {
                    message: "Some rules have errors. Fix them, then save the version again."
                        .to_owned(),
                    errors: check.errors,
                }));
            }

            let transaction = connection.transaction()?;
            transaction.execute(
                "INSERT INTO rule_set_versions (parent_id) VALUES (?1)",
                [body.parent_id],
            )?;
            let id = transaction.last_insert_rowid();
            for (rule_id, definition) in &definitions {
                transaction.execute(
                    "INSERT INTO rule_set_version_rules (rule_set_version_id, rule_id, definition)
                     VALUES (?1, ?2, ?3)",
                    params![id, rule_id, definition.to_string()],
                )?;
                transaction.execute(
                    "UPDATE rules SET drafting = 0,
                         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                     WHERE id = ?1 AND drafting = 1",
                    [rule_id],
                )?;
            }
            transaction.commit()?;
            load_detail(connection, id).map(|detail| Ok(detail.expect("new version should exist")))
        })
        .await??;
    Ok((StatusCode::CREATED, Json(detail)))
}

#[utoipa::path(
    patch,
    path = "/api/rule-set-versions/{id}",
    tag = "Rule set versions",
    summary = "Archive or restore a rule set version",
    params(("id" = i64, Path, description = "Rule set version id")),
    request_body = UpdateVersion,
    responses((status = 200, body = RuleSetVersion), (status = 404, body = ErrorBody))
)]
pub async fn update(
    State(db): State<Db>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateVersion>,
) -> Result<Json<RuleSetVersion>, ApiError> {
    db.call(move |connection| {
        connection.execute(
            "UPDATE rule_set_versions SET archived = ?1,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?2",
            params![body.archived, id],
        )?;
        load_version(connection, id)
    })
    .await?
    .map(Json)
    .ok_or_else(|| not_found(id))
}
