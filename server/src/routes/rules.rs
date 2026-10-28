use super::error::{ApiError, ErrorBody, json_column};
use crate::{
    db::Db,
    validation::{self, RuleCheck},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::Value;

pub fn router() -> Router<Db> {
    Router::new()
        .route("/", get(list).post(create))
        .route("/{id}", get(fetch).put(update).delete(remove))
        .route("/{id}/check", post(check))
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct Rule {
    id: i64,
    /// True until the rule is added into a rule set version. Drafts are not validated.
    drafting: bool,
    /// Name, pattern, severity and the other rule fields, as set by the rule form.
    #[schema(value_type = Object)]
    definition: Value,
    /// The rule set versions this rule has been added into, oldest first.
    version_ids: Vec<i64>,
    created_at: String,
    updated_at: String,
}

impl Rule {
    pub(crate) fn definition(&self) -> &Value {
        &self.definition
    }
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct RuleBody {
    #[serde(default = "empty_definition")]
    #[schema(value_type = Object)]
    definition: Value,
}

fn empty_definition() -> Value {
    Value::Object(Default::default())
}

const SELECT_RULE: &str = "SELECT id, drafting, definition, created_at, updated_at,
        (SELECT json_group_array(rule_set_version_id) FROM (
            SELECT rule_set_version_id FROM rule_set_version_rules
            WHERE rule_id = rules.id ORDER BY rule_set_version_id))
    FROM rules";

fn read_rule(row: &rusqlite::Row) -> rusqlite::Result<Rule> {
    Ok(Rule {
        id: row.get(0)?,
        drafting: row.get(1)?,
        definition: json_column(row, 2)?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
        version_ids: json_column(row, 5)?,
    })
}

pub(crate) fn load_rule(connection: &Connection, id: i64) -> rusqlite::Result<Option<Rule>> {
    connection
        .query_row(&format!("{SELECT_RULE} WHERE id = ?1"), [id], read_rule)
        .optional()
}

fn not_found(id: i64) -> ApiError {
    ApiError::NotFound(format!("Rule {id} does not exist."))
}

fn require_object(definition: &Value) -> Result<(), ApiError> {
    if definition.is_object() {
        Ok(())
    } else {
        Err(ApiError::BadRequest(
            "A rule definition must be a JSON object.".to_owned(),
        ))
    }
}

#[utoipa::path(
    get,
    path = "/api/rules",
    tag = "Rules",
    summary = "List rules",
    description = "Every rule, drafts included, oldest first.",
    responses((status = 200, body = [Rule]))
)]
pub async fn list(State(db): State<Db>) -> Result<Json<Vec<Rule>>, ApiError> {
    let rules = db
        .call(|connection| {
            let mut statement = connection.prepare(&format!("{SELECT_RULE} ORDER BY id"))?;
            statement
                .query_map([], read_rule)?
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .await?;
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
        (status = 201, body = Rule),
        (status = 400, description = "Definition is not an object", body = ErrorBody)
    )
)]
pub async fn create(
    State(db): State<Db>,
    Json(body): Json<RuleBody>,
) -> Result<(StatusCode, Json<Rule>), ApiError> {
    require_object(&body.definition)?;
    let rule = db
        .call(move |connection| {
            connection.execute(
                "INSERT INTO rules (definition) VALUES (?1)",
                [body.definition.to_string()],
            )?;
            let id = connection.last_insert_rowid();
            load_rule(connection, id).map(|rule| rule.expect("inserted rule should exist"))
        })
        .await?;
    Ok((StatusCode::CREATED, Json(rule)))
}

#[utoipa::path(
    get,
    path = "/api/rules/{id}",
    tag = "Rules",
    summary = "Get a rule",
    params(("id" = i64, Path, description = "Rule id")),
    responses((status = 200, body = Rule), (status = 404, body = ErrorBody))
)]
pub async fn fetch(State(db): State<Db>, Path(id): Path<i64>) -> Result<Json<Rule>, ApiError> {
    db.call(move |connection| load_rule(connection, id))
        .await?
        .map(Json)
        .ok_or_else(|| not_found(id))
}

#[utoipa::path(
    put,
    path = "/api/rules/{id}",
    tag = "Rules",
    summary = "Save a rule",
    description = "Replaces the rule's definition. A draft saves as-is; a rule that has been \
                   added into a version must stay valid. Versions keep their own snapshot, so \
                   this never changes what an existing version scans with.",
    params(("id" = i64, Path, description = "Rule id")),
    request_body = RuleBody,
    responses(
        (status = 200, body = Rule),
        (status = 404, body = ErrorBody),
        (status = 422, description = "The rule is not a draft and the definition is invalid", body = ErrorBody)
    )
)]
pub async fn update(
    State(db): State<Db>,
    Path(id): Path<i64>,
    Json(body): Json<RuleBody>,
) -> Result<Json<Rule>, ApiError> {
    require_object(&body.definition)?;
    let rule = db
        .call(move |connection| {
            let Some(existing) = load_rule(connection, id)? else {
                return Ok(Err(not_found(id)));
            };
            if !existing.drafting {
                let check = validation::check_rule(id, &body.definition);
                if !check.errors.is_empty() {
                    return Ok(Err(ApiError::Invalid {
                        message: "Fix the rule's errors before saving.".to_owned(),
                        errors: check.errors,
                    }));
                }
            }
            connection.execute(
                "UPDATE rules SET definition = ?1,
                     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?2",
                params![body.definition.to_string(), id],
            )?;
            load_rule(connection, id).map(|rule| Ok(rule.expect("updated rule should exist")))
        })
        .await??;
    Ok(Json(rule))
}

#[utoipa::path(
    delete,
    path = "/api/rules/{id}",
    tag = "Rules",
    summary = "Delete a rule",
    description = "Only a rule that is in no rule set version can be deleted. Its id is never reused.",
    params(("id" = i64, Path, description = "Rule id")),
    responses(
        (status = 204),
        (status = 404, body = ErrorBody),
        (status = 409, description = "The rule is in a rule set version", body = ErrorBody)
    )
)]
pub async fn remove(State(db): State<Db>, Path(id): Path<i64>) -> Result<StatusCode, ApiError> {
    db.call(move |connection| {
        let Some(existing) = load_rule(connection, id)? else {
            return Ok(Err(not_found(id)));
        };
        if !existing.version_ids.is_empty() {
            return Ok(Err(ApiError::Conflict(
                "This rule is in a rule set version, so it can't be deleted. Leave it out of \
                 the next version instead."
                    .to_owned(),
            )));
        }
        connection.execute("DELETE FROM rules WHERE id = ?1", [id])?;
        Ok(Ok(StatusCode::NO_CONTENT))
    })
    .await?
}

#[utoipa::path(
    post,
    path = "/api/rules/{id}/check",
    tag = "Rules",
    summary = "Check a rule definition",
    description = "Validates a definition for this rule without saving it, for inline form errors.",
    params(("id" = i64, Path, description = "Rule id")),
    request_body = RuleBody,
    responses((status = 200, body = RuleCheck), (status = 404, body = ErrorBody))
)]
pub async fn check(
    State(db): State<Db>,
    Path(id): Path<i64>,
    Json(body): Json<RuleBody>,
) -> Result<Json<RuleCheck>, ApiError> {
    let exists = db
        .call(move |connection| load_rule(connection, id).map(|rule| rule.is_some()))
        .await?;
    if !exists {
        return Err(not_found(id));
    }
    Ok(Json(validation::check_rule(id, &body.definition)))
}
