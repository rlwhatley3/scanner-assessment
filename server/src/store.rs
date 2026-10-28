//! Reads and writes rules, rule set versions, and scan sessions. Plain functions over a SQLite
//! connection, so any front end (the MCP server today, REST routes later) can share them. Each
//! enforces the storage rules from SUBMISSION.md: drafts are not validated, adding rules into a
//! version validates and snapshots them, and saved versions never change except for archiving.

use rusqlite::{Connection, OptionalExtension, Row};
use secrets_scanner_engine::{Rule, RuleCheck, RuleDefinition, check_rule_set};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;

const NOW: &str = "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')";

pub enum StoreError {
    NotFound(String),
    /// The request can't be carried out as asked, e.g. deleting a rule that is in a version.
    Invalid(String),
    /// The rules failed the engine's checks, so no version was saved.
    RulesInvalid(RuleCheck),
    Database(rusqlite::Error),
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        StoreError::Database(error)
    }
}

pub type StoreResult<T> = Result<T, StoreError>;

#[derive(Serialize, schemars::JsonSchema, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleRecord {
    pub id: i64,
    /// True until the rule is added into a rule set version. Drafts are not validated.
    pub drafting: bool,
    /// The rule's current definition. Saved versions keep their own snapshots.
    #[schema(value_type = Object)]
    pub definition: Value,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, schemars::JsonSchema, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetVersionSummary {
    pub id: i64,
    /// The version this one was based on, if any.
    pub parent_id: Option<i64>,
    /// Archived versions are hidden from the timeline and can't start new scan sessions.
    pub archived: bool,
    pub rule_count: i64,
    /// Scan sessions started on this version.
    pub scan_session_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, schemars::JsonSchema, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetVersionRecord {
    #[serde(flatten)]
    pub summary: RuleSetVersionSummary,
    pub rules: Vec<VersionRule>,
}

#[derive(Serialize, schemars::JsonSchema, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct VersionRule {
    pub rule_id: i64,
    /// The rule's definition as it was when added to this version. This is what scans use.
    #[schema(value_type = Object)]
    pub definition: Value,
}

#[derive(Serialize, schemars::JsonSchema, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScanSessionSummary {
    pub id: i64,
    pub rule_set_version_id: i64,
    /// When the session's latest scan ran. Null until its first scan.
    pub last_ran: Option<String>,
    pub scan_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, schemars::JsonSchema, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScanSessionRecord {
    #[serde(flatten)]
    pub summary: ScanSessionSummary,
    pub scans: Vec<ScanSummary>,
}

#[derive(Serialize, schemars::JsonSchema, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScanSummary {
    pub id: i64,
    /// True when there were more findings than the cap and the rest were not saved.
    pub truncated: bool,
    /// True when at least one rule could not run.
    pub partial: bool,
    /// Matches only; rule errors are counted by `partial`.
    pub match_count: i64,
    pub created_at: String,
}

/// Parses a definition from the rule form's JSON. Field values aren't checked here (drafts are
/// allowed to be incomplete), but unknown or mistyped fields are rejected.
pub fn parse_definition(definition: Value) -> StoreResult<RuleDefinition> {
    serde_json::from_value(definition)
        .map_err(|error| StoreError::Invalid(format!("Invalid rule definition: {error}")))
}

fn to_json(definition: &RuleDefinition) -> String {
    serde_json::to_string(definition).expect("a rule definition always serializes")
}

fn json_column(row: &Row, index: usize) -> rusqlite::Result<Value> {
    let text: String = row.get(index)?;
    serde_json::from_str(&text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

// Rules

const RULE_COLUMNS: &str = "id, drafting, definition, created_at, updated_at";

fn rule_record(row: &Row) -> rusqlite::Result<RuleRecord> {
    Ok(RuleRecord {
        id: row.get(0)?,
        drafting: row.get(1)?,
        definition: json_column(row, 2)?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
    })
}

pub fn list_rules(connection: &Connection, drafting: Option<bool>) -> StoreResult<Vec<RuleRecord>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {RULE_COLUMNS} FROM rules WHERE ?1 IS NULL OR drafting = ?1 ORDER BY id"
    ))?;
    let rules = statement
        .query_map([drafting], rule_record)?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rules)
}

pub fn get_rule(connection: &Connection, rule_id: i64) -> StoreResult<RuleRecord> {
    connection
        .query_row(
            &format!("SELECT {RULE_COLUMNS} FROM rules WHERE id = ?1"),
            [rule_id],
            rule_record,
        )
        .optional()?
        .ok_or_else(|| StoreError::NotFound(format!("Rule {rule_id} not found.")))
}

/// Ids of the rule set versions that hold a snapshot of this rule.
pub fn rule_version_ids(connection: &Connection, rule_id: i64) -> StoreResult<Vec<i64>> {
    let mut statement = connection.prepare(
        "SELECT rule_set_version_id FROM rule_set_version_rules
         WHERE rule_id = ?1 ORDER BY rule_set_version_id",
    )?;
    let ids = statement
        .query_map([rule_id], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(ids)
}

/// Stores a new draft rule. Drafts are not validated until they are added into a version.
pub fn create_rule(
    connection: &Connection,
    definition: &RuleDefinition,
) -> StoreResult<RuleRecord> {
    connection.execute(
        "INSERT INTO rules (definition) VALUES (?1)",
        [to_json(definition)],
    )?;
    get_rule(connection, connection.last_insert_rowid())
}

/// Replaces a rule's definition. A draft saves as-is; a rule that has been added into a version
/// must pass the engine's checks, or nothing is saved and the errors come back. Versions that
/// already hold the rule keep their snapshots.
pub fn update_rule(
    connection: &Connection,
    rule_id: i64,
    definition: &RuleDefinition,
) -> StoreResult<RuleRecord> {
    if !get_rule(connection, rule_id)?.drafting {
        let check = check_rule_set(&[Rule {
            id: rule_id,
            definition: definition.clone(),
        }]);
        if !check.is_valid() {
            return Err(StoreError::RulesInvalid(check));
        }
    }
    connection.execute(
        &format!("UPDATE rules SET definition = ?1, updated_at = {NOW} WHERE id = ?2"),
        rusqlite::params![to_json(definition), rule_id],
    )?;
    get_rule(connection, rule_id)
}

/// Deletes a draft. A rule that has been added into a version is part of that version's history,
/// so it can only be left out of later versions or disabled, not deleted.
pub fn delete_draft_rule(connection: &Connection, rule_id: i64) -> StoreResult<()> {
    let rule = get_rule(connection, rule_id)?;
    if !rule.drafting || !rule_version_ids(connection, rule_id)?.is_empty() {
        return Err(StoreError::Invalid(format!(
            "Rule {rule_id} is in a rule set version, so it can't be deleted. Leave it out of \
             the next version, or disable it, instead."
        )));
    }
    connection.execute("DELETE FROM rules WHERE id = ?1", [rule_id])?;
    Ok(())
}

/// Loads rules by id in the engine's shape, for checking. Fails on the first unknown id.
fn load_rules(connection: &Connection, rule_ids: &[i64]) -> StoreResult<Vec<Rule>> {
    rule_ids
        .iter()
        .map(|&id| {
            let record = get_rule(connection, id)?;
            let definition = serde_json::from_value(record.definition).map_err(|error| {
                StoreError::Invalid(format!("Rule {id} has an unreadable definition: {error}"))
            })?;
            Ok(Rule { id, definition })
        })
        .collect()
}

fn unique_rule_ids(rule_ids: &[i64]) -> StoreResult<()> {
    let mut seen = HashSet::new();
    match rule_ids.iter().find(|&&id| !seen.insert(id)) {
        Some(id) => Err(StoreError::Invalid(format!(
            "Rule {id} is listed more than once."
        ))),
        None => Ok(()),
    }
}

/// Runs the engine's checks on these rules as one set, the same checks saving a version runs.
pub fn check_rules(connection: &Connection, rule_ids: &[i64]) -> StoreResult<RuleCheck> {
    unique_rule_ids(rule_ids)?;
    Ok(check_rule_set(&load_rules(connection, rule_ids)?))
}

// Rule set versions

const VERSION_COLUMNS: &str = "v.id, v.parent_id, v.archived, v.created_at, v.updated_at,
    (SELECT COUNT(*) FROM rule_set_version_rules r WHERE r.rule_set_version_id = v.id),
    (SELECT COUNT(*) FROM scan_sessions s WHERE s.rule_set_version_id = v.id)";

fn version_summary(row: &Row) -> rusqlite::Result<RuleSetVersionSummary> {
    Ok(RuleSetVersionSummary {
        id: row.get(0)?,
        parent_id: row.get(1)?,
        archived: row.get(2)?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
        rule_count: row.get(5)?,
        scan_session_count: row.get(6)?,
    })
}

/// Versions oldest first, as the timeline shows them.
pub fn list_versions(
    connection: &Connection,
    include_archived: bool,
) -> StoreResult<Vec<RuleSetVersionSummary>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {VERSION_COLUMNS} FROM rule_set_versions v
         WHERE ?1 OR v.archived = 0 ORDER BY v.id"
    ))?;
    let versions = statement
        .query_map([include_archived], version_summary)?
        .collect::<rusqlite::Result<_>>()?;
    Ok(versions)
}

fn get_version_summary(
    connection: &Connection,
    version_id: i64,
) -> StoreResult<RuleSetVersionSummary> {
    connection
        .query_row(
            &format!("SELECT {VERSION_COLUMNS} FROM rule_set_versions v WHERE v.id = ?1"),
            [version_id],
            version_summary,
        )
        .optional()?
        .ok_or_else(|| StoreError::NotFound(format!("Rule set version {version_id} not found.")))
}

pub fn get_version(connection: &Connection, version_id: i64) -> StoreResult<RuleSetVersionRecord> {
    let summary = get_version_summary(connection, version_id)?;
    let mut statement = connection.prepare(
        "SELECT rule_id, definition FROM rule_set_version_rules
         WHERE rule_set_version_id = ?1 ORDER BY rule_id",
    )?;
    let rules = statement
        .query_map([version_id], |row| {
            Ok(VersionRule {
                rule_id: row.get(0)?,
                definition: json_column(row, 1)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(RuleSetVersionRecord { summary, rules })
}

/// Saves a new version holding exactly these rules, each snapshotted from its current
/// definition. The rules are checked as a set first; if any check fails, nothing is saved and
/// the errors come back. Rules that were drafts stop being drafts. Returns the new version and
/// any warnings from the check.
pub fn create_version(
    connection: &mut Connection,
    parent_id: Option<i64>,
    rule_ids: &[i64],
) -> StoreResult<(RuleSetVersionRecord, RuleCheck)> {
    if rule_ids.is_empty() {
        return Err(StoreError::Invalid(
            "A rule set version needs at least one rule.".to_string(),
        ));
    }
    unique_rule_ids(rule_ids)?;
    let transaction = connection.transaction()?;
    if let Some(parent_id) = parent_id {
        get_version_summary(&transaction, parent_id)?;
    }
    let rules = load_rules(&transaction, rule_ids)?;
    let check = check_rule_set(&rules);
    if !check.is_valid() {
        return Err(StoreError::RulesInvalid(check));
    }

    transaction.execute(
        "INSERT INTO rule_set_versions (parent_id) VALUES (?1)",
        [parent_id],
    )?;
    let version_id = transaction.last_insert_rowid();
    for rule in &rules {
        transaction.execute(
            "INSERT INTO rule_set_version_rules (rule_set_version_id, rule_id, definition)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![version_id, rule.id, to_json(&rule.definition)],
        )?;
        transaction.execute(
            &format!(
                "UPDATE rules SET drafting = 0, updated_at = {NOW} WHERE id = ?1 AND drafting = 1"
            ),
            [rule.id],
        )?;
    }
    let version = get_version(&transaction, version_id)?;
    transaction.commit()?;
    Ok((version, check))
}

/// Archives or restores a version. This is the only change a saved version allows.
pub fn set_version_archived(
    connection: &Connection,
    version_id: i64,
    archived: bool,
) -> StoreResult<RuleSetVersionSummary> {
    let updated = connection.execute(
        &format!("UPDATE rule_set_versions SET archived = ?1, updated_at = {NOW} WHERE id = ?2"),
        rusqlite::params![archived, version_id],
    )?;
    if updated == 0 {
        return Err(StoreError::NotFound(format!(
            "Rule set version {version_id} not found."
        )));
    }
    get_version_summary(connection, version_id)
}

// Scan sessions

const SESSION_COLUMNS: &str = "s.id, s.rule_set_version_id, s.last_ran, s.created_at, s.updated_at,
    (SELECT COUNT(*) FROM scans c WHERE c.scan_session_id = s.id)";

fn session_summary(row: &Row) -> rusqlite::Result<ScanSessionSummary> {
    Ok(ScanSessionSummary {
        id: row.get(0)?,
        rule_set_version_id: row.get(1)?,
        last_ran: row.get(2)?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
        scan_count: row.get(5)?,
    })
}

/// Sessions newest first.
pub fn list_sessions(connection: &Connection) -> StoreResult<Vec<ScanSessionSummary>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {SESSION_COLUMNS} FROM scan_sessions s ORDER BY s.id DESC"
    ))?;
    let sessions = statement
        .query_map([], session_summary)?
        .collect::<rusqlite::Result<_>>()?;
    Ok(sessions)
}

fn get_session_summary(
    connection: &Connection,
    session_id: i64,
) -> StoreResult<ScanSessionSummary> {
    connection
        .query_row(
            &format!("SELECT {SESSION_COLUMNS} FROM scan_sessions s WHERE s.id = ?1"),
            [session_id],
            session_summary,
        )
        .optional()?
        .ok_or_else(|| StoreError::NotFound(format!("Scan session {session_id} not found.")))
}

/// A session with its scans, oldest first.
pub fn get_session(connection: &Connection, session_id: i64) -> StoreResult<ScanSessionRecord> {
    let summary = get_session_summary(connection, session_id)?;
    let mut statement = connection.prepare(
        "SELECT c.id, c.truncated, c.created_at,
             EXISTS (SELECT 1 FROM findings f WHERE f.scan_id = c.id AND f.kind = 'rule_error'),
             (SELECT COUNT(*) FROM findings f WHERE f.scan_id = c.id AND f.kind = 'match')
         FROM scans c WHERE c.scan_session_id = ?1 ORDER BY c.id",
    )?;
    let scans = statement
        .query_map([session_id], |row| {
            Ok(ScanSummary {
                id: row.get(0)?,
                truncated: row.get(1)?,
                created_at: row.get(2)?,
                partial: row.get(3)?,
                match_count: row.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(ScanSessionRecord { summary, scans })
}

/// Starts a session on a version. Archived versions can't start new sessions.
pub fn create_session(
    connection: &Connection,
    rule_set_version_id: i64,
) -> StoreResult<ScanSessionSummary> {
    let version = get_version_summary(connection, rule_set_version_id)?;
    if version.archived {
        return Err(StoreError::Invalid(format!(
            "Rule set version {rule_set_version_id} is archived. Restore it first, or pick \
             another version."
        )));
    }
    connection.execute(
        "INSERT INTO scan_sessions (rule_set_version_id) VALUES (?1)",
        [rule_set_version_id],
    )?;
    get_session_summary(connection, connection.last_insert_rowid())
}
