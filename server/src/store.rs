//! Reads and writes rules, rule sets and their versions, scan sessions, and suppressions. Plain functions over a SQLite
//! connection, so any front end (the MCP server today, REST routes later) can share them. Each
//! enforces the storage rules from SUBMISSION.md: drafts are not validated, adding rules into a
//! version validates and snapshots them, and saved versions never change except for archiving.

use rusqlite::{Connection, OptionalExtension, Row};
use secrets_scanner_engine::{Rule, RuleCheck, RuleDefinition, check_rule_set};
use serde::{Deserialize, Serialize};
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

/// The longest rule set name allowed.
pub const MAX_RULE_SET_NAME: usize = 80;

#[derive(Serialize, schemars::JsonSchema, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetSummary {
    pub id: i64,
    /// Unique among rule sets, ignoring case.
    pub name: String,
    pub description: String,
    /// Archived sets are hidden from the list, can't get new versions, and can't start new
    /// scan sessions.
    pub archived: bool,
    pub version_count: i64,
    /// The newest version that isn't archived, if any. New versions start from it.
    pub latest_version_id: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, schemars::JsonSchema, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetRecord {
    #[serde(flatten)]
    pub summary: RuleSetSummary,
    /// Every version in the set, archived ones included, oldest first.
    pub versions: Vec<RuleSetVersionSummary>,
}

#[derive(Serialize, schemars::JsonSchema, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetVersionSummary {
    pub id: i64,
    pub rule_set_id: i64,
    pub rule_set_name: String,
    /// The version's place in its rule set: 1 for the first, and so on.
    pub number: i64,
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
    pub rule_set_id: i64,
    pub rule_set_name: String,
    /// The version's number within its rule set.
    pub version_number: i64,
    /// When the session's latest scan ran. Null until its first scan.
    pub last_ran: Option<String>,
    pub scan_count: i64,
    /// Suppressions that apply to the session's next scan: not removed and not expired.
    pub active_suppression_count: i64,
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
    /// `completed` once its findings are saved. `running` while the engine runs, and
    /// `interrupted` when the scan ended before its findings were saved, so they are missing.
    pub status: String,
    /// True when there were more findings than the cap and the rest were not saved.
    pub truncated: bool,
    /// True when at least one rule could not run.
    pub partial: bool,
    /// Matches only; rule errors are counted by `partial`.
    pub match_count: i64,
    /// Matches left out because an active suppression covered their value. They aren't saved,
    /// so they aren't in `match_count`.
    pub suppressed_count: i64,
    /// Rules that matched so much of the text that they slowed the scan.
    pub slow_rules: Vec<SlowRule>,
    pub created_at: String,
}

/// What one rule cost a scan, as saved with it.
#[derive(Clone, Serialize, Deserialize, schemars::JsonSchema, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleTimingRecord {
    pub rule_id: i64,
    pub rule_name: String,
    /// Time spent on the rule's own work: its search, its model, and its value classifier.
    pub micros: u64,
    /// Values it found, before overlapping findings were merged and the findings were capped.
    pub matches: usize,
    /// Whether it matched so much of the text that it slowed the scan: at least 1,000 times, and
    /// at least once every 16 characters. Never true for a model rule.
    pub floods: bool,
}

/// A rule that matched so much of a scan's text that it slowed the scan.
#[derive(Serialize, schemars::JsonSchema, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SlowRule {
    pub rule_id: i64,
    pub rule_name: String,
    pub matches: usize,
    pub micros: u64,
    /// What happened and what to change, in plain words.
    pub message: String,
}

/// The rules in `timings` that flooded a text of `text_bytes` bytes.
pub fn slow_rules(timings: &[RuleTimingRecord], text_bytes: Option<i64>) -> Vec<SlowRule> {
    timings
        .iter()
        .filter(|timing| timing.floods)
        .map(|timing| {
            let how_often = text_bytes
                .and_then(|bytes| usize::try_from(bytes).ok())
                .map(|bytes| {
                    format!(
                        ", about once every {} characters,",
                        (bytes / timing.matches.max(1)).max(1)
                    )
                })
                .unwrap_or_default();
            SlowRule {
                rule_id: timing.rule_id,
                rule_name: timing.rule_name.clone(),
                matches: timing.matches,
                micros: timing.micros,
                message: format!(
                    "{} matched {} times in this text{how_often} and spent {:.1} ms on it. A \
                     rule that matches almost everything slows every scan: each match is \
                     scored, checked against other rules' matches, and counted toward the cap of \
                     200 findings. Narrow its pattern to the text around the secret, such as a \
                     prefix or a key name.",
                    timing.rule_name,
                    timing.matches,
                    timing.micros as f64 / 1000.0
                ),
            }
        })
        .collect()
}

/// Reads a scan's saved rule timings. Unreadable ones read as none: they only explain a scan.
pub fn parse_rule_timings(json: &str) -> Vec<RuleTimingRecord> {
    serde_json::from_str(json).unwrap_or_default()
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

// Rule sets

const RULE_SET_COLUMNS: &str =
    "t.id, t.name, t.description, t.archived, t.created_at, t.updated_at,
    (SELECT COUNT(*) FROM rule_set_versions v WHERE v.rule_set_id = t.id),
    (SELECT MAX(v.id) FROM rule_set_versions v WHERE v.rule_set_id = t.id AND v.archived = 0)";

fn rule_set_summary(row: &Row) -> rusqlite::Result<RuleSetSummary> {
    Ok(RuleSetSummary {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        archived: row.get(3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
        version_count: row.get(6)?,
        latest_version_id: row.get(7)?,
    })
}

/// Rule sets in creation order.
pub fn list_rule_sets(
    connection: &Connection,
    include_archived: bool,
) -> StoreResult<Vec<RuleSetSummary>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {RULE_SET_COLUMNS} FROM rule_sets t WHERE ?1 OR t.archived = 0 ORDER BY t.id"
    ))?;
    let rule_sets = statement
        .query_map([include_archived], rule_set_summary)?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rule_sets)
}

fn get_rule_set_summary(connection: &Connection, rule_set_id: i64) -> StoreResult<RuleSetSummary> {
    connection
        .query_row(
            &format!("SELECT {RULE_SET_COLUMNS} FROM rule_sets t WHERE t.id = ?1"),
            [rule_set_id],
            rule_set_summary,
        )
        .optional()?
        .ok_or_else(|| StoreError::NotFound(format!("Rule set {rule_set_id} not found.")))
}

/// A rule set with every one of its versions.
pub fn get_rule_set(connection: &Connection, rule_set_id: i64) -> StoreResult<RuleSetRecord> {
    let summary = get_rule_set_summary(connection, rule_set_id)?;
    let versions = list_versions(connection, Some(rule_set_id), true)?;
    Ok(RuleSetRecord { summary, versions })
}

/// A trimmed name that is present, not too long, and not used by another set.
fn check_rule_set_name(
    connection: &Connection,
    name: &str,
    except_id: Option<i64>,
) -> StoreResult<String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(StoreError::Invalid("A rule set needs a name.".to_string()));
    }
    if name.chars().count() > MAX_RULE_SET_NAME {
        return Err(StoreError::Invalid(format!(
            "A rule set name can be at most {MAX_RULE_SET_NAME} characters."
        )));
    }
    let taken: bool = connection.query_row(
        "SELECT EXISTS (SELECT 1 FROM rule_sets
             WHERE lower(trim(name)) = lower(?1) AND id IS NOT ?2)",
        rusqlite::params![name, except_id],
        |row| row.get(0),
    )?;
    if taken {
        return Err(StoreError::Invalid(format!(
            "A rule set named \"{name}\" already exists. Pick another name."
        )));
    }
    Ok(name.to_string())
}

/// Creates a named rule set. With `from_version_id`, its first version is an exact copy of that
/// version (from any set), recorded as its parent; otherwise the set starts with no versions.
pub fn create_rule_set(
    connection: &mut Connection,
    name: &str,
    description: &str,
    from_version_id: Option<i64>,
) -> StoreResult<RuleSetRecord> {
    let transaction = connection.transaction()?;
    let name = check_rule_set_name(&transaction, name, None)?;
    transaction.execute(
        "INSERT INTO rule_sets (name, description) VALUES (?1, ?2)",
        rusqlite::params![name, description.trim()],
    )?;
    let rule_set_id = transaction.last_insert_rowid();
    if let Some(source_id) = from_version_id {
        // Saved versions are valid and never change, so the copy needs no new checks.
        get_version_summary(&transaction, source_id)?;
        transaction.execute(
            "INSERT INTO rule_set_versions (rule_set_id, parent_id) VALUES (?1, ?2)",
            rusqlite::params![rule_set_id, source_id],
        )?;
        transaction.execute(
            "INSERT INTO rule_set_version_rules (rule_set_version_id, rule_id, definition)
             SELECT ?1, rule_id, definition FROM rule_set_version_rules
             WHERE rule_set_version_id = ?2",
            rusqlite::params![transaction.last_insert_rowid(), source_id],
        )?;
    }
    let rule_set = get_rule_set(&transaction, rule_set_id)?;
    transaction.commit()?;
    Ok(rule_set)
}

/// Renames, redescribes, archives, or restores a rule set. Its versions never change.
pub fn update_rule_set(
    connection: &Connection,
    rule_set_id: i64,
    name: Option<&str>,
    description: Option<&str>,
    archived: Option<bool>,
) -> StoreResult<RuleSetSummary> {
    get_rule_set_summary(connection, rule_set_id)?;
    let name = name
        .map(|name| check_rule_set_name(connection, name, Some(rule_set_id)))
        .transpose()?;
    connection.execute(
        &format!(
            "UPDATE rule_sets SET name = COALESCE(?1, name),
                 description = COALESCE(?2, description),
                 archived = COALESCE(?3, archived),
                 updated_at = {NOW}
             WHERE id = ?4"
        ),
        rusqlite::params![name, description.map(str::trim), archived, rule_set_id],
    )?;
    get_rule_set_summary(connection, rule_set_id)
}

// Rule set versions

/// A version's number within its rule set: how many versions of the set exist up to it.
const VERSION_COLUMNS: &str = "v.id, v.parent_id, v.archived, v.created_at, v.updated_at,
    (SELECT COUNT(*) FROM rule_set_version_rules r WHERE r.rule_set_version_id = v.id),
    (SELECT COUNT(*) FROM scan_sessions s WHERE s.rule_set_version_id = v.id),
    v.rule_set_id,
    (SELECT name FROM rule_sets t WHERE t.id = v.rule_set_id),
    (SELECT COUNT(*) FROM rule_set_versions n
        WHERE n.rule_set_id = v.rule_set_id AND n.id <= v.id)";

fn version_summary(row: &Row) -> rusqlite::Result<RuleSetVersionSummary> {
    Ok(RuleSetVersionSummary {
        id: row.get(0)?,
        parent_id: row.get(1)?,
        archived: row.get(2)?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
        rule_count: row.get(5)?,
        scan_session_count: row.get(6)?,
        rule_set_id: row.get(7)?,
        rule_set_name: row.get(8)?,
        number: row.get(9)?,
    })
}

/// Versions oldest first, as the timeline shows them: every rule set's, or one set's.
pub fn list_versions(
    connection: &Connection,
    rule_set_id: Option<i64>,
    include_archived: bool,
) -> StoreResult<Vec<RuleSetVersionSummary>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {VERSION_COLUMNS} FROM rule_set_versions v
         WHERE (?1 OR v.archived = 0) AND (?2 IS NULL OR v.rule_set_id = ?2)
         ORDER BY v.id"
    ))?;
    let versions = statement
        .query_map(
            rusqlite::params![include_archived, rule_set_id],
            version_summary,
        )?
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

/// Saves a new version of a rule set holding exactly these rules, each snapshotted from its
/// current definition. The rules are checked as a set first; if any check fails, nothing is
/// saved and the errors come back. Rules that were drafts stop being drafts. The parent, if
/// given, must be a version of the same set. Returns the new version and any warnings.
pub fn create_version(
    connection: &mut Connection,
    rule_set_id: i64,
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
    let rule_set = get_rule_set_summary(&transaction, rule_set_id)?;
    if rule_set.archived {
        return Err(StoreError::Invalid(format!(
            "Rule set \"{}\" is archived. Restore it before adding versions.",
            rule_set.name
        )));
    }
    if let Some(parent_id) = parent_id
        && get_version_summary(&transaction, parent_id)?.rule_set_id != rule_set_id
    {
        return Err(StoreError::Invalid(format!(
            "Version {parent_id} belongs to another rule set. To start a set from it, create a \
             new rule set from that version instead."
        )));
    }
    let rules = load_rules(&transaction, rule_ids)?;
    let check = check_rule_set(&rules);
    if !check.is_valid() {
        return Err(StoreError::RulesInvalid(check));
    }

    transaction.execute(
        "INSERT INTO rule_set_versions (rule_set_id, parent_id) VALUES (?1, ?2)",
        rusqlite::params![rule_set_id, parent_id],
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
    (SELECT COUNT(*) FROM scans c WHERE c.scan_session_id = s.id),
    v.rule_set_id,
    (SELECT name FROM rule_sets t WHERE t.id = v.rule_set_id),
    (SELECT COUNT(*) FROM rule_set_versions n
        WHERE n.rule_set_id = v.rule_set_id AND n.id <= v.id),
    (SELECT COUNT(*) FROM suppressions p
        WHERE p.scan_session_id = s.id AND p.removed_at IS NULL
            AND p.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))";

/// Sessions joined to their version, for the rule set columns above.
const SESSION_FROM: &str =
    "scan_sessions s JOIN rule_set_versions v ON v.id = s.rule_set_version_id";

fn session_summary(row: &Row) -> rusqlite::Result<ScanSessionSummary> {
    Ok(ScanSessionSummary {
        id: row.get(0)?,
        rule_set_version_id: row.get(1)?,
        last_ran: row.get(2)?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
        scan_count: row.get(5)?,
        rule_set_id: row.get(6)?,
        rule_set_name: row.get(7)?,
        version_number: row.get(8)?,
        active_suppression_count: row.get(9)?,
    })
}

/// Sessions newest first.
pub fn list_sessions(connection: &Connection) -> StoreResult<Vec<ScanSessionSummary>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {SESSION_COLUMNS} FROM {SESSION_FROM} ORDER BY s.id DESC"
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
            &format!("SELECT {SESSION_COLUMNS} FROM {SESSION_FROM} WHERE s.id = ?1"),
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
             (SELECT COUNT(*) FROM findings f WHERE f.scan_id = c.id AND f.kind = 'match'),
             c.suppressed_count, c.status, c.rule_timings, c.text_bytes
         FROM scans c WHERE c.scan_session_id = ?1 ORDER BY c.id",
    )?;
    let scans = statement
        .query_map([session_id], |row| {
            let timings = parse_rule_timings(&row.get::<_, String>(7)?);
            Ok(ScanSummary {
                id: row.get(0)?,
                truncated: row.get(1)?,
                created_at: row.get(2)?,
                partial: row.get(3)?,
                match_count: row.get(4)?,
                suppressed_count: row.get(5)?,
                status: row.get(6)?,
                slow_rules: slow_rules(&timings, row.get(8)?),
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(ScanSessionRecord { summary, scans })
}

/// Marks scans that are still running as interrupted: one scan, or with `None`, every scan. A
/// scan's findings are saved when its request finishes, so a scan whose request ended first never
/// gets them. Returns how many scans were marked.
pub fn interrupt_running_scans(
    connection: &Connection,
    scan_id: Option<i64>,
) -> rusqlite::Result<usize> {
    connection.execute(
        "UPDATE scans SET status = 'interrupted',
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
         WHERE status = 'running' AND (?1 IS NULL OR id = ?1)",
        [scan_id],
    )
}

/// Starts a session on a version. Archived versions, and versions of an archived rule set,
/// can't start new sessions.
pub fn create_session(
    connection: &Connection,
    rule_set_version_id: i64,
) -> StoreResult<ScanSessionSummary> {
    let version = get_version_summary(connection, rule_set_version_id)?;
    let rule_set = get_rule_set_summary(connection, version.rule_set_id)?;
    if rule_set.archived {
        return Err(StoreError::Invalid(format!(
            "Rule set \"{}\" is archived. Restore it first, or pick another rule set.",
            rule_set.name
        )));
    }
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

// Suppressions

/// The longest suppression reason allowed.
pub const MAX_SUPPRESSION_REASON: usize = 500;

/// How far ahead a suppression can expire. A suppression is for a known example, not a standing
/// exception, so it has to be renewed rather than forgotten.
pub const MAX_SUPPRESSION_DAYS: i64 = 365;

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug, schemars::JsonSchema, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionStatus {
    /// The session's scans don't report its value.
    Active,
    /// Past its expiry, so its value is reported again.
    Expired,
    /// Removed by a user, so its value is reported again.
    Removed,
}

/// A suppression, without its fingerprint: the fingerprint only matters to the scan path, so it
/// never leaves the server.
#[derive(Serialize, schemars::JsonSchema, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SuppressionRecord {
    pub id: i64,
    pub scan_session_id: i64,
    /// The rule whose finding it covers. It covers one value found by this rule, never the rule
    /// as a whole.
    pub rule_id: i64,
    pub rule_name: String,
    /// The finding it was made from, and that finding's scan.
    pub finding_id: i64,
    pub scan_id: i64,
    pub reason: String,
    pub expires_at: String,
    pub removed_at: Option<String>,
    pub status: SuppressionStatus,
    pub created_at: String,
    pub updated_at: String,
}

const SUPPRESSION_COLUMNS: &str = "p.id, p.scan_session_id, p.rule_id,
    COALESCE(json_extract(f.violation, '$.ruleName'), 'Rule ' || p.rule_id),
    p.finding_id, f.scan_id, p.reason, p.expires_at, p.removed_at,
    CASE WHEN p.removed_at IS NOT NULL THEN 'removed'
        WHEN p.expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now') THEN 'expired'
        ELSE 'active' END,
    p.created_at, p.updated_at";

const SUPPRESSION_FROM: &str = "suppressions p JOIN findings f ON f.id = p.finding_id";

fn suppression_record(row: &Row) -> rusqlite::Result<SuppressionRecord> {
    let status: String = row.get(9)?;
    Ok(SuppressionRecord {
        id: row.get(0)?,
        scan_session_id: row.get(1)?,
        rule_id: row.get(2)?,
        rule_name: row.get(3)?,
        finding_id: row.get(4)?,
        scan_id: row.get(5)?,
        reason: row.get(6)?,
        expires_at: row.get(7)?,
        removed_at: row.get(8)?,
        status: match status.as_str() {
            "removed" => SuppressionStatus::Removed,
            "expired" => SuppressionStatus::Expired,
            _ => SuppressionStatus::Active,
        },
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

/// A session's suppressions, newest first, removed and expired ones included.
pub fn list_suppressions(
    connection: &Connection,
    session_id: i64,
) -> StoreResult<Vec<SuppressionRecord>> {
    get_session_summary(connection, session_id)?;
    let mut statement = connection.prepare(&format!(
        "SELECT {SUPPRESSION_COLUMNS} FROM {SUPPRESSION_FROM}
         WHERE p.scan_session_id = ?1 ORDER BY p.id DESC"
    ))?;
    let suppressions = statement
        .query_map([session_id], suppression_record)?
        .collect::<rusqlite::Result<_>>()?;
    Ok(suppressions)
}

fn get_suppression(
    connection: &Connection,
    session_id: i64,
    suppression_id: i64,
) -> StoreResult<SuppressionRecord> {
    connection
        .query_row(
            &format!(
                "SELECT {SUPPRESSION_COLUMNS} FROM {SUPPRESSION_FROM}
                 WHERE p.id = ?1 AND p.scan_session_id = ?2"
            ),
            [suppression_id, session_id],
            suppression_record,
        )
        .optional()?
        .ok_or_else(|| {
            StoreError::NotFound(format!(
                "Suppression {suppression_id} not found in scan session {session_id}."
            ))
        })
}

/// `expires_at` in the stored format, if it is a date or date-time in the allowed window: after
/// now and at most `MAX_SUPPRESSION_DAYS` ahead. A date alone means midnight UTC at its start.
fn check_expiry(connection: &Connection, expires_at: &str) -> StoreResult<String> {
    let expires_at = expires_at.trim();
    let looks_like_a_date = expires_at.len() >= 10
        && expires_at.as_bytes()[..4].iter().all(u8::is_ascii_digit)
        && expires_at.as_bytes()[4] == b'-';
    let (normalized, in_future, in_window): (Option<String>, bool, bool) = connection.query_row(
        &format!(
            "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?1),
                 strftime('%Y-%m-%dT%H:%M:%fZ', ?1) > {NOW},
                 strftime('%Y-%m-%dT%H:%M:%fZ', ?1) <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2)"
        ),
        rusqlite::params![expires_at, format!("+{MAX_SUPPRESSION_DAYS} days")],
        |row| {
            Ok((
                row.get(0)?,
                row.get::<_, Option<bool>>(1)?.unwrap_or(false),
                row.get::<_, Option<bool>>(2)?.unwrap_or(false),
            ))
        },
    )?;
    let Some(normalized) = normalized.filter(|_| looks_like_a_date) else {
        return Err(StoreError::Invalid(
            "A suppression needs an expiry: an ISO 8601 date or date-time, such as \
             2026-12-31T00:00:00Z."
                .to_string(),
        ));
    };
    if !in_future {
        return Err(StoreError::Invalid(
            "A suppression's expiry must be in the future.".to_string(),
        ));
    }
    if !in_window {
        return Err(StoreError::Invalid(format!(
            "A suppression can expire at most {MAX_SUPPRESSION_DAYS} days from now."
        )));
    }
    Ok(normalized)
}

/// Suppresses the value of one of the session's findings: later scans in this session don't
/// report a match when the same rule finds a value with the same fingerprint, until the
/// suppression expires or is removed. Scans already saved keep their findings, the one it was
/// made from included.
pub fn create_suppression(
    connection: &mut Connection,
    session_id: i64,
    finding_id: i64,
    reason: &str,
    expires_at: &str,
) -> StoreResult<SuppressionRecord> {
    let transaction = connection.transaction()?;
    get_session_summary(&transaction, session_id)?;
    // The finding is named in the request, so one outside this session makes it invalid.
    let (rule_id, fingerprint) = transaction
        .query_row(
            "SELECT f.rule_id, f.fingerprint FROM findings f
             JOIN scans c ON c.id = f.scan_id
             WHERE f.id = ?1 AND c.scan_session_id = ?2 AND f.kind = 'match'",
            [finding_id, session_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?)),
        )
        .optional()?
        .ok_or_else(|| {
            StoreError::Invalid(format!(
                "Finding {finding_id} is not a match in scan session {session_id}. Only matches \
                 can be suppressed, and only in the session they were found in."
            ))
        })?;
    let Some(fingerprint) = fingerprint else {
        return Err(StoreError::Invalid(format!(
            "Finding {finding_id} was saved before suppressions existed, so it has no \
             fingerprint. Scan the text again and suppress the new finding."
        )));
    };
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(StoreError::Invalid(
            "A suppression needs a reason: why this value is safe to leave.".to_string(),
        ));
    }
    if reason.chars().count() > MAX_SUPPRESSION_REASON {
        return Err(StoreError::Invalid(format!(
            "A suppression reason can be at most {MAX_SUPPRESSION_REASON} characters."
        )));
    }
    let expires_at = check_expiry(&transaction, expires_at)?;
    if let Some(existing) = active_suppressions(&transaction, session_id)?
        .into_iter()
        .find(|active| active.rule_id == rule_id && active.fingerprint == fingerprint)
    {
        return Err(StoreError::Invalid(format!(
            "This value is already suppressed for this rule by suppression {}. Remove it first \
             to change the reason or expiry.",
            existing.id
        )));
    }

    transaction.execute(
        "INSERT INTO suppressions
             (scan_session_id, rule_id, fingerprint, finding_id, reason, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            session_id,
            rule_id,
            fingerprint,
            finding_id,
            reason,
            expires_at
        ],
    )?;
    let suppression_id = transaction.last_insert_rowid();
    let suppression = get_suppression(&transaction, session_id, suppression_id)?;
    transaction.commit()?;
    Ok(suppression)
}

/// Removes a suppression: later scans in the session report its value again. The row is kept as
/// a record of what was suppressed, why, and until when. Removing it twice is harmless.
pub fn remove_suppression(
    connection: &Connection,
    session_id: i64,
    suppression_id: i64,
) -> StoreResult<SuppressionRecord> {
    get_suppression(connection, session_id, suppression_id)?;
    connection.execute(
        &format!(
            "UPDATE suppressions SET removed_at = {NOW}, updated_at = {NOW}
             WHERE id = ?1 AND removed_at IS NULL"
        ),
        [suppression_id],
    )?;
    get_suppression(connection, session_id, suppression_id)
}

/// A suppression a scan applies, with the rule and fingerprint it covers.
pub struct ActiveSuppression {
    pub id: i64,
    pub rule_id: i64,
    pub fingerprint: String,
}

/// The session's suppressions that apply right now: not removed and not expired, oldest first.
pub fn active_suppressions(
    connection: &Connection,
    session_id: i64,
) -> rusqlite::Result<Vec<ActiveSuppression>> {
    let mut statement = connection.prepare(&format!(
        "SELECT id, rule_id, fingerprint FROM suppressions
         WHERE scan_session_id = ?1 AND removed_at IS NULL AND expires_at > {NOW}
         ORDER BY id"
    ))?;
    let active = statement
        .query_map([session_id], |row| {
            Ok(ActiveSuppression {
                id: row.get(0)?,
                rule_id: row.get(1)?,
                fingerprint: row.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(active)
}
