use crate::db::Db;
use secrets_scanner_engine::{
    RuleDefinition, VALUE_CLASSIFIER_SHA256, default_rule_set, value_classifier_rule,
};

/// The name the built-in rules are seeded under. Users can rename it.
pub const BUILT_IN_RULE_SET_NAME: &str = "Built-in rules";

/// The rules a new database starts with: the engine's built-in rule set, then the value
/// classifier, which the API can run because it loads the classifier at startup.
pub fn built_in_rules() -> Vec<RuleDefinition> {
    default_rule_set()
        .rules
        .into_iter()
        .map(|rule| rule.definition)
        .chain([value_classifier_rule()])
        .collect()
}

/// Seeds the built-in rules as the first version of a "Built-in rules" rule set, once, on an
/// empty database. Each built-in rule becomes a saved (non-draft) rule, joined to the version
/// with a snapshot of its definition. The database assigns the ids.
pub async fn seed_default_rule_set(db: &Db) -> rusqlite::Result<()> {
    db.call(|connection| {
        let versions: i64 =
            connection.query_row("SELECT COUNT(*) FROM rule_set_versions", [], |row| {
                row.get(0)
            })?;
        if versions > 0 {
            return Ok(());
        }

        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO rule_sets (name, description) VALUES (?1, ?2)",
            [
                BUILT_IN_RULE_SET_NAME,
                "The rules this app ships with. Edit them into new versions, or copy a version \
                 into a new rule set.",
            ],
        )?;
        transaction.execute(
            "INSERT INTO rule_set_versions (rule_set_id) VALUES (?1)",
            [transaction.last_insert_rowid()],
        )?;
        let version_id = transaction.last_insert_rowid();
        for definition in built_in_rules() {
            let definition =
                serde_json::to_string(&definition).expect("a rule definition always serializes");
            transaction.execute(
                "INSERT INTO rules (definition, drafting) VALUES (?1, 0)",
                [&definition],
            )?;
            let rule_id = transaction.last_insert_rowid();
            transaction.execute(
                "INSERT INTO rule_set_version_rules (rule_set_version_id, rule_id, definition)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![version_id, rule_id, definition],
            )?;
        }
        transaction.commit()
    })
    .await
}

/// Adds the value classifier rule to a database seeded before the API shipped it, once. It is
/// saved as a rule on its own, outside any version, since versions never change; add it to a
/// new version to use it. Databases that already have a rule naming the classifier are left
/// alone, even if that rule was edited.
pub async fn seed_value_classifier_rule(db: &Db) -> rusqlite::Result<()> {
    db.call(|connection| {
        let existing: i64 = connection.query_row(
            "SELECT COUNT(*) FROM rules WHERE json_extract(definition, '$.model.sha256') = ?1",
            [VALUE_CLASSIFIER_SHA256],
            |row| row.get(0),
        )?;
        if existing == 0 {
            let definition = serde_json::to_string(&value_classifier_rule())
                .expect("a rule definition always serializes");
            connection.execute(
                "INSERT INTO rules (definition, drafting) VALUES (?1, 0)",
                [&definition],
            )?;
        }
        Ok(())
    })
    .await
}
