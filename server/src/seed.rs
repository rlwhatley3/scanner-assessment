use crate::db::Db;
use secrets_scanner_engine::default_rule_set;

/// The name the built-in rules are seeded under. Users can rename it.
pub const BUILT_IN_RULE_SET_NAME: &str = "Built-in rules";

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
        for rule in default_rule_set().rules {
            let definition = serde_json::to_string(&rule.definition)
                .expect("a rule definition always serializes");
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
