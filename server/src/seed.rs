use crate::db::Db;
use secrets_scanner_engine::default_rule_set;

/// Seeds the built-in rule set as the first rule set version, once, on an empty database.
/// Each built-in rule becomes a saved (non-draft) rule, joined to the version with a snapshot of
/// its definition. The database assigns the rule ids.
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
        transaction.execute("INSERT INTO rule_set_versions DEFAULT VALUES", [])?;
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
