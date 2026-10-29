use crate::db::Db;
use secrets_scanner_engine::{
    DetectionType, RuleDefinition, default_rule_set, secret_detector_rule, value_classifier_setting,
};

/// The name the built-in rules are seeded under. Users can rename it.
pub const BUILT_IN_RULE_SET_NAME: &str = "Built-in rules";

/// The rules a new database starts with: the engine's built-in rule set, with the value
/// classifier turned on for the likely-credential rules, then the secret detector rule. The
/// likely-credential rules match by randomness or password shape, so they're the ones that catch
/// hashes and IDs. The detector flags secrets no pattern describes, and the classifier lowers
/// the confidence of what it flags that isn't a credential. The API loads both models at startup.
pub fn built_in_rules() -> Vec<RuleDefinition> {
    let mut detector = secret_detector_rule();
    detector.value_classifier = Some(value_classifier_setting());
    default_rule_set()
        .rules
        .into_iter()
        .map(|rule| {
            let mut definition = rule.definition;
            if definition.detection_type == Some(DetectionType::LikelyCredential) {
                definition.value_classifier = Some(value_classifier_setting());
            }
            definition
        })
        .chain([detector])
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
