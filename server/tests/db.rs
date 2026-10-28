use secrets_scanner_api::db::Db;

/// A rule set version with one rule added to it, a scan session on it, and one scan:
/// ids 1 for each.
const SEED: &str = "INSERT INTO rule_set_versions DEFAULT VALUES;
                    INSERT INTO rules DEFAULT VALUES;
                    INSERT INTO rule_set_version_rules (rule_set_version_id, rule_id, definition) VALUES (1, 1, '{}');
                    INSERT INTO scan_sessions (rule_set_version_id) VALUES (1);
                    INSERT INTO scans (scan_session_id) VALUES (1);";

#[tokio::test]
async fn migrations_create_the_storage_tables() {
    let db = Db::open_in_memory().expect("in-memory database should open");
    let tables = db
        .call(|connection| {
            let mut statement = connection.prepare(
                "SELECT name FROM sqlite_schema
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )?;
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .await
        .expect("schema should be readable");

    assert_eq!(
        tables,
        [
            "findings",
            "rule_set_version_rules",
            "rule_set_versions",
            "rules",
            "scan_sessions",
            "scans"
        ]
    );
}

#[tokio::test]
async fn foreign_keys_are_enforced() {
    let db = Db::open_in_memory().expect("in-memory database should open");
    let results = db
        .call(|connection| {
            let insert = |sql: &str| connection.execute(sql, []).is_ok();
            Ok([
                insert("INSERT INTO rule_set_version_rules (rule_set_version_id, rule_id, definition) VALUES (1, 1, '{}')"),
                insert("INSERT INTO scan_sessions (rule_set_version_id) VALUES (1)"),
                insert("INSERT INTO scans (scan_session_id) VALUES (1)"),
                insert("INSERT INTO rule_set_versions (parent_id) VALUES (99)"),
            ])
        })
        .await
        .expect("inserts should run");

    assert_eq!(results, [false; 4]);
}

#[tokio::test]
async fn a_rule_exists_unattached_and_keeps_one_id_across_versions() {
    let db = Db::open_in_memory().expect("in-memory database should open");
    let (unattached, versions_of_rule, duplicate) = db
        .call(|connection| {
            connection.execute_batch(
                "INSERT INTO rules DEFAULT VALUES;
                 INSERT INTO rule_set_versions DEFAULT VALUES;
                 INSERT INTO rule_set_versions (parent_id) VALUES (1);",
            )?;
            let unattached: i64 = connection.query_row(
                "SELECT COUNT(*) FROM rule_set_version_rules WHERE rule_id = 1",
                [],
                |row| row.get(0),
            )?;
            connection.execute_batch(
                "INSERT INTO rule_set_version_rules (rule_set_version_id, rule_id, definition) VALUES (1, 1, '{}');
                 INSERT INTO rule_set_version_rules (rule_set_version_id, rule_id, definition) VALUES (2, 1, '{}');",
            )?;
            let mut statement = connection.prepare(
                "SELECT rule_set_version_id FROM rule_set_version_rules
                 WHERE rule_id = 1 ORDER BY rule_set_version_id",
            )?;
            let versions_of_rule = statement
                .query_map([], |row| row.get::<_, i64>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let duplicate = connection
                .execute(
                    "INSERT INTO rule_set_version_rules (rule_set_version_id, rule_id, definition) VALUES (1, 1, '{}')",
                    [],
                )
                .is_ok();
            Ok((unattached, versions_of_rule, duplicate))
        })
        .await
        .expect("rules should attach to versions");

    assert_eq!(unattached, 0);
    assert_eq!(versions_of_rule, [1, 2]);
    assert!(!duplicate);
}

#[tokio::test]
async fn a_new_rule_starts_as_a_draft_and_drafting_is_a_boolean() {
    let db = Db::open_in_memory().expect("in-memory database should open");
    let (drafting, cleared, invalid) = db
        .call(|connection| {
            connection.execute_batch(SEED)?;
            let drafting: bool =
                connection.query_row("SELECT drafting FROM rules", [], |row| row.get(0))?;
            connection.execute("UPDATE rules SET drafting = 0", [])?;
            let cleared: bool =
                connection.query_row("SELECT drafting FROM rules", [], |row| row.get(0))?;
            let invalid = connection
                .execute("UPDATE rules SET drafting = 2", [])
                .is_ok();
            Ok((drafting, cleared, invalid))
        })
        .await
        .expect("rule should be readable");

    assert!(drafting);
    assert!(!cleared);
    assert!(!invalid);
}

#[tokio::test]
async fn a_rule_definition_starts_empty_and_must_be_json() {
    let db = Db::open_in_memory().expect("in-memory database should open");
    let (empty, pattern, invalid) = db
        .call(|connection| {
            connection.execute_batch(SEED)?;
            let empty: String =
                connection.query_row("SELECT definition FROM rules", [], |row| row.get(0))?;
            connection.execute(
                "UPDATE rules SET definition = '{\"name\": \"AWS access key\", \"pattern\": \"AKIA[0-9A-Z]{16}\"}'",
                [],
            )?;
            let pattern: String = connection.query_row(
                "SELECT json_extract(definition, '$.pattern') FROM rules",
                [],
                |row| row.get(0),
            )?;
            let invalid = connection
                .execute("UPDATE rules SET definition = 'not json'", [])
                .is_ok();
            Ok((empty, pattern, invalid))
        })
        .await
        .expect("rule definition should round-trip");

    assert_eq!(empty, "{}");
    assert_eq!(pattern, "AKIA[0-9A-Z]{16}");
    assert!(!invalid);
}

#[tokio::test]
async fn a_version_keeps_its_snapshot_when_the_rule_is_edited_later() {
    let db = Db::open_in_memory().expect("in-memory database should open");
    let (snapshot, current) = db
        .call(|connection| {
            connection.execute_batch(
                "INSERT INTO rule_set_versions DEFAULT VALUES;
                 INSERT INTO rules (definition) VALUES ('{\"pattern\": \"AKIA[0-9A-Z]{16}\"}');
                 INSERT INTO rule_set_version_rules (rule_set_version_id, rule_id, definition)
                     SELECT 1, id, definition FROM rules WHERE id = 1;
                 UPDATE rules SET definition = '{\"pattern\": \"AKIA[0-9A-Z]{20}\"}' WHERE id = 1;",
            )?;
            let snapshot: String = connection.query_row(
                "SELECT json_extract(definition, '$.pattern') FROM rule_set_version_rules",
                [],
                |row| row.get(0),
            )?;
            let current: String = connection.query_row(
                "SELECT json_extract(definition, '$.pattern') FROM rules",
                [],
                |row| row.get(0),
            )?;
            Ok((snapshot, current))
        })
        .await
        .expect("snapshot should be readable");

    assert_eq!(snapshot, "AKIA[0-9A-Z]{16}");
    assert_eq!(current, "AKIA[0-9A-Z]{20}");
}

#[tokio::test]
async fn a_finding_links_its_scan_and_the_rule_it_violates() {
    let db = Db::open_in_memory().expect("in-memory database should open");
    let (rule_id, kind, pretty) = db
        .call(|connection| {
            connection.execute_batch(SEED)?;
            connection.execute(
                "INSERT INTO findings (scan_id, rule_id, kind, violation, violation_pretty)
                 VALUES (1, 1, 'match', '{\"line\": 4}', 'AWS access key at line 4')",
                [],
            )?;
            connection.query_row(
                "SELECT findings.rule_id, findings.kind, violation_pretty
                 FROM findings JOIN scans ON scans.id = findings.scan_id",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
        })
        .await
        .expect("finding should round-trip");

    assert_eq!(rule_id, 1);
    assert_eq!(kind, "match");
    assert_eq!(pretty, "AWS access key at line 4");
}

#[tokio::test]
async fn a_finding_rejects_a_violation_that_is_not_json() {
    let db = Db::open_in_memory().expect("in-memory database should open");
    let result = db
        .call(|connection| {
            connection.execute_batch(SEED)?;
            connection.execute(
                "INSERT INTO findings (scan_id, rule_id, kind, violation, violation_pretty)
                 VALUES (1, 1, 'match', 'not json', 'pretty')",
                [],
            )
        })
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn a_rule_error_is_a_finding_and_kind_only_accepts_known_values() {
    let db = Db::open_in_memory().expect("in-memory database should open");
    let (partial, unknown_kind) = db
        .call(|connection| {
            connection.execute_batch(SEED)?;
            connection.execute(
                "INSERT INTO findings (scan_id, rule_id, kind, violation, violation_pretty)
                 VALUES (1, 1, 'rule_error',
                         '{\"field\": \"pattern\", \"code\": \"invalid_regex\", \"span\": [7, 8]}',
                         'AWS access key: pattern has an unclosed group')",
                [],
            )?;
            let partial: bool = connection.query_row(
                "SELECT EXISTS (SELECT 1 FROM findings WHERE scan_id = 1 AND kind = 'rule_error')",
                [],
                |row| row.get(0),
            )?;
            let unknown_kind = connection
                .execute(
                    "INSERT INTO findings (scan_id, rule_id, kind, violation, violation_pretty)
                     VALUES (1, 1, 'rule-error', '{}', 'pretty')",
                    [],
                )
                .is_ok();
            Ok((partial, unknown_kind))
        })
        .await
        .expect("rule error finding should insert");

    assert!(partial);
    assert!(!unknown_kind);
}

#[tokio::test]
async fn a_scan_session_starts_with_no_last_ran_and_dates_set() {
    let db = Db::open_in_memory().expect("in-memory database should open");
    let (last_ran, created_at, updated_at) = db
        .call(|connection| {
            connection.execute_batch(SEED)?;
            connection.query_row(
                "SELECT last_ran, created_at, updated_at FROM scan_sessions",
                [],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
        })
        .await
        .expect("scan session should be readable");

    assert_eq!(last_ran, None);
    assert!(created_at.ends_with('Z'));
    assert_eq!(created_at, updated_at);
}

#[tokio::test]
async fn a_scan_starts_untruncated_and_truncated_is_a_boolean() {
    let db = Db::open_in_memory().expect("in-memory database should open");
    let (truncated, set, invalid) = db
        .call(|connection| {
            connection.execute_batch(SEED)?;
            let truncated: bool =
                connection.query_row("SELECT truncated FROM scans", [], |row| row.get(0))?;
            connection.execute("UPDATE scans SET truncated = 1", [])?;
            let set: bool =
                connection.query_row("SELECT truncated FROM scans", [], |row| row.get(0))?;
            let invalid = connection
                .execute("UPDATE scans SET truncated = 2", [])
                .is_ok();
            Ok((truncated, set, invalid))
        })
        .await
        .expect("scan should be readable");

    assert!(!truncated);
    assert!(set);
    assert!(!invalid);
}

#[tokio::test]
async fn a_rule_set_version_starts_unarchived_and_archived_is_a_boolean() {
    let db = Db::open_in_memory().expect("in-memory database should open");
    let (archived, set, invalid) = db
        .call(|connection| {
            connection.execute_batch(SEED)?;
            let archived: bool =
                connection.query_row("SELECT archived FROM rule_set_versions", [], |row| {
                    row.get(0)
                })?;
            connection.execute("UPDATE rule_set_versions SET archived = 1", [])?;
            let set: bool =
                connection.query_row("SELECT archived FROM rule_set_versions", [], |row| {
                    row.get(0)
                })?;
            let invalid = connection
                .execute("UPDATE rule_set_versions SET archived = 2", [])
                .is_ok();
            Ok((archived, set, invalid))
        })
        .await
        .expect("rule set version should be readable");

    assert!(!archived);
    assert!(set);
    assert!(!invalid);
}

#[tokio::test]
async fn reopening_a_file_database_keeps_data_and_skips_applied_migrations() {
    let path = std::env::temp_dir().join(format!(
        "secrets-scanner-db-test-{}.sqlite3",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);

    let db = Db::open(&path).expect("file database should open");
    db.call(|connection| connection.execute_batch(SEED))
        .await
        .expect("seed rows should insert");
    drop(db);

    let db = Db::open(&path).expect("file database should reopen");
    let sessions: i64 = db
        .call(|connection| {
            connection.query_row("SELECT COUNT(*) FROM scan_sessions", [], |row| row.get(0))
        })
        .await
        .expect("scan sessions should be countable");
    drop(db);

    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    assert_eq!(sessions, 1);
}
