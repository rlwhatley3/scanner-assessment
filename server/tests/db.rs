use secrets_scanner_api::db::Db;

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
            "inspections",
            "rule_errors",
            "rule_ids",
            "rule_set_versions",
            "rule_set_working_copy",
            "scan_sessions"
        ]
    );
}

#[tokio::test]
async fn the_working_copy_holds_draft_rules_and_is_a_single_row() {
    let db = Db::open_in_memory().expect("in-memory database should open");
    let (draft, second_row) = db
        .call(|connection| {
            connection.execute(
                "INSERT INTO rule_set_working_copy (id, placeholders, rules)
                 VALUES (1, '[]', '[{\"id\": 1, \"name\": \"\", \"draft\": true}]')",
                [],
            )?;
            let draft: bool = connection.query_row(
                "SELECT json_extract(rules, '$[0].draft') FROM rule_set_working_copy",
                [],
                |row| row.get(0),
            )?;
            let second_row = connection
                .execute(
                    "INSERT INTO rule_set_working_copy (id, placeholders, rules)
                     VALUES (2, '[]', '[]')",
                    [],
                )
                .is_ok();
            Ok((draft, second_row))
        })
        .await
        .expect("working copy should be writable");

    assert!(draft);
    assert!(!second_row);
}

#[tokio::test]
async fn foreign_keys_are_enforced() {
    let db = Db::open_in_memory().expect("in-memory database should open");
    let result = db
        .call(|connection| {
            connection.execute(
                "INSERT INTO inspections (scan_session_id, rule_set_version_id, log_id, outcome)
                 VALUES (1, 1, 'log', 'clean')",
                [],
            )
        })
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn rule_ids_are_never_reused() {
    let db = Db::open_in_memory().expect("in-memory database should open");
    let (first, second) = db
        .call(|connection| {
            connection.execute("INSERT INTO rule_ids DEFAULT VALUES", [])?;
            let first = connection.last_insert_rowid();
            connection.execute("DELETE FROM rule_ids WHERE id = ?1", [first])?;
            connection.execute("INSERT INTO rule_ids DEFAULT VALUES", [])?;
            Ok((first, connection.last_insert_rowid()))
        })
        .await
        .expect("rule ids should be allocated");

    assert!(second > first);
}

#[tokio::test]
async fn rule_errors_keep_the_field_code_and_span() {
    let db = Db::open_in_memory().expect("in-memory database should open");
    let stored = db
        .call(|connection| {
            connection.execute_batch(
                "INSERT INTO scan_sessions DEFAULT VALUES;
                 INSERT INTO rule_set_versions (placeholders, rules) VALUES ('[]', '[]');
                 INSERT INTO inspections (scan_session_id, rule_set_version_id, log_id, outcome)
                 VALUES (1, 1, 'log', 'partial');",
            )?;
            connection.execute(
                "INSERT INTO rule_errors
                     (inspection_id, rule_id, rule_name, field, code, message, span_start, span_end)
                 VALUES (1, 7, 'AWS access key', 'pattern', 'invalid_regex', 'unclosed group', 7, 8)",
                [],
            )?;
            connection.query_row(
                "SELECT field, code, span_start, span_end FROM rule_errors",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                    ))
                },
            )
        })
        .await
        .expect("rule error should round-trip");

    assert_eq!(
        stored,
        ("pattern".into(), "invalid_regex".into(), Some(7), Some(8))
    );
}

#[tokio::test]
async fn rule_errors_reject_unknown_codes_and_half_spans() {
    let db = Db::open_in_memory().expect("in-memory database should open");
    let results = db
        .call(|connection| {
            connection.execute_batch(
                "INSERT INTO scan_sessions DEFAULT VALUES;
                 INSERT INTO rule_set_versions (placeholders, rules) VALUES ('[]', '[]');
                 INSERT INTO inspections (scan_session_id, rule_set_version_id, log_id, outcome)
                 VALUES (1, 1, 'log', 'partial');",
            )?;
            let insert = |field: &str, code: &str, span: (Option<i64>, Option<i64>)| {
                connection
                    .execute(
                        "INSERT INTO rule_errors
                             (inspection_id, rule_id, field, code, message, span_start, span_end)
                         VALUES (1, 1, ?1, ?2, 'message', ?3, ?4)",
                        rusqlite::params![field, code, span.0, span.1],
                    )
                    .is_ok()
            };
            Ok([
                insert("pattern", "made_up", (None, None)),
                insert("made_up", "required", (None, None)),
                insert("pattern", "invalid_regex", (Some(3), None)),
                insert("pattern", "invalid_regex", (Some(5), Some(2))),
                insert("name", "required", (None, None)),
            ])
        })
        .await
        .expect("inserts should run");

    assert_eq!(results, [false, false, false, false, true]);
}

#[tokio::test]
async fn reopening_a_file_database_keeps_data_and_skips_applied_migrations() {
    let path = std::env::temp_dir().join(format!(
        "secrets-scanner-db-test-{}.sqlite3",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);

    let db = Db::open(&path).expect("file database should open");
    db.call(|connection| connection.execute("INSERT INTO scan_sessions DEFAULT VALUES", []))
        .await
        .expect("scan session should insert");
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
