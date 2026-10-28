use rusqlite::{Connection, Transaction};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

/// Applied in order. The connection's `user_version` records how many have run,
/// so only append to this list; never edit a migration that has shipped.
const MIGRATIONS: &[&str] = &[
    include_str!("db/migrations/0001_initial.sql"),
    include_str!("db/migrations/0002_seeds.sql"),
];

type Seed = fn(&Transaction) -> rusqlite::Result<()>;

/// Built-in data, applied once per database by `Db::seed` and recorded in the `seeds` table.
/// Only append; a seed that has run is never applied again.
const SEEDS: &[(&str, Seed)] = &[("default_rule_set", seed_default_rule_set)];

/// The built-in rules, copied from the engine's `rule_sets/default.json`. Once the engine crate
/// is a dependency, read them from `engine::default_rule_set()` instead.
const DEFAULT_RULE_SET: &str = include_str!("db/seeds/default_rule_set.json");

/// A shared SQLite connection. Cloning is cheap; all clones use the same connection.
#[derive(Clone)]
pub struct Db(Arc<Mutex<Connection>>);

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        Self::init(connection)
    }

    /// A fresh database that disappears when the last clone is dropped. Used by tests.
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut connection: Connection) -> rusqlite::Result<Self> {
        connection.pragma_update(None, "foreign_keys", true)?;
        migrate(&mut connection)?;
        Ok(Self(Arc::new(Mutex::new(connection))))
    }

    /// Applies any seeds this database has not had yet. The app calls this on startup; tests
    /// that need an empty database simply don't.
    pub async fn seed(&self) -> rusqlite::Result<()> {
        self.call(|connection| {
            for (name, apply) in SEEDS {
                let transaction = connection.transaction()?;
                let applied: bool = transaction.query_row(
                    "SELECT EXISTS (SELECT 1 FROM seeds WHERE name = ?1)",
                    [name],
                    |row| row.get(0),
                )?;
                if !applied {
                    apply(&transaction)?;
                    transaction.execute("INSERT INTO seeds (name) VALUES (?1)", [name])?;
                }
                transaction.commit()?;
            }
            Ok(())
        })
        .await
    }

    /// Runs `work` on a blocking thread so SQLite calls never stall the async runtime.
    pub async fn call<T, F>(&self, work: F) -> rusqlite::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        let connection = Arc::clone(&self.0);
        tokio::task::spawn_blocking(move || {
            let mut connection = connection.lock().expect("database mutex poisoned");
            work(&mut connection)
        })
        .await
        .unwrap_or_else(|error| std::panic::resume_unwind(error.into_panic()))
    }
}

/// `server/data/scanner.sqlite3`, unless `DATABASE_PATH` is set.
pub fn default_path() -> PathBuf {
    std::env::var_os("DATABASE_PATH").map_or_else(
        || {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("data")
                .join("scanner.sqlite3")
        },
        PathBuf::from,
    )
}

fn migrate(connection: &mut Connection) -> rusqlite::Result<()> {
    let applied: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    for (index, migration) in MIGRATIONS.iter().enumerate().skip(applied as usize) {
        let transaction = connection.transaction()?;
        transaction.execute_batch(migration)?;
        transaction.pragma_update(None, "user_version", (index + 1) as u32)?;
        transaction.commit()?;
    }
    Ok(())
}

/// The built-in rules as one rule set version, every rule already validated (not drafting).
fn seed_default_rule_set(transaction: &Transaction) -> rusqlite::Result<()> {
    let rule_set: serde_json::Value =
        serde_json::from_str(DEFAULT_RULE_SET).expect("default_rule_set.json should be JSON");
    let rules = rule_set["rules"]
        .as_array()
        .expect("default_rule_set.json should list rules");

    transaction.execute("INSERT INTO rule_set_versions DEFAULT VALUES", [])?;
    let version_id = transaction.last_insert_rowid();
    for rule in rules {
        let definition = rule["definition"].to_string();
        transaction.execute(
            "INSERT INTO rules (definition, drafting) VALUES (?1, 0)",
            [&definition],
        )?;
        transaction.execute(
            "INSERT INTO rule_set_version_rules (rule_set_version_id, rule_id, definition)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![version_id, transaction.last_insert_rowid(), definition],
        )?;
    }
    Ok(())
}
