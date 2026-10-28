use rusqlite::Connection;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

/// Applied in order. The connection's `user_version` records how many have run,
/// so only append to this list; never edit a migration that has shipped.
const MIGRATIONS: &[&str] = &[
    include_str!("db/migrations/0001_initial.sql"),
    include_str!("db/migrations/0002_rule_sets.sql"),
];

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
