//! The local secret key that fingerprints matched values, so suppressions can recognize a value
//! without anyone storing it.
//!
//! It is generated once, on first start, into its own file beside the database
//! (`server/data/fingerprint.key`, git-ignored with the rest of `server/data/`), not into the
//! database: someone with a copy of the SQLite file alone has fingerprints they can't test
//! guesses against. It is never logged, sent to the UI, or returned by the API or MCP server.
//! Losing it is safe: every suppression stops matching, so suppressed findings come back.

use secrets_scanner_engine::{FINGERPRINT_KEY_BYTES, FingerprintKey};
use std::{
    fs, io,
    io::Write,
    path::{Path, PathBuf},
};

/// `fingerprint.key` beside the database, unless `FINGERPRINT_KEY_PATH` is set.
pub fn default_path(database_path: &Path) -> PathBuf {
    std::env::var_os("FINGERPRINT_KEY_PATH").map_or_else(
        || {
            database_path
                .parent()
                .unwrap_or(Path::new("."))
                .join("fingerprint.key")
        },
        PathBuf::from,
    )
}

/// A new random key from the operating system's generator.
pub fn generate() -> FingerprintKey {
    let mut bytes = [0; FINGERPRINT_KEY_BYTES];
    getrandom::fill(&mut bytes).expect("the operating system should provide random bytes");
    FingerprintKey::new(bytes)
}

/// Reads the key at `path`, or generates one and writes it there if the file doesn't exist. The
/// file holds the raw key bytes and, on Unix, is readable by its owner only.
pub fn load_or_create(path: &Path) -> io::Result<FingerprintKey> {
    match fs::read(path) {
        Ok(bytes) => {
            let bytes: [u8; FINGERPRINT_KEY_BYTES] = bytes.try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{} should hold exactly {FINGERPRINT_KEY_BYTES} bytes",
                        path.display()
                    ),
                )
            })?;
            Ok(FingerprintKey::new(bytes))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut bytes = [0; FINGERPRINT_KEY_BYTES];
            getrandom::fill(&mut bytes).map_err(io::Error::other)?;
            let mut options = fs::OpenOptions::new();
            // Never replace an existing key: that would silently end every suppression.
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            options.open(path)?.write_all(&bytes)?;
            Ok(FingerprintKey::new(bytes))
        }
        Err(error) => Err(error),
    }
}
