use argon2::{Algorithm, Argon2, Params, Version};

/// The length of a fingerprint key in bytes.
pub const FINGERPRINT_KEY_BYTES: usize = 32;

/// Argon2id memory cost in KiB (4 MiB). With `FINGERPRINT_PASSES`, about 4.5 ms per value on a
/// laptop, so a scan's 200 findings at most add under a second. Changing either makes every
/// stored fingerprint stop matching, so every suppression ends.
const FINGERPRINT_MEMORY_KIB: u32 = 4 * 1024;
const FINGERPRINT_PASSES: u32 = 3;

/// Argon2 needs a salt. The same value must always give the same fingerprint, so this one is
/// fixed: it only keeps these hashes apart from any other use of the same key.
const FINGERPRINT_SALT: &[u8] = b"secrets-scanner/fingerprint/v1";

/// A secret key for matched-value fingerprints. The engine does no I/O, so the caller generates
/// and keeps it (the API stores it in its own file) and passes it to [`scan_with_options`].
///
/// A fingerprint is Argon2id of the value, with this key as Argon2's secret input. Without the
/// key it says nothing about the value: guesses can't even be tested. With the key, each guess
/// still costs milliseconds and megabytes, instead of the nanoseconds a fast hash such as
/// SHA-256 or HMAC takes, so a short password can't be found by trying billions of guesses.
///
/// [`scan_with_options`]: crate::scan_with_options
#[derive(Clone)]
pub struct FingerprintKey([u8; FINGERPRINT_KEY_BYTES]);

impl FingerprintKey {
    pub fn new(bytes: [u8; FINGERPRINT_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// Keyed Argon2id of `value`, as 64 lowercase hex characters.
    pub fn fingerprint(&self, value: &[u8]) -> String {
        let params = Params::new(FINGERPRINT_MEMORY_KIB, FINGERPRINT_PASSES, 1, Some(32))
            .expect("the fingerprint parameters are valid");
        let argon2 = Argon2::new_with_secret(&self.0, Algorithm::Argon2id, Version::V0x13, params)
            .expect("a 32-byte secret is valid");
        let mut hash = [0; 32];
        argon2
            .hash_password_into(value, FINGERPRINT_SALT, &mut hash)
            .expect("any value can be hashed");
        hash.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

/// Never prints the key.
impl std::fmt::Debug for FingerprintKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FingerprintKey(…)")
    }
}
