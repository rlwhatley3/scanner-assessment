use hmac::{Hmac, Mac};
use sha2::Sha256;

/// The length of a fingerprint key in bytes: the size of a SHA-256 output.
pub const FINGERPRINT_KEY_BYTES: usize = 32;

/// A secret key for matched-value fingerprints. The engine does no I/O, so the caller generates
/// and keeps it (the API stores it in its own file) and passes it to [`scan_with_options`].
///
/// A plain hash of a short password can be brute-forced from the hash alone. Keying it means a
/// fingerprint says nothing about the value without the key, and the key never leaves the
/// machine that scanned.
///
/// [`scan_with_options`]: crate::scan_with_options
#[derive(Clone)]
pub struct FingerprintKey([u8; FINGERPRINT_KEY_BYTES]);

impl FingerprintKey {
    pub fn new(bytes: [u8; FINGERPRINT_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// HMAC-SHA256 of `value` under this key, as 64 lowercase hex characters.
    pub fn fingerprint(&self, value: &[u8]) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC takes a key of any size");
        mac.update(value);
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

/// Never prints the key.
impl std::fmt::Debug for FingerprintKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FingerprintKey(…)")
    }
}
