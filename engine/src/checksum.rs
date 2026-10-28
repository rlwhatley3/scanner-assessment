use serde::{Deserialize, Serialize};

/// A checksum some token formats carry, so a match can be checked offline: a real-format token
/// passes, and a made-up one (an example, a test value, random text) almost always fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Checksum {
    /// GitHub's token format: a prefix such as `ghp_`, 30 random base62 characters, then the
    /// CRC32 of those 30 characters in base62, zero-padded to 6 characters.
    GithubCrc32,
}

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

impl Checksum {
    /// Whether `token` passes this checksum. A token that isn't even the right shape fails.
    pub fn is_valid(self, token: &str) -> bool {
        match self {
            Checksum::GithubCrc32 => {
                let Some((_, body)) = token.split_once('_') else {
                    return false;
                };
                if body.len() != 36 || !body.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
                    return false;
                }
                let (random, checksum) = body.split_at(30);
                github_checksum(random) == checksum
            }
        }
    }
}

/// The 6-character checksum GitHub appends to a token's random part.
pub fn github_checksum(random: &str) -> String {
    let mut value = crc32fast::hash(random.as_bytes());
    let mut digits = [b'0'; 6];
    for digit in digits.iter_mut().rev() {
        *digit = BASE62[(value % 62) as usize];
        value /= 62;
    }
    String::from_utf8(digits.to_vec()).expect("base62 digits are ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_built_with_its_checksum_passes_and_a_changed_one_fails() {
        let random = "Zq7Lm2Xc9Vb4Nn6Tt1Rr8Pp3Kk5Hh0";
        let token = format!("ghp_{random}{}", github_checksum(random));
        assert!(Checksum::GithubCrc32.is_valid(&token));

        let mut tampered = token.clone().into_bytes();
        tampered[10] = if tampered[10] == b'a' { b'b' } else { b'a' };
        let tampered = String::from_utf8(tampered).unwrap();
        assert!(!Checksum::GithubCrc32.is_valid(&tampered));
    }

    #[test]
    fn the_checksum_is_six_base62_digits_padded_with_zeros() {
        // CRC32 of the empty string is 0, which pads to all zeros.
        assert_eq!(github_checksum(""), "000000");
        let checksum = github_checksum("anything");
        assert_eq!(checksum.len(), 6);
        assert!(checksum.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    }

    #[test]
    fn the_wrong_shape_fails() {
        assert!(!Checksum::GithubCrc32.is_valid("ghp_short"));
        assert!(!Checksum::GithubCrc32.is_valid("no-underscore-here-at-all-000000000000"));
    }
}
