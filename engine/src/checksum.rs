use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How a format's checksum is built, so a match can be checked offline: a real value passes,
/// and a made-up one (an example, a test value, random text) almost always fails. The built-in
/// rules seed the common setups; a rule author can describe their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "algorithm", rename_all = "snake_case")]
pub enum Checksum {
    /// A CRC32 written at the end of a token. Used by GitHub, npm, and GitLab tokens, and by
    /// in-house formats a rule author describes.
    Crc32(Crc32Checksum),
    /// The mod-10 check digit on payment card numbers. Spaces and dashes between digit groups
    /// are ignored.
    Luhn,
    /// Base58 with a 4-byte double-SHA-256 checksum at the end, as in Bitcoin private keys (WIF).
    Base58check,
}

impl Checksum {
    /// Whether `value` passes this checksum. A value that isn't even the right shape fails.
    pub fn is_valid(self, value: &str) -> bool {
        match self {
            Checksum::Crc32(checksum) => checksum.is_valid(value),
            Checksum::Luhn => luhn_is_valid(value),
            Checksum::Base58check => base58check_is_valid(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumEncoding {
    /// Digits `0-9A-Za-z`, in that order.
    Base62,
    /// Digits `0-9a-z`; either case matches.
    Base36,
    /// Digits `0-9a-f`; either case matches.
    Hex,
}

/// A token read as `prefix + covered part + checksum`, where the checksum is the CRC32 of the
/// covered part, written in the encoding and zero-padded to `length` characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Crc32Checksum {
    pub encoding: ChecksumEncoding,
    /// Characters at the start that the checksum doesn't cover, such as `ghp_`.
    pub prefix_length: usize,
    /// Characters at the end that hold the checksum.
    pub length: usize,
}

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE36: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
const HEX: &[u8] = b"0123456789abcdef";
const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

impl Crc32Checksum {
    /// GitHub's token format (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`), which npm also uses
    /// (`npm_`): a 4-character prefix, 30 random characters, then a 6-character base62 CRC32.
    pub const GITHUB: Crc32Checksum = Crc32Checksum {
        encoding: ChecksumEncoding::Base62,
        prefix_length: 4,
        length: 6,
    };

    /// GitLab's routable token format: a CRC32 of everything before the last 7 characters,
    /// prefix included, written in base36.
    pub const GITLAB: Crc32Checksum = Crc32Checksum {
        encoding: ChecksumEncoding::Base36,
        prefix_length: 0,
        length: 7,
    };

    /// The longest checksum a setup may describe.
    pub const MAX_LENGTH: usize = 16;

    /// The fewest characters that can hold a full CRC32 in this encoding. A shorter checksum
    /// would drop part of the value and never match.
    pub fn min_length(self) -> usize {
        match self.encoding {
            ChecksumEncoding::Base62 => 6,
            ChecksumEncoding::Base36 => 7,
            ChecksumEncoding::Hex => 8,
        }
    }

    /// The checksum for the covered part of a token, as it appears at the token's end.
    pub fn compute(self, covered: &str) -> String {
        let digits = match self.encoding {
            ChecksumEncoding::Base62 => BASE62,
            ChecksumEncoding::Base36 => BASE36,
            ChecksumEncoding::Hex => HEX,
        };
        let base = digits.len() as u64;
        let mut value = u64::from(crc32fast::hash(covered.as_bytes()));
        let mut encoded = vec![b'0'; self.length];
        for digit in encoded.iter_mut().rev() {
            *digit = digits[(value % base) as usize];
            value /= base;
        }
        String::from_utf8(encoded).expect("checksum digits are ASCII")
    }

    /// Whether `token` passes. A token too short to hold a prefix, a covered part, and a
    /// checksum fails.
    pub fn is_valid(self, token: &str) -> bool {
        if !token.is_ascii() || token.len() <= self.prefix_length + self.length {
            return false;
        }
        let (rest, checksum) = token.split_at(token.len() - self.length);
        let expected = self.compute(&rest[self.prefix_length..]);
        match self.encoding {
            ChecksumEncoding::Base62 => checksum == expected,
            ChecksumEncoding::Base36 | ChecksumEncoding::Hex => {
                checksum.eq_ignore_ascii_case(&expected)
            }
        }
    }
}

fn luhn_is_valid(value: &str) -> bool {
    let digits: Vec<u32> = value
        .chars()
        .filter(|character| !matches!(character, ' ' | '-'))
        .map(|character| character.to_digit(10))
        .collect::<Option<_>>()
        .unwrap_or_default();
    if digits.len() < 2 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(index, &digit)| {
            if index % 2 == 1 {
                let doubled = digit * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                digit
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Decodes Base58 into bytes; each leading `1` is a leading zero byte.
fn base58_decode(value: &str) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    for character in value.bytes() {
        let mut carry = BASE58.iter().position(|&digit| digit == character)? as u32;
        for byte in bytes.iter_mut().rev() {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let leading_zeros = value
        .bytes()
        .take_while(|&character| character == b'1')
        .count();
    let mut decoded = vec![0; leading_zeros];
    decoded.extend(bytes);
    Some(decoded)
}

fn base58check_is_valid(value: &str) -> bool {
    let Some(bytes) = base58_decode(value) else {
        return false;
    };
    if bytes.len() < 5 {
        return false;
    }
    let (payload, checksum) = bytes.split_at(bytes.len() - 4);
    let digest = Sha256::digest(Sha256::digest(payload));
    digest[..4] == *checksum
}

#[cfg(test)]
mod tests {
    use super::*;

    const RANDOM: &str = "Zq7Lm2Xc9Vb4Nn6Tt1Rr8Pp3Kk5Hh0";

    #[test]
    fn a_github_token_built_with_its_checksum_passes_and_a_changed_one_fails() {
        let token = format!("ghp_{RANDOM}{}", Crc32Checksum::GITHUB.compute(RANDOM));
        assert!(Checksum::Crc32(Crc32Checksum::GITHUB).is_valid(&token));

        let mut tampered = token.into_bytes();
        tampered[10] = if tampered[10] == b'a' { b'b' } else { b'a' };
        assert!(!Crc32Checksum::GITHUB.is_valid(&String::from_utf8(tampered).unwrap()));
    }

    #[test]
    fn crc32_checksums_are_zero_padded_and_match_the_standard_check_value() {
        assert_eq!(Crc32Checksum::GITHUB.compute(""), "000000");
        let hex = Crc32Checksum {
            encoding: ChecksumEncoding::Hex,
            prefix_length: 0,
            length: 8,
        };
        // The well-known CRC32 of "123456789" is 0xCBF43926.
        assert_eq!(hex.compute("123456789"), "cbf43926");
        assert_eq!(Crc32Checksum::GITLAB.compute("123456789"), "1kl8mjq");
    }

    #[test]
    fn a_gitlab_checksum_covers_the_prefix_and_matches_in_either_case() {
        // Built from pieces so no token-shaped string sits in the source for secret scanners.
        let body = ["glpat", "-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789.01.0w"].concat();
        let token = format!("{body}{}", Crc32Checksum::GITLAB.compute(&body));
        assert!(Crc32Checksum::GITLAB.is_valid(&token));
        assert!(Crc32Checksum::GITLAB.is_valid(&format!(
            "{body}{}",
            Crc32Checksum::GITLAB.compute(&body).to_uppercase()
        )));
        assert!(!Crc32Checksum::GITLAB.is_valid(&token.replacen("glpat", "glpaT", 1)));
    }

    #[test]
    fn hex_checksums_match_in_either_case() {
        let setup = Crc32Checksum {
            encoding: ChecksumEncoding::Hex,
            prefix_length: 5,
            length: 8,
        };
        assert!(setup.is_valid("acme_123456789cbf43926"));
        assert!(setup.is_valid("acme_123456789CBF43926"));
        assert!(!setup.is_valid("acme_123456780cbf43926"));
    }

    #[test]
    fn a_token_too_short_for_the_setup_fails() {
        assert!(!Crc32Checksum::GITHUB.is_valid("ghp_short"));
        assert!(!Crc32Checksum::GITHUB.is_valid("ghp_000000"));
    }

    #[test]
    fn the_minimum_length_holds_a_full_crc32() {
        let with = |encoding| Crc32Checksum {
            encoding,
            ..Crc32Checksum::GITHUB
        };
        assert_eq!(with(ChecksumEncoding::Base62).min_length(), 6);
        assert_eq!(with(ChecksumEncoding::Base36).min_length(), 7);
        assert_eq!(with(ChecksumEncoding::Hex).min_length(), 8);
    }

    #[test]
    fn luhn_accepts_valid_card_numbers_with_or_without_separators() {
        for number in [
            "4111111111111111",
            "4111 1111 1111 1111",
            "3782-822463-10005",
        ] {
            assert!(Checksum::Luhn.is_valid(number), "{number}");
        }
        for number in ["4111111111111112", "4111x1111", "7"] {
            assert!(!Checksum::Luhn.is_valid(number), "{number}");
        }
    }

    #[test]
    fn base58check_accepts_a_valid_key_and_rejects_a_changed_one() {
        // The private key example from the Bitcoin wiki's Wallet Import Format page.
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        assert!(Checksum::Base58check.is_valid(wif));
        assert!(!Checksum::Base58check.is_valid(&wif.replacen('H', "J", 1)));
        assert!(!Checksum::Base58check.is_valid("0OIl"));
    }
}
