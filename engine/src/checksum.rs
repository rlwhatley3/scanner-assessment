use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumAlgorithm {
    Crc32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumEncoding {
    /// Digits `0-9A-Za-z`, in that order.
    Base62,
    /// Digits `0-9a-f`; either case matches.
    Hex,
}

/// How a token format builds its checksum, so a match can be checked offline: a real-format
/// token passes, and a made-up one (an example, a test value, random text) almost always fails.
///
/// A token is read as `prefix + covered part + checksum`. The checksum is the algorithm's value
/// for the covered part, written in the encoding and zero-padded to `length` characters. The
/// built-in rules seed the common setups (GitHub, npm); a rule author can describe their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Checksum {
    pub algorithm: ChecksumAlgorithm,
    pub encoding: ChecksumEncoding,
    /// Characters at the start that the checksum doesn't cover, such as `ghp_`.
    pub prefix_length: usize,
    /// Characters at the end that hold the checksum.
    pub length: usize,
}

const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const HEX: &[u8] = b"0123456789abcdef";

impl Checksum {
    /// GitHub's token format (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`), which npm also uses
    /// (`npm_`): a 4-character prefix, 30 random characters, then a 6-character base62 CRC32.
    pub const GITHUB: Checksum = Checksum {
        algorithm: ChecksumAlgorithm::Crc32,
        encoding: ChecksumEncoding::Base62,
        prefix_length: 4,
        length: 6,
    };

    /// The longest checksum a setup may describe.
    pub const MAX_LENGTH: usize = 16;

    /// The fewest characters that can hold the algorithm's full value in this encoding. A
    /// shorter checksum would drop part of the value and never match.
    pub fn min_length(self) -> usize {
        match (self.algorithm, self.encoding) {
            (ChecksumAlgorithm::Crc32, ChecksumEncoding::Base62) => 6,
            (ChecksumAlgorithm::Crc32, ChecksumEncoding::Hex) => 8,
        }
    }

    /// The checksum for the covered part of a token, as it appears at the token's end.
    pub fn compute(self, covered: &str) -> String {
        let value = match self.algorithm {
            ChecksumAlgorithm::Crc32 => crc32fast::hash(covered.as_bytes()),
        };
        let digits = match self.encoding {
            ChecksumEncoding::Base62 => BASE62,
            ChecksumEncoding::Hex => HEX,
        };
        let base = digits.len() as u64;
        let mut value = u64::from(value);
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
            ChecksumEncoding::Hex => checksum.eq_ignore_ascii_case(&expected),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RANDOM: &str = "Zq7Lm2Xc9Vb4Nn6Tt1Rr8Pp3Kk5Hh0";

    #[test]
    fn a_github_token_built_with_its_checksum_passes_and_a_changed_one_fails() {
        let token = format!("ghp_{RANDOM}{}", Checksum::GITHUB.compute(RANDOM));
        assert!(Checksum::GITHUB.is_valid(&token));

        let mut tampered = token.into_bytes();
        tampered[10] = if tampered[10] == b'a' { b'b' } else { b'a' };
        assert!(!Checksum::GITHUB.is_valid(&String::from_utf8(tampered).unwrap()));
    }

    #[test]
    fn checksums_are_zero_padded_to_their_length() {
        // CRC32 of the empty string is 0.
        assert_eq!(Checksum::GITHUB.compute(""), "000000");
        let hex = Checksum {
            encoding: ChecksumEncoding::Hex,
            length: 8,
            ..Checksum::GITHUB
        };
        assert_eq!(hex.compute(""), "00000000");
        // The well-known CRC32 of "123456789".
        assert_eq!(hex.compute("123456789"), "cbf43926");
    }

    #[test]
    fn hex_checksums_match_in_either_case() {
        let setup = Checksum {
            algorithm: ChecksumAlgorithm::Crc32,
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
        assert!(!Checksum::GITHUB.is_valid("ghp_short"));
        assert!(!Checksum::GITHUB.is_valid("ghp_000000"));
    }

    #[test]
    fn the_minimum_length_holds_a_full_crc32() {
        assert_eq!(Checksum::GITHUB.min_length(), 6);
        let hex = Checksum {
            encoding: ChecksumEncoding::Hex,
            ..Checksum::GITHUB
        };
        assert_eq!(hex.min_length(), 8);
    }
}
