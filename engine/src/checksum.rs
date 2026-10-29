use std::sync::LazyLock;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
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
    /// The mod-10 check digit on payment card numbers. Whitespace (including a line break) and
    /// dashes between digit groups are ignored.
    Luhn,
    /// Base58 with a 4-byte double-SHA-256 checksum at the end, as in Bitcoin private keys (WIF).
    Base58check,
    /// Bech32 (BIP-173): `hrp` + `1` + data + a 6-character checksum, as in age secret keys and
    /// Nostr private keys (`nsec1`). All upper or all lower case.
    Bech32,
    /// Bech32m (BIP-350): Bech32 with a different checksum constant, as in Taproot addresses.
    Bech32m,
    /// A BIP-39 seed phrase: 12, 15, 18, 21, or 24 words from the English list, the last of
    /// which carries a SHA-256 checksum of the rest.
    Bip39,
    /// A Microsoft identifiable key: base64 whose last 4 bytes are a Marvin32 hash of the rest,
    /// as in Azure Storage, Cosmos DB, and Functions keys.
    Marvin32(Marvin32Checksum),
    /// The Verhoeff check digit, as in India's Aadhaar numbers. Whitespace and dashes between
    /// digit groups are ignored.
    Verhoeff,
    /// A position-weighted mod-11 check digit (weights 1, 2, 3, ... from the right; a final `X`
    /// is 10), as in ISBN-10 and UK NHS numbers. Whitespace and dashes are ignored.
    Mod11,
    /// ISO 7064 MOD 97-10 as IBANs use it: the first four characters (country code and check
    /// digits) are moved to the end, letters become 10 to 35, and the number is 1 mod 97.
    /// Whitespace is ignored.
    Mod97,
}

impl Checksum {
    /// Whether `value` passes this checksum. A value that isn't even the right shape fails.
    pub fn is_valid(self, value: &str) -> bool {
        match self {
            Checksum::Crc32(checksum) => checksum.is_valid(value),
            Checksum::Luhn => luhn_is_valid(value),
            Checksum::Base58check => base58check_is_valid(value),
            Checksum::Bech32 => bech32_is_valid(value, BECH32_CONST),
            Checksum::Bech32m => bech32_is_valid(value, BECH32M_CONST),
            Checksum::Bip39 => bip39_is_valid(value),
            Checksum::Marvin32(checksum) => checksum.is_valid(value),
            Checksum::Verhoeff => verhoeff_is_valid(value),
            Checksum::Mod11 => mod11_is_valid(value),
            Checksum::Mod97 => mod97_is_valid(value),
        }
    }

    /// `value` with its checksum part rewritten so it passes, for generating test data. `None`
    /// when the value can't hold one (too short, or not in the checksum's alphabet). Base58Check
    /// re-encodes the whole value, so its length can change by a character; BIP-39 swaps any
    /// word not in its list for one that is.
    pub(crate) fn repair(self, value: &str) -> Option<String> {
        match self {
            Checksum::Crc32(checksum) => {
                if !value.is_ascii() || value.len() <= checksum.prefix_length + checksum.length {
                    return None;
                }
                let rest = &value[..value.len() - checksum.length];
                Some(format!(
                    "{rest}{}",
                    checksum.compute(&rest[checksum.prefix_length..])
                ))
            }
            Checksum::Luhn => luhn_repair(value),
            Checksum::Base58check => {
                let bytes = base58_decode(value)?;
                if bytes.len() < 5 {
                    return None;
                }
                let mut payload = bytes[..bytes.len() - 4].to_vec();
                let digest = Sha256::digest(Sha256::digest(&payload));
                payload.extend_from_slice(&digest[..4]);
                Some(base58_encode(&payload))
            }
            Checksum::Bech32 => bech32_repair(value, BECH32_CONST),
            Checksum::Bech32m => bech32_repair(value, BECH32M_CONST),
            Checksum::Bip39 => bip39_repair(value),
            Checksum::Marvin32(checksum) => checksum.repair(value),
            Checksum::Verhoeff => verhoeff_repair(value),
            Checksum::Mod11 => mod11_repair(value),
            Checksum::Mod97 => mod97_repair(value),
        }
    }

    /// The byte range of `value` the checksum covers and a one-character change breaks: the
    /// covered part of a CRC32 token, a check digit, a Bech32 data part, or a whole body.
    pub(crate) fn covered(self, value: &str) -> Option<(usize, usize)> {
        let range = match self {
            Checksum::Crc32(checksum) => (
                checksum.prefix_length,
                value.len().checked_sub(checksum.length)?,
            ),
            Checksum::Luhn | Checksum::Verhoeff => {
                let last = value.rfind(|character: char| character.is_ascii_digit())?;
                (last, last + 1)
            }
            Checksum::Mod11 => {
                let last = value.rfind(|character: char| {
                    character.is_ascii_digit() || character.eq_ignore_ascii_case(&'x')
                })?;
                (last, last + 1)
            }
            Checksum::Base58check => (1, value.len().checked_sub(1)?),
            Checksum::Bech32 | Checksum::Bech32m => (value.rfind('1')? + 1, value.len()),
            Checksum::Marvin32(_) => (0, marvin32_payload_characters(value)?),
            Checksum::Bip39 | Checksum::Mod97 => (0, value.len()),
        };
        (range.0 < range.1).then_some(range)
    }

    /// How many characters at the end of `value` hold the checksum itself, so test data can
    /// leave them alone; 0 when the checksum is spread through the value.
    pub(crate) fn tail(self, value: &str) -> usize {
        match self {
            Checksum::Crc32(checksum) => checksum.length,
            Checksum::Luhn | Checksum::Verhoeff | Checksum::Mod11 => 1,
            Checksum::Bech32 | Checksum::Bech32m => 6,
            Checksum::Marvin32(_) => {
                marvin32_payload_characters(value).map_or(0, |payload| value.len() - payload)
            }
            Checksum::Base58check | Checksum::Bip39 | Checksum::Mod97 => 0,
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
        .filter(|character| !character.is_whitespace() && *character != '-')
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

/// Rewrites the last digit of `value` to the Luhn check digit of the digits before it, keeping
/// every separator where it is.
fn luhn_repair(value: &str) -> Option<String> {
    let last = value.rfind(|character: char| character.is_ascii_digit())?;
    let payload: Vec<u32> = value[..last]
        .chars()
        .filter_map(|character| character.to_digit(10))
        .collect();
    if payload.is_empty() {
        return None;
    }
    // The check digit sits at position 0 from the right, so the payload's rightmost digit is
    // the first one doubled.
    let sum: u32 = payload
        .iter()
        .rev()
        .enumerate()
        .map(|(index, &digit)| {
            if index % 2 == 0 {
                let doubled = digit * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                digit
            }
        })
        .sum();
    let check = char::from_digit((10 - sum % 10) % 10, 10)?;
    Some(format!("{}{check}{}", &value[..last], &value[last + 1..]))
}

/// Encodes bytes as Base58; each leading zero byte is a leading `1`.
fn base58_encode(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::new();
    for &byte in bytes {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let leading_zeros = bytes.iter().take_while(|&&byte| byte == 0).count();
    std::iter::repeat_n('1', leading_zeros)
        .chain(
            digits
                .iter()
                .rev()
                .map(|&digit| BASE58[digit as usize] as char),
        )
        .collect()
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

/// A Microsoft identifiable key: base64 (standard or URL-safe, padded or not) whose last 4 bytes
/// are the Marvin32 hash of the bytes before them, little-endian. Each key kind has its own seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Marvin32Checksum {
    /// The key kind's 8-character seed name, such as `Default0` for Azure Storage.
    pub seed: Marvin32Seed,
}

/// A Marvin32 seed, written as the 8 ASCII characters Microsoft names it by (`Default0`, read
/// big-endian as `0x44656661756c7430`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Marvin32Seed(pub [u8; 8]);

impl Marvin32Seed {
    fn value(self) -> u64 {
        u64::from_be_bytes(self.0)
    }
}

impl Serialize for Marvin32Seed {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(std::str::from_utf8(&self.0).expect("seeds are ASCII"))
    }
}

impl<'de> Deserialize<'de> for Marvin32Seed {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let seed = String::deserialize(deserializer)?;
        seed.as_bytes()
            .try_into()
            .ok()
            .filter(|_| seed.is_ascii())
            .map(Marvin32Seed)
            .ok_or_else(|| {
                serde::de::Error::custom(
                    "a Marvin32 seed is 8 ASCII characters, such as \"Default0\"",
                )
            })
    }
}

impl Marvin32Checksum {
    /// Azure Storage account keys, and the seed Microsoft's tools default to.
    pub const AZURE_STORAGE: Marvin32Checksum = Marvin32Checksum {
        seed: Marvin32Seed(*b"Default0"),
    };

    /// Whether `key` decodes to at least 5 bytes whose last 4 are the Marvin32 of the rest.
    pub fn is_valid(self, key: &str) -> bool {
        let Some(bytes) = base64_decode(key) else {
            return false;
        };
        if bytes.len() < 5 {
            return false;
        }
        let (payload, checksum) = bytes.split_at(bytes.len() - 4);
        marvin32(payload, self.seed.value()).to_le_bytes() == *checksum
    }

    /// `key` with its last 4 bytes rewritten, keeping its alphabet and padding.
    fn repair(self, key: &str) -> Option<String> {
        let mut bytes = base64_decode(key)?;
        if bytes.len() < 5 {
            return None;
        }
        let payload = bytes.len() - 4;
        let checksum = marvin32(&bytes[..payload], self.seed.value());
        bytes[payload..].copy_from_slice(&checksum.to_le_bytes());
        Some(base64_encode(
            &bytes,
            key.contains(['-', '_']),
            key.ends_with('='),
        ))
    }
}

/// Marvin32 as .NET and Microsoft's security-utilities compute it: the 64-bit Marvin hash with
/// its halves XORed together.
fn marvin32(data: &[u8], seed: u64) -> u32 {
    fn block(p0: &mut u32, p1: &mut u32) {
        *p1 ^= *p0;
        *p0 = p0.rotate_left(20);
        *p0 = p0.wrapping_add(*p1);
        *p1 = p1.rotate_left(9);
        *p1 ^= *p0;
        *p0 = p0.rotate_left(27);
        *p0 = p0.wrapping_add(*p1);
        *p1 = p1.rotate_left(19);
    }
    let mut p0 = seed as u32;
    let mut p1 = (seed >> 32) as u32;
    let (chunks, rest) = data.as_chunks::<4>();
    for &chunk in chunks {
        p0 = p0.wrapping_add(u32::from_le_bytes(chunk));
        block(&mut p0, &mut p1);
    }
    // The tail, little-endian, followed by a 0x80 byte.
    let mut last = 0x80u32 << (8 * rest.len());
    for (index, &byte) in rest.iter().enumerate() {
        last |= u32::from(byte) << (8 * index);
    }
    p0 = p0.wrapping_add(last);
    block(&mut p0, &mut p1);
    block(&mut p0, &mut p1);
    p0 ^ p1
}

/// How many leading characters of a base64 `key` hold only the bytes before its 4-byte
/// checksum.
fn marvin32_payload_characters(key: &str) -> Option<usize> {
    let bytes = key.trim_end_matches('=').len() * 6 / 8;
    Some(bytes.checked_sub(4).filter(|&payload| payload > 0)? * 8 / 6)
}

/// Decodes standard or URL-safe base64, with or without `=` padding.
fn base64_decode(value: &str) -> Option<Vec<u8>> {
    let body = value.trim_end_matches('=');
    let padding = value.len() - body.len();
    if padding > 2 || (padding > 0 && !value.len().is_multiple_of(4)) || body.len() % 4 == 1 {
        return None;
    }
    let mut bytes = Vec::with_capacity(body.len() * 3 / 4);
    let (mut buffer, mut bits) = (0u32, 0);
    for character in body.bytes() {
        let digit = match character {
            b'A'..=b'Z' => character - b'A',
            b'a'..=b'z' => character - b'a' + 26,
            b'0'..=b'9' => character - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
        }
    }
    Some(bytes)
}

fn base64_encode(bytes: &[u8], url_safe: bool, padded: bool) -> String {
    let alphabet: &[u8] = if url_safe {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let buffer = chunk
            .iter()
            .enumerate()
            .fold(0u32, |buffer, (index, &byte)| {
                buffer | u32::from(byte) << (16 - 8 * index)
            });
        for index in 0..=chunk.len() {
            encoded.push(alphabet[(buffer >> (18 - 6 * index) & 63) as usize] as char);
        }
        if padded {
            encoded.extend(std::iter::repeat_n('=', 3 - chunk.len()));
        }
    }
    encoded
}

const BECH32_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CONST: u32 = 1;
const BECH32M_CONST: u32 = 0x2bc8_30a3;

fn bech32_polymod(values: impl IntoIterator<Item = u8>) -> u32 {
    const GENERATOR: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    values.into_iter().fold(1, |check, value| {
        let top = check >> 25;
        let check = ((check & 0x1ff_ffff) << 5) ^ u32::from(value);
        (0..5)
            .filter(|bit| (top >> bit) & 1 == 1)
            .fold(check, |check, bit| check ^ GENERATOR[bit])
    })
}

/// The lowercase human-readable part and the data part's 5-bit values, or `None` when `value`
/// isn't Bech32-shaped: mixed case, no `1` separator, or a data character outside the alphabet.
fn bech32_parts(value: &str) -> Option<(String, Vec<u8>)> {
    if !value.is_ascii()
        || (value.contains(|c: char| c.is_ascii_uppercase())
            && value.contains(|c: char| c.is_ascii_lowercase()))
    {
        return None;
    }
    let lower = value.to_ascii_lowercase();
    let separator = lower.rfind('1')?;
    let (hrp, data) = (&lower[..separator], &lower[separator + 1..]);
    if hrp.is_empty() || !hrp.bytes().all(|byte| (33..=126).contains(&byte)) {
        return None;
    }
    let data = data
        .bytes()
        .map(|character| {
            BECH32_CHARSET
                .iter()
                .position(|&digit| digit == character)
                .map(|digit| digit as u8)
        })
        .collect::<Option<Vec<u8>>>()?;
    Some((hrp.to_string(), data))
}

fn bech32_hrp_expand(hrp: &str) -> impl Iterator<Item = u8> + '_ {
    hrp.bytes()
        .map(|byte| byte >> 5)
        .chain([0])
        .chain(hrp.bytes().map(|byte| byte & 31))
}

fn bech32_is_valid(value: &str, constant: u32) -> bool {
    bech32_parts(value).is_some_and(|(hrp, data)| {
        data.len() >= 6 && bech32_polymod(bech32_hrp_expand(&hrp).chain(data)) == constant
    })
}

/// Rewrites the last 6 characters to the checksum of everything before them, in the value's
/// case.
fn bech32_repair(value: &str, constant: u32) -> Option<String> {
    let keep = value.len().checked_sub(6).filter(|_| value.is_ascii())?;
    let upper = value[..keep].contains(|c: char| c.is_ascii_uppercase());
    let filler = if upper { "QQQQQQ" } else { "qqqqqq" };
    let (hrp, data) = bech32_parts(&format!("{}{filler}", &value[..keep]))?;
    let payload = &data[..data.len() - 6];
    let check = bech32_polymod(
        bech32_hrp_expand(&hrp)
            .chain(payload.iter().copied())
            .chain([0; 6]),
    ) ^ constant;
    let checksum: String = (0..6)
        .map(|index| BECH32_CHARSET[(check >> (5 * (5 - index)) & 31) as usize] as char)
        .collect();
    Some(format!(
        "{}{}",
        &value[..keep],
        if upper {
            checksum.to_ascii_uppercase()
        } else {
            checksum
        }
    ))
}

/// The BIP-39 English word list, in order: a word's position is its 11-bit value.
static BIP39_WORDS: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| include_str!("bip39_english.txt").lines().collect());

/// The byte ranges of the whitespace-separated words in `value`.
fn word_spans(value: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = None;
    for (index, character) in value.char_indices().chain([(value.len(), ' ')]) {
        match (start, character.is_whitespace()) {
            (None, false) => start = Some(index),
            (Some(from), true) => {
                spans.push((from, index));
                start = None;
            }
            _ => {}
        }
    }
    spans
}

fn bip39_index(word: &str) -> Option<u16> {
    BIP39_WORDS
        .binary_search(&word.to_ascii_lowercase().as_str())
        .ok()
        .map(|index| index as u16)
}

/// The last word's value with its checksum bits set from the entropy the phrase holds, or
/// `None` for a word count BIP-39 doesn't use.
fn bip39_expected_last(indices: &[u16]) -> Option<u16> {
    if ![12, 15, 18, 21, 24].contains(&indices.len()) {
        return None;
    }
    let checksum_bits = indices.len() / 3;
    let bits: Vec<u8> = indices
        .iter()
        .flat_map(|&index| (0..11).rev().map(move |bit| (index >> bit & 1) as u8))
        .collect();
    let entropy: Vec<u8> = bits[..bits.len() - checksum_bits]
        .chunks(8)
        .map(|byte| byte.iter().fold(0, |acc, &bit| acc << 1 | bit))
        .collect();
    let checksum = u16::from(Sha256::digest(&entropy)[0] >> (8 - checksum_bits));
    let last = *indices.last()?;
    Some(last >> checksum_bits << checksum_bits | checksum)
}

fn bip39_is_valid(value: &str) -> bool {
    let indices: Option<Vec<u16>> = word_spans(value)
        .into_iter()
        .map(|(start, end)| bip39_index(&value[start..end]))
        .collect();
    indices.is_some_and(|indices| bip39_expected_last(&indices) == indices.last().copied())
}

/// Swaps each word not in the list for one that is (picked from the word itself, so the same
/// input always gives the same phrase), then rewrites the last word's checksum bits.
fn bip39_repair(value: &str) -> Option<String> {
    let spans = word_spans(value);
    let mut indices: Vec<u16> = spans
        .iter()
        .map(|&(start, end)| {
            let word = &value[start..end];
            bip39_index(word).unwrap_or((crc32fast::hash(word.as_bytes()) % 2048) as u16)
        })
        .collect();
    let last = bip39_expected_last(&indices)?;
    *indices.last_mut()? = last;
    let mut repaired = String::with_capacity(value.len());
    let mut from = 0;
    for (&(start, end), &index) in spans.iter().zip(&indices) {
        repaired.push_str(&value[from..start]);
        repaired.push_str(BIP39_WORDS[usize::from(index)]);
        from = end;
    }
    repaired.push_str(&value[from..]);
    Some(repaired)
}

/// The digits of `value`, ignoring whitespace and dashes between groups; `None` if anything
/// else is in it.
fn separated_digits(value: &str) -> Option<Vec<u32>> {
    value
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '-')
        .map(|character| character.to_digit(10))
        .collect()
}

const VERHOEFF_MULTIPLY: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_PERMUTE: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];
const VERHOEFF_INVERSE: [u8; 10] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

/// The Verhoeff running check over `digits`, starting at position `offset` from the right.
fn verhoeff_check(digits: &[u32], offset: usize) -> u8 {
    digits
        .iter()
        .rev()
        .enumerate()
        .fold(0, |check, (index, &digit)| {
            VERHOEFF_MULTIPLY[usize::from(check)]
                [usize::from(VERHOEFF_PERMUTE[(index + offset) % 8][digit as usize])]
        })
}

fn verhoeff_is_valid(value: &str) -> bool {
    separated_digits(value)
        .is_some_and(|digits| digits.len() >= 2 && verhoeff_check(&digits, 0) == 0)
}

/// Rewrites the last digit to the Verhoeff check digit of the digits before it, keeping every
/// separator where it is.
fn verhoeff_repair(value: &str) -> Option<String> {
    let last = value.rfind(|character: char| character.is_ascii_digit())?;
    let payload: Vec<u32> = value[..last]
        .chars()
        .filter_map(|character| character.to_digit(10))
        .collect();
    if payload.is_empty() {
        return None;
    }
    let check = VERHOEFF_INVERSE[usize::from(verhoeff_check(&payload, 1))];
    Some(format!("{}{check}{}", &value[..last], &value[last + 1..]))
}

fn mod11_is_valid(value: &str) -> bool {
    let characters: Vec<char> = value
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '-')
        .collect();
    let Some((&check, payload)) = characters.split_last() else {
        return false;
    };
    let check = if check.eq_ignore_ascii_case(&'x') {
        10
    } else {
        match check.to_digit(10) {
            Some(digit) => digit,
            None => return false,
        }
    };
    let Some(payload) = payload
        .iter()
        .map(|character| character.to_digit(10))
        .collect::<Option<Vec<u32>>>()
    else {
        return false;
    };
    !payload.is_empty() && (check + mod11_weighted(&payload)).is_multiple_of(11)
}

/// The payload digits weighted 2, 3, 4, ... from the right, as they sit before a check digit.
fn mod11_weighted(payload: &[u32]) -> u32 {
    payload
        .iter()
        .rev()
        .zip(2..)
        .map(|(&digit, weight)| digit * weight)
        .sum()
}

/// Rewrites the last digit (or `X`) to the mod-11 check digit, writing `X` for 10.
fn mod11_repair(value: &str) -> Option<String> {
    let last = value.rfind(|character: char| {
        character.is_ascii_digit() || character.eq_ignore_ascii_case(&'x')
    })?;
    let payload: Vec<u32> = value[..last]
        .chars()
        .filter_map(|character| character.to_digit(10))
        .collect();
    if payload.is_empty() {
        return None;
    }
    let check = match (11 - mod11_weighted(&payload) % 11) % 11 {
        10 => 'X',
        digit => char::from_digit(digit, 10)?,
    };
    Some(format!("{}{check}{}", &value[..last], &value[last + 1..]))
}

/// The remainder mod 97 of `value` with whitespace removed, its first four characters moved to
/// the end, and each letter written as 10 to 35. `None` unless every character is a letter or
/// digit and there are at least 5.
fn mod97_remainder(value: &str) -> Option<u32> {
    let characters: Vec<char> = value.chars().filter(|c| !c.is_whitespace()).collect();
    if characters.len() < 5 {
        return None;
    }
    characters[4..]
        .iter()
        .chain(&characters[..4])
        .try_fold(0, |remainder, character| {
            let digit = character.to_digit(36)?;
            Some(if digit < 10 {
                (remainder * 10 + digit) % 97
            } else {
                (remainder * 100 + digit) % 97
            })
        })
}

fn mod97_is_valid(value: &str) -> bool {
    value.is_ascii() && mod97_remainder(value) == Some(1)
}

/// Rewrites the check digits (the third and fourth characters, after the country code).
fn mod97_repair(value: &str) -> Option<String> {
    if !value.is_ascii() {
        return None;
    }
    let positions: Vec<usize> = value
        .char_indices()
        .filter(|(_, character)| !character.is_whitespace())
        .map(|(index, _)| index)
        .take(4)
        .collect();
    let &[_, _, first, second] = &positions[..] else {
        return None;
    };
    let mut bytes = value.as_bytes().to_vec();
    bytes[first] = b'0';
    bytes[second] = b'0';
    let zeroed = String::from_utf8(bytes).ok()?;
    let check = format!("{:02}", 98 - mod97_remainder(&zeroed)?);
    let mut bytes = zeroed.into_bytes();
    bytes[first] = check.as_bytes()[0];
    bytes[second] = check.as_bytes()[1];
    String::from_utf8(bytes).ok()
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
            "4000 0566\n5566 5556",
            "4000 0566\r\n  5566 5556",
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

    #[test]
    fn repair_rewrites_each_checksum_so_it_passes() {
        let github = Checksum::Crc32(Crc32Checksum::GITHUB);
        let repaired = github.repair(&format!("ghp_{RANDOM}000000")).unwrap();
        assert!(github.is_valid(&repaired));
        assert_eq!(repaired.len(), 40);

        for number in [
            "4111111111111110",
            "4111 1111 1111 1119",
            "3782-822463-10009",
        ] {
            let repaired = Checksum::Luhn.repair(number).unwrap();
            assert!(Checksum::Luhn.is_valid(&repaired), "{number}");
            assert_eq!(repaired.len(), number.len());
        }

        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        assert_eq!(Checksum::Base58check.repair(wif).as_deref(), Some(wif));
        let changed = Checksum::Base58check
            .repair(&wif.replacen('H', "J", 1))
            .unwrap();
        assert!(Checksum::Base58check.is_valid(&changed));
        assert!(github.repair("ghp_short").is_none());
    }
    #[test]
    fn bech32_and_bech32m_accept_the_bip_test_vectors_and_reject_each_other() {
        for value in [
            "A12UEL5L",
            "a12uel5l",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        ] {
            assert!(Checksum::Bech32.is_valid(value), "{value}");
            assert!(!Checksum::Bech32m.is_valid(value), "{value}");
        }
        for value in [
            "A1LQFN3A",
            "a1lqfn3a",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
        ] {
            assert!(Checksum::Bech32m.is_valid(value), "{value}");
            assert!(!Checksum::Bech32.is_valid(value), "{value}");
        }
        for value in ["A12uEL5L", "a12uel5m", "12uel5l", "a1b2uel5l", "a1qqqqq"] {
            assert!(!Checksum::Bech32.is_valid(value), "{value}");
        }
    }

    #[test]
    fn bip39_accepts_the_reference_phrases_and_rejects_a_wrong_last_word() {
        let zeros = ["abandon"; 11].join(" ");
        for phrase in [
            format!("{zeros} about"),
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
                .to_string(),
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong".to_string(),
            format!("{} art", ["abandon"; 23].join(" ")),
            format!("{}\n  about", zeros.replace(' ', "\t")),
        ] {
            assert!(Checksum::Bip39.is_valid(&phrase), "{phrase}");
        }
        for phrase in [
            format!("{zeros} abandon"),
            format!("{zeros} abuot"),
            ["abandon"; 10].join(" ") + " about",
        ] {
            assert!(!Checksum::Bip39.is_valid(&phrase), "{phrase}");
        }
    }

    #[test]
    fn marvin32_matches_microsofts_test_vectors() {
        let seed0 = 0x004f_b61a_001b_dbcc;
        let seed2 = 0x804f_b61a_801b_dbcc;
        for (seed, data, expected) in [
            (0xd53c_d9ce_cd08_93b7, b"abc".as_slice(), 0x6be0_2a86),
            (
                0x0ddd_deee_efff_f000,
                b"abcdefghijklmnopqrstuvwxyz",
                0xd348_47dc,
            ),
            (seed0, b"", 0x3020_09bc),
            (seed0, &[175], 0x3592_e206),
            (seed0, &[231, 15], 0xfdab_5e04),
            (seed0, &[55, 244, 149], 0x6b3c_8b90),
            (seed0, &[134, 66, 220, 89], 0x0e94_07be),
            (seed0, &[171, 66, 126, 168, 209, 15, 199], 0x117f_cba5),
            (seed2, &[255, 0, 255, 0, 255, 0, 255], 0xe0c1_ffff),
        ] {
            assert_eq!(marvin32(data, seed), expected, "{data:?}");
        }
        assert_eq!(
            Marvin32Checksum::AZURE_STORAGE.seed.value(),
            0x4465_6661_756c_7430
        );
    }

    #[test]
    fn a_marvin32_key_passes_in_any_base64_form_and_a_changed_one_fails() {
        let setup = Marvin32Checksum::AZURE_STORAGE;
        let mut bytes: Vec<u8> = (1..=28).collect();
        bytes.extend_from_slice(&marvin32(&bytes, setup.seed.value()).to_le_bytes());
        for (url_safe, padded) in [(false, true), (false, false), (true, true), (true, false)] {
            let key = base64_encode(&bytes, url_safe, padded);
            assert!(Checksum::Marvin32(setup).is_valid(&key), "{key}");
            let changed = key.replacen('A', "B", 1);
            assert!(!setup.is_valid(&changed), "{changed}");
            let repaired = Checksum::Marvin32(setup).repair(&changed).unwrap();
            assert!(setup.is_valid(&repaired), "{repaired}");
            assert_eq!(repaired.len(), key.len());
            assert_eq!(Checksum::Marvin32(setup).repair(&key), Some(key));
        }
        let other = Marvin32Checksum {
            seed: Marvin32Seed(*b"MastRW00"),
        };
        assert!(!other.is_valid(&base64_encode(&bytes, false, true)));
        assert!(!setup.is_valid("AAAA"));
        assert!(!setup.is_valid("not base64!"));
    }

    #[test]
    fn a_marvin32_seed_is_written_as_its_eight_character_name() {
        let json =
            serde_json::to_string(&Checksum::Marvin32(Marvin32Checksum::AZURE_STORAGE)).unwrap();
        assert_eq!(json, r#"{"algorithm":"marvin32","seed":"Default0"}"#);
        assert_eq!(
            serde_json::from_str::<Checksum>(&json).unwrap(),
            Checksum::Marvin32(Marvin32Checksum::AZURE_STORAGE)
        );
        for seed in ["Default", "Default00", "Défaut0"] {
            let json = format!(r#"{{"algorithm":"marvin32","seed":"{seed}"}}"#);
            assert!(serde_json::from_str::<Checksum>(&json).is_err(), "{seed}");
        }
    }

    #[test]
    fn verhoeff_mod11_and_mod97_accept_known_numbers_and_reject_changed_ones() {
        for (checksum, valid, invalid) in [
            (Checksum::Verhoeff, "2363", "2364"),
            (Checksum::Verhoeff, "236 3", "236 4"),
            (Checksum::Mod11, "0-306-40615-2", "0-306-40615-3"),
            (Checksum::Mod11, "0-8044-2957-X", "0-8044-2957-9"),
            (Checksum::Mod11, "943 476 5919", "943 476 5918"),
            (
                Checksum::Mod97,
                "GB82 WEST 1234 5698 7654 32",
                "GB83 WEST 1234 5698 7654 32",
            ),
            (
                Checksum::Mod97,
                "DE89370400440532013000",
                "DE88370400440532013000",
            ),
        ] {
            assert!(checksum.is_valid(valid), "{valid}");
            assert!(!checksum.is_valid(invalid), "{invalid}");
            assert_eq!(
                checksum.repair(invalid).as_deref(),
                Some(valid),
                "{invalid}"
            );
        }
        assert!(!Checksum::Verhoeff.is_valid("2633"));
        assert!(!Checksum::Mod97.is_valid("DE89370400440532013001"));
        assert!(!Checksum::Mod11.is_valid("X"));
        assert!(!Checksum::Mod11.is_valid("12X4"));
        assert!(!Checksum::Mod97.is_valid("GB82"));
    }

    #[test]
    fn repair_rewrites_each_new_checksum_so_it_passes() {
        for (checksum, value) in [
            (
                Checksum::Bech32,
                "age1qpzry9x8gf2tvdw0s3jn54khce6mua7lqqqqqq",
            ),
            (
                Checksum::Bech32,
                "AGE-SECRET-KEY-1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQQQQQQ",
            ),
            (
                Checksum::Bech32m,
                "abcdef1l7aum6echk45nj3s0wdvt2fg8x9qqqqqq",
            ),
            (
                Checksum::Bip39,
                "apple banana cherry zebra moon sun star tree lake river hill rock",
            ),
        ] {
            let repaired = checksum.repair(value).unwrap();
            assert!(checksum.is_valid(&repaired), "{value} -> {repaired}");
        }
        assert_eq!(
            Checksum::Bech32
                .repair("AGE-SECRET-KEY-1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQQQQQQ")
                .unwrap()
                .to_ascii_uppercase(),
            Checksum::Bech32
                .repair("AGE-SECRET-KEY-1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQQQQQQ")
                .unwrap()
        );
        assert!(Checksum::Bip39.repair("only three words").is_none());
        assert!(Checksum::Bech32.repair("abc1b").is_none());
    }
}
