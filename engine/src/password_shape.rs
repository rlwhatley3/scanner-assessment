//! Judges whether a value looks like a password a person made up, from the value alone.
//!
//! Key names catch `password = …`, but a password can sit under any name (`safe_bet: "…"`).
//! Without the name, the only evidence is the value's shape: people mix in symbols, swap letters
//! for look-alike digits, tack a number on the end, use odd capitals, and reuse words like
//! "pass". Values that are clearly something else (URLs, paths, numbers, hashes, and identifiers
//! in a regular naming style) never count. The result is a score plus the signals behind it, so
//! a finding can say why without quoting the value.

use crate::scan::shannon_entropy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

/// A rule setting: keep only values that look like a human-made password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasswordShape {
    /// Points of password-like signals a value needs to count, 1 to `MAX_SCORE`. Most signals are
    /// worth 1 or 2, and a known common password scores the maximum.
    pub min_score: u8,
}

impl PasswordShape {
    pub const MAX_SCORE: u8 = 10;
}

/// Values shorter than this only count when they are a known common password.
const MIN_SHAPE_LENGTH: usize = 8;
const MIN_LENGTH: usize = 6;
/// Longer values are tokens, hashes, or prose, not something a person types as a password.
const MAX_LENGTH: usize = 64;
/// From this length, a value this random (bits per character) was generated, not typed: an API
/// key or token, which format and key-name rules are for.
const MACHINE_MADE_LENGTH: usize = 20;
const MACHINE_MADE_ENTROPY: f64 = 4.0;

/// How password-like a value is, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Assessment {
    pub score: u8,
    /// Short descriptions of the signals that fired. They never quote the value.
    pub signals: Vec<&'static str>,
}

/// A small sample of the most common breached passwords, lowercase. A value equal to one of
/// these (ignoring case) is a password no matter its shape. Plain words such as "password" or
/// "admin" are left out: as config values they are usually names (a role, a key, a resource
/// kind), not passwords.
const COMMON_PASSWORDS: &[&str] = &[
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "111111",
    "000000",
    "123123",
    "654321",
    "666666",
    "121212",
    "112233",
    "password1",
    "password12",
    "password123",
    "password!",
    "passw0rd",
    "p@ssw0rd",
    "p@ssword",
    "pa$$word",
    "qwerty1",
    "qwerty123",
    "1q2w3e4r",
    "1qaz2wsx",
    "zaq12wsx",
    "abc123",
    "abc12345",
    "abcd1234",
    "letmein1",
    "welcome1",
    "welcome123",
    "admin1",
    "admin123",
    "root123",
    "iloveyou1",
    "monkey1",
    "monkey123",
    "dragon1",
    "master1",
    "trustno1",
    "hunter2",
    "jordan23",
    "secret1",
    "secret123",
    "login123",
    "summer2023",
    "summer2024",
    "summer2025",
    "winter2023",
    "winter2024",
    "winter2025",
    "spring2024",
    "autumn2024",
    "fall2024",
    "access14",
    "temp123",
    "test1234",
    "guest123",
    "pass1234",
    "pass123",
];

/// Characters people add to passwords. `_`, `-` and `.` are left out: identifiers use them.
const SYMBOLS: &str = "!@#$%^&*?~+=";

/// Fragments people put in passwords. Matched ignoring case.
const PASSWORD_WORDS: &[&str] = &[
    "pw", "pwd", "pass", "secret", "letmein", "admin", "qwerty", "welcome", "login", "iloveyou",
    "monkey", "dragon", "trustno", "1234",
];

macro_rules! patterns {
    ($($name:ident = $pattern:literal;)*) => {
        $(static $name: LazyLock<Regex> =
            LazyLock::new(|| Regex::new($pattern).expect("built-in pattern compiles"));)*
    };
}

patterns! {
    // Not secrets.
    PATH = r"^[\w.-]+(/[\w.-]+)+/?$";
    EMAIL = r"^[^@]+@[^@]+\.[A-Za-z]{2,}$";
    UUID = r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$";
    HEX = r"^(0x)?[0-9a-fA-F]+$";
    LOWER_WORDS = r"^[a-z][a-z0-9]*([_.\-][a-z0-9]+)*$";
    UPPER_WORDS = r"^[A-Z][A-Z0-9]*([_.\-][A-Z0-9]+)*$";
    CAMEL_CASE = r"^[a-z]+([A-Z][a-z]+)+$";
    PASCAL_CASE = r"^([A-Z][a-z]+)+$";
    // Password signals.
    LOOKALIKE = r"[a-z][013457@$][a-z]";
    TRAILING_NUMBER = r"[A-Za-z]{3}\d{1,4}[!@#$%^&*?]*$";
    CAPITALS_AT_END = r"[a-z][A-Z]{3,}$";
    ALTERNATING_CASE = r"([a-z][A-Z]){2}|([A-Z][a-z]){2}[A-Z]";
}

/// Scores how much `value` looks like a human-made password. `None` when it is clearly not a
/// secret, or outside the lengths a person would type.
pub(crate) fn assess(value: &str) -> Option<Assessment> {
    let length = value.chars().count();
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) || value.chars().any(char::is_whitespace) {
        return None;
    }
    if COMMON_PASSWORDS.contains(&value.to_lowercase().as_str()) {
        return Some(Assessment {
            score: PasswordShape::MAX_SCORE,
            signals: vec!["is one of the most common passwords"],
        });
    }
    if length < MIN_SHAPE_LENGTH || is_clearly_not_a_secret(value) {
        return None;
    }
    if length >= MACHINE_MADE_LENGTH && shannon_entropy(value) >= MACHINE_MADE_ENTROPY {
        return None;
    }

    let lowercase = value.to_lowercase();
    let has_letter = value.chars().any(char::is_alphabetic);
    let has_lower = value.chars().any(char::is_lowercase);
    let has_upper = value.chars().any(char::is_uppercase);
    let has_digit = value.chars().any(|character| character.is_ascii_digit());
    let mut score = 0;
    let mut signals = Vec::new();
    let mut signal = |present: bool, points: u8, description: &'static str| {
        if present {
            score += points;
            signals.push(description);
        }
    };
    signal(
        has_letter && value.chars().any(|character| SYMBOLS.contains(character)),
        2,
        "mixes symbols into letters",
    );
    signal(
        LOOKALIKE.is_match(value),
        2,
        "swaps letters for look-alike digits or symbols",
    );
    signal(
        PASSWORD_WORDS.iter().any(|word| lowercase.contains(word)),
        2,
        "contains a word common in passwords",
    );
    signal(
        TRAILING_NUMBER.is_match(value),
        1,
        "ends in a short number, as people add to passwords",
    );
    signal(
        CAPITALS_AT_END.is_match(value) || ALTERNATING_CASE.is_match(value),
        1,
        "uses irregular capitals",
    );
    signal(
        has_lower && has_upper && has_digit,
        1,
        "mixes upper- and lowercase letters with digits",
    );
    Some(Assessment {
        score: score.min(PasswordShape::MAX_SCORE),
        signals,
    })
}

/// URLs, paths, emails, numbers, versions, hashes, template references, and identifiers in a
/// regular naming style (`snake_case`, `kebab-case`, `ALL_CAPS`, `camelCase`, `PascalCase`).
fn is_clearly_not_a_secret(value: &str) -> bool {
    let reference = value.starts_with(['$', '%']) || value.contains("{{") || value.contains("${");
    let numeric = value
        .chars()
        .all(|character| character.is_ascii_digit() || ".:-+_/,".contains(character));
    reference
        || numeric
        || value.contains("://")
        || value.starts_with(['/', '~'])
        || value.starts_with("./")
        || value.starts_with("../")
        || [
            &PATH,
            &EMAIL,
            &UUID,
            &HEX,
            &LOWER_WORDS,
            &UPPER_WORDS,
            &CAMEL_CASE,
            &PASCAL_CASE,
        ]
        .iter()
        .any(|pattern| pattern.is_match(value))
}

#[cfg(test)]
mod tests {
    use super::assess;

    fn score(value: &str) -> u8 {
        assess(value).map_or(0, |assessment| assessment.score)
    }

    #[test]
    fn made_up_passwords_score_at_least_two() {
        for value in [
            "myUnencryptedPWHERE",
            "Summer2024!",
            "Summer2024",
            "Tr0ub4dor&3",
            "s3cretSauce99",
            "c0rrectHorse",
            "MyD0g$Name",
        ] {
            assert!(score(value) >= 2, "{value} scored {}", score(value));
        }
    }

    #[test]
    fn common_passwords_score_the_maximum_even_when_short() {
        assert_eq!(score("hunter2"), 10);
        assert_eq!(score("PASSWORD123"), 10);
    }

    #[test]
    fn plain_words_are_names_not_common_passwords() {
        for value in ["password", "Secret", "admin", "default"] {
            assert_eq!(assess(value), None, "{value}");
        }
    }

    #[test]
    fn values_that_are_clearly_not_secrets_are_never_scored() {
        for value in [
            "https://auth.example.com/.well-known/jwks.json",
            "/var/lib/data",
            "src/main.rs",
            "ops@example.com",
            "2026-10-28",
            "10.0.0.12:5432",
            "1.24.3",
            "1f3a7c2e-8b4d-4e6f-9a1b-2c3d4e5f6a7b",
            "d41d8cd98f00b204e9800998ecf8427e",
            "production",
            "catalog-db",
            "us-east-1",
            "com.example.service",
            "LOG_LEVEL_DEBUG",
            "myUnencryptedFileHandler",
            "ProductionDatabase",
            "${DB_PASSWORD}",
            "{{ .Values.secret }}",
            "two words here",
        ] {
            assert_eq!(assess(value), None, "{value}");
        }
    }

    #[test]
    fn long_random_tokens_are_machine_made_not_typed() {
        // Random strings with no provider prefix, so they read as generated tokens only.
        assert_eq!(assess("zR8qLm2XvT5nKp9WdY4hJc7B"), None);
        assert_eq!(assess("Qw7Ht3Lp9Zx2Vb6Nm4Kd8Rf1"), None);
    }

    #[test]
    fn identifiers_with_digits_or_acronyms_stay_below_two() {
        for value in [
            "base64Url",
            "utf8Encoder",
            "s3Bucket",
            "myCrappyIdIMade",
            "ubuntu2204",
        ] {
            assert!(score(value) < 2, "{value} scored {}", score(value));
        }
    }

    #[test]
    fn signals_describe_the_shape_without_quoting_the_value() {
        let assessment = assess("myUnencryptedPWHERE").expect("value is scored");
        assert_eq!(
            assessment.signals,
            [
                "contains a word common in passwords",
                "uses irregular capitals"
            ]
        );
        assert!(
            assessment
                .signals
                .iter()
                .all(|signal| !signal.contains("PWHERE"))
        );
    }
}
