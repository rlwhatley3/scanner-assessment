//! The built-in rule set, seeded as the first rule set version. Every rule here is ordinary
//! data: users can edit, disable, or remove any of them. See `engine/README.md` for what each
//! rule catches, what it misses, and why.

use crate::rules::{DetectionType, RuleDefinition, Severity};

/// Known placeholder values. A match containing one of these scores as a likely example.
pub fn default_placeholders() -> Vec<String> {
    [
        "your_key_here",
        "changeme",
        "xxxx",
        "example",
        "dummy",
        "test",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

pub fn default_rules() -> Vec<RuleDefinition> {
    vec![
        RuleDefinition {
            name: Some("AWS access key".into()),
            detection_type: Some(DetectionType::DirectCredential),
            severity: Some(Severity::High),
            pattern: Some(r"\bAKIA[0-9A-Z]{16}\b".into()),
            prefix: Some("AKIA".into()),
            remediation: Some(
                "Deactivate this key in AWS IAM, create a new one, and load it from a secret \
                 manager or environment variable instead of the file."
                    .into(),
            ),
            ..RuleDefinition::default()
        },
        RuleDefinition {
            name: Some("GitHub token".into()),
            detection_type: Some(DetectionType::DirectCredential),
            severity: Some(Severity::High),
            pattern: Some(r"\bghp_[A-Za-z0-9]{36}\b".into()),
            prefix: Some("ghp_".into()),
            remediation: Some(
                "Revoke this token in GitHub settings and create a new one with only the scopes \
                 it needs."
                    .into(),
            ),
            ..RuleDefinition::default()
        },
        RuleDefinition {
            name: Some("Private key block".into()),
            detection_type: Some(DetectionType::DirectCredential),
            severity: Some(Severity::High),
            // The whole block when its END line is present; otherwise just the header, so a
            // truncated key is still caught.
            pattern: Some(
                r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)?"
                    .into(),
            ),
            prefix: Some("-----BEGIN".into()),
            remediation: Some(
                "Treat this key as compromised: replace it, revoke the old one, and keep private \
                 keys in a key store or secret manager."
                    .into(),
            ),
            ..RuleDefinition::default()
        },
        RuleDefinition {
            name: Some("Secret-looking assignment".into()),
            detection_type: Some(DetectionType::LikelyCredential),
            severity: Some(Severity::Medium),
            // A name, `=` or `:`, then a value of 8+ characters. Values starting with `$`, `{`,
            // or `(` are references like `${DB_PASS}`, not secrets, so they never match.
            pattern: Some(
                r#"(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)["']?\s*[:=]\s*["']?(?P<value>[^\s"'`,;${}()]{8,})"#
                    .into(),
            ),
            key_names: ["password", "passwd", "secret", "api_key", "apikey", "token"]
                .into_iter()
                .map(String::from)
                .collect(),
            min_entropy: Some(3.0),
            remediation: Some(
                "If this is a real secret, rotate it and load it from a secret manager or \
                 environment variable instead of the file."
                    .into(),
            ),
            ..RuleDefinition::default()
        },
        RuleDefinition {
            name: Some("Secret written to a log".into()),
            detection_type: Some(DetectionType::UnsafeHandling),
            severity: Some(Severity::Medium),
            pattern: Some(
                r"(?i)\b(?:console\.(?:log|info|warn|error|debug)|println!?|print|logger\.\w+|log\.\w+)\s*\([^)\n]*(?:password|passwd|secret|api_?key|token)"
                    .into(),
            ),
            remediation: Some(
                "Remove the secret from this log call, or log a fixed placeholder such as \
                 \"[redacted]\" instead."
                    .into(),
            ),
            ..RuleDefinition::default()
        },
    ]
}
