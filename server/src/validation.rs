//! Checks a rule definition before it can join a rule set version.
//!
//! The error and warning shapes match the engine's (`rule_id`, `field`, `code`, `message`,
//! `span`), so the UI shows save-time and scan-time problems the same way. When the engine crate
//! lands, these checks should defer to its `check_rule` / `check_rule_set`.

use regex::RegexBuilder;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::HashMap;

/// The compiled-size limit for a rule's pattern.
pub const MAX_PATTERN_SIZE: usize = 1024 * 1024;

const DETECTION_TYPES: &[&str] = &[
    "direct_credential",
    "likely_credential",
    "unsafe_handling",
    "placeholder_vs_real",
];
const SEVERITIES: &[&str] = &["high", "medium", "low"];

/// A problem that stops a rule from being added to a rule set version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
pub struct RuleError {
    pub rule_id: i64,
    /// The definition field at fault, in snake_case (e.g. `pattern`, `min_entropy`).
    pub field: String,
    /// `required`, `invalid_value`, `invalid_regex`, `too_large`, `out_of_range`, or
    /// `duplicate_name`.
    pub code: String,
    pub message: String,
    /// Byte range within the field's value, when known.
    pub span: Option<(usize, usize)>,
}

/// Worth showing, but does not stop the rule from being saved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
pub struct RuleWarning {
    pub rule_id: i64,
    pub field: String,
    /// `matches_empty`.
    pub code: String,
    pub message: String,
}

#[derive(Debug, Default, Serialize, utoipa::ToSchema)]
pub struct RuleCheck {
    pub errors: Vec<RuleError>,
    pub warnings: Vec<RuleWarning>,
}

impl RuleCheck {
    fn error(&mut self, rule_id: i64, field: &str, code: &str, message: impl Into<String>) {
        self.errors.push(RuleError {
            rule_id,
            field: field.to_owned(),
            code: code.to_owned(),
            message: message.into(),
            span: None,
        });
    }
}

/// Checks one rule's definition on its own.
pub fn check_rule(rule_id: i64, definition: &Value) -> RuleCheck {
    let mut check = RuleCheck::default();
    let empty = Map::new();
    let fields = definition.as_object().unwrap_or(&empty);

    if non_empty_string(fields.get("name")).is_none() {
        check.error(rule_id, "name", "required", "Give the rule a name.");
    }
    if fields
        .get("enabled")
        .is_some_and(|enabled| !enabled.is_boolean())
    {
        check.error(
            rule_id,
            "enabled",
            "invalid_value",
            "Enabled must be true or false.",
        );
    }
    one_of(
        &mut check,
        rule_id,
        fields,
        "detectionType",
        "detection_type",
        DETECTION_TYPES,
    );
    // Placeholder rules only mark other findings as likely examples, so severity doesn't apply.
    let creates_findings =
        fields.get("detectionType").and_then(Value::as_str) != Some("placeholder_vs_real");
    if creates_findings || fields.contains_key("severity") {
        one_of(
            &mut check, rule_id, fields, "severity", "severity", SEVERITIES,
        );
    }

    match non_empty_string(fields.get("pattern")) {
        None => check.error(rule_id, "pattern", "required", "Enter a pattern to match."),
        Some(pattern) => match RegexBuilder::new(pattern)
            .size_limit(MAX_PATTERN_SIZE)
            .build()
        {
            Ok(regex) if regex.is_match("") => check.warnings.push(RuleWarning {
                rule_id,
                field: "pattern".to_owned(),
                code: "matches_empty".to_owned(),
                message: "This pattern can match empty text, which would flood results.".to_owned(),
            }),
            Ok(_) => {}
            Err(regex::Error::CompiledTooBig(_)) => check.error(
                rule_id,
                "pattern",
                "too_large",
                "This pattern is too large to compile. Simplify it or split it into two rules.",
            ),
            Err(error) => check.error(rule_id, "pattern", "invalid_regex", error.to_string()),
        },
    }

    for (key, field) in [
        ("prefix", "prefix"),
        ("remediation", "remediation"),
        ("checksum", "checksum"),
    ] {
        if fields.get(key).is_some_and(|value| !value.is_string()) {
            check.error(rule_id, field, "invalid_value", "Must be text.");
        }
    }
    if let Some(key_names) = fields.get("keyNames")
        && !key_names
            .as_array()
            .is_some_and(|names| names.iter().all(Value::is_string))
    {
        check.error(
            rule_id,
            "key_names",
            "invalid_value",
            "Must be a list of names.",
        );
    }
    if let Some(min_entropy) = fields.get("minEntropy")
        && !min_entropy
            .as_f64()
            .is_some_and(|value| (0.0..=8.0).contains(&value))
    {
        check.error(
            rule_id,
            "min_entropy",
            "out_of_range",
            "Minimum entropy must be between 0 and 8 bits per character.",
        );
    }

    check
}

/// Checks every rule, plus the checks that span rules (no two rules share a name).
pub fn check_rule_set(rules: &[(i64, Value)]) -> RuleCheck {
    let mut check = RuleCheck::default();
    let mut names: HashMap<String, i64> = HashMap::new();
    for (rule_id, definition) in rules {
        let RuleCheck { errors, warnings } = check_rule(*rule_id, definition);
        check.errors.extend(errors);
        check.warnings.extend(warnings);
        let Some(name) = non_empty_string(definition.get("name")) else {
            continue;
        };
        let first = *names.entry(name.trim().to_lowercase()).or_insert(*rule_id);
        if first != *rule_id {
            check.error(
                *rule_id,
                "name",
                "duplicate_name",
                format!("Another rule in this set (rule {first}) has the same name."),
            );
        }
    }
    check
}

fn non_empty_string(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
}

fn one_of(
    check: &mut RuleCheck,
    rule_id: i64,
    fields: &Map<String, Value>,
    key: &str,
    field: &str,
    allowed: &[&str],
) {
    match fields.get(key).and_then(Value::as_str) {
        None => check.error(rule_id, field, "required", "Choose a value."),
        Some(value) if !allowed.contains(&value) => check.error(
            rule_id,
            field,
            "invalid_value",
            format!("Must be one of: {}.", allowed.join(", ")),
        ),
        Some(_) => {}
    }
}
