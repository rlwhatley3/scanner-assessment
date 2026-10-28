use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Patterns whose compiled form would be larger than this are rejected as too large.
const PATTERN_SIZE_LIMIT: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionType {
    /// A secret value is present in a known format.
    DirectCredential,
    /// A random-looking value assigned to a suspicious name, with no known format.
    LikelyCredential,
    /// Code that handles a secret unsafely; no secret value is involved.
    UnsafeHandling,
    /// Known fake values such as `changeme`. These rules never create findings of their own:
    /// a match that falls inside another rule's finding marks that finding as a likely example.
    PlaceholderVsReal,
}

impl DetectionType {
    /// Whether this rule type's matches become findings of their own.
    pub fn creates_findings(self) -> bool {
        self != DetectionType::PlaceholderVsReal
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    High,
    Medium,
    Low,
}

impl Severity {
    fn as_str(self) -> &'static str {
        match self {
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rule's definition as the rule form saves it (the `definition` JSON). Every field is
/// optional so a half-filled draft still parses and gets field-level errors instead of a
/// parse failure. Unknown fields are rejected, so a misspelled field fails loudly instead of
/// being silently ignored.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct RuleDefinition {
    pub name: Option<String>,
    /// Missing means enabled.
    pub enabled: Option<bool>,
    pub detection_type: Option<DetectionType>,
    pub severity: Option<Severity>,
    /// A regex. A named group `value` narrows the finding to the secret itself, and a named
    /// group `key` is what `key_names` is checked against.
    pub pattern: Option<String>,
    /// A public prefix every match starts with, shown as the redacted preview.
    pub prefix: Option<String>,
    /// If set, the `key` group (or the whole match) must contain one of these, ignoring case.
    pub key_names: Vec<String>,
    /// If set, the `value` group (or the whole match) needs at least this many bits of
    /// entropy per character. Range 0–8.
    pub min_entropy: Option<f64>,
    pub remediation: Option<String>,
}

impl RuleDefinition {
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }
}

/// A stored rule: its database id plus its definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: i64,
    pub definition: RuleDefinition,
}

/// What the API hands the engine for a scan: one rule set version's rules, each with its
/// definition as snapshotted into that version. Known placeholder values are rules too, of type
/// placeholder vs. real. The built-in rule set in `rule_sets/default.json` is written in exactly
/// this shape.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleField {
    Name,
    Enabled,
    DetectionType,
    Severity,
    Pattern,
    Prefix,
    KeyNames,
    MinEntropy,
    Remediation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Required,
    InvalidRegex,
    TooLarge,
    OutOfRange,
    DuplicateName,
}

/// A problem that stops a rule from running, pointing at the exact field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleError {
    pub rule_id: i64,
    pub field: RuleField,
    pub code: ErrorCode,
    pub message: String,
    /// Byte range within the field's value (e.g. the bad spot in a pattern), when known.
    pub span: Option<(usize, usize)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningCode {
    MatchesEmpty,
}

/// Worth showing the rule author, but does not stop the rule from saving or running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleWarning {
    pub rule_id: i64,
    pub field: RuleField,
    pub code: WarningCode,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RuleCheck {
    pub errors: Vec<RuleError>,
    pub warnings: Vec<RuleWarning>,
}

impl RuleCheck {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// A rule that passed its checks, ready to run.
#[derive(Debug)]
pub(crate) struct CompiledRule {
    pub id: i64,
    pub name: String,
    pub detection_type: DetectionType,
    /// Always set for rule types that create findings; placeholder rules don't need one.
    pub severity: Option<Severity>,
    pub regex: Regex,
    pub prefix: Option<String>,
    pub key_names: Vec<String>,
    pub min_entropy: Option<f64>,
    pub remediation: String,
}

/// Checks one rule on its own: required fields, ranges, and whether the pattern compiles.
pub fn check_rule(rule: &Rule) -> RuleCheck {
    check_and_compile(rule).1
}

/// Checks every rule, plus names that repeat within the set.
pub fn check_rule_set(rules: &[Rule]) -> RuleCheck {
    let mut check = RuleCheck::default();
    for rule in rules {
        let rule_check = check_rule(rule);
        check.errors.extend(rule_check.errors);
        check.warnings.extend(rule_check.warnings);
    }
    check.errors.extend(duplicate_name_errors(rules));
    check
}

/// Rules whose name repeats an earlier rule's name (ignoring case and surrounding space).
pub(crate) fn duplicate_name_errors(rules: &[Rule]) -> Vec<RuleError> {
    let mut seen = HashSet::new();
    let mut errors = Vec::new();
    for rule in rules {
        let Some(name) = rule.definition.name.as_deref().map(str::trim) else {
            continue;
        };
        if !name.is_empty() && !seen.insert(name.to_lowercase()) {
            errors.push(RuleError {
                rule_id: rule.id,
                field: RuleField::Name,
                code: ErrorCode::DuplicateName,
                message: format!("Another rule in this set is already named \"{name}\"."),
                span: None,
            });
        }
    }
    errors
}

pub(crate) fn check_and_compile(rule: &Rule) -> (Option<CompiledRule>, RuleCheck) {
    let definition = &rule.definition;
    let mut check = RuleCheck::default();
    let error = |field, code, message: &str, span| RuleError {
        rule_id: rule.id,
        field,
        code,
        message: message.to_string(),
        span,
    };

    let name = definition.name.as_deref().map(str::trim).unwrap_or("");
    if name.is_empty() {
        check.errors.push(error(
            RuleField::Name,
            ErrorCode::Required,
            "A name is required.",
            None,
        ));
    }
    if definition.detection_type.is_none() {
        check.errors.push(error(
            RuleField::DetectionType,
            ErrorCode::Required,
            "A detection type is required.",
            None,
        ));
    }
    let creates_findings = definition
        .detection_type
        .is_none_or(DetectionType::creates_findings);
    if creates_findings && definition.severity.is_none() {
        check.errors.push(error(
            RuleField::Severity,
            ErrorCode::Required,
            "A severity is required.",
            None,
        ));
    }
    if let Some(entropy) = definition.min_entropy
        && !(0.0..=8.0).contains(&entropy)
    {
        check.errors.push(error(
            RuleField::MinEntropy,
            ErrorCode::OutOfRange,
            "Minimum entropy must be between 0 and 8 bits per character.",
            None,
        ));
    }

    let pattern = definition.pattern.as_deref().unwrap_or("");
    let regex = if pattern.is_empty() {
        check.errors.push(error(
            RuleField::Pattern,
            ErrorCode::Required,
            "A pattern is required.",
            None,
        ));
        None
    } else {
        match compile_pattern(pattern) {
            Ok(regex) => Some(regex),
            Err((code, message, span)) => {
                check
                    .errors
                    .push(error(RuleField::Pattern, code, &message, span));
                None
            }
        }
    };

    if let Some(regex) = &regex
        && regex.is_match("")
    {
        check.warnings.push(RuleWarning {
            rule_id: rule.id,
            field: RuleField::Pattern,
            code: WarningCode::MatchesEmpty,
            message: "This pattern can match empty text, which can flood results.".to_string(),
        });
    }

    let compiled = match (regex, definition.detection_type) {
        (Some(regex), Some(detection_type)) if check.is_valid() => Some(CompiledRule {
            id: rule.id,
            name: name.to_string(),
            detection_type,
            severity: definition.severity,
            regex,
            prefix: definition
                .prefix
                .clone()
                .filter(|prefix| !prefix.is_empty()),
            key_names: definition
                .key_names
                .iter()
                .map(|key| key.to_lowercase())
                .filter(|key| !key.is_empty())
                .collect(),
            min_entropy: definition.min_entropy,
            remediation: definition.remediation.clone().unwrap_or_default(),
        }),
        _ => None,
    };
    (compiled, check)
}

/// Why a pattern did not compile: the error code, a message, and the bad span when known.
type PatternError = (ErrorCode, String, Option<(usize, usize)>);

/// Compiles a pattern, reporting where a syntax error is when the parser knows.
fn compile_pattern(pattern: &str) -> Result<Regex, PatternError> {
    // Parse first only to get a precise span for syntax errors; the regex crate's own error
    // carries the same message but no machine-readable position.
    if let Err(error) = regex_syntax::Parser::new().parse(pattern) {
        let (message, span) = match &error {
            regex_syntax::Error::Parse(error) => (error.kind().to_string(), Some(*error.span())),
            regex_syntax::Error::Translate(error) => {
                (error.kind().to_string(), Some(*error.span()))
            }
            _ => (error.to_string(), None),
        };
        let span = span.map(|span| (span.start.offset, span.end.offset));
        return Err((ErrorCode::InvalidRegex, message, span));
    }
    RegexBuilder::new(pattern)
        .size_limit(PATTERN_SIZE_LIMIT)
        .build()
        .map_err(|error| match error {
            regex::Error::CompiledTooBig(_) => (
                ErrorCode::TooLarge,
                "This pattern is too large to compile.".to_string(),
                None,
            ),
            error => (ErrorCode::InvalidRegex, error.to_string(), None),
        })
}
