use crate::checksum::Checksum;
use crate::password_shape::PasswordShape;
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
    /// A model that rates each finding's value as likely real or likely an example. Like
    /// placeholder rules, these never create findings of their own.
    ModelAssessment,
    /// A model that reads the text itself and flags spans that look like secrets, including ones
    /// no pattern describes.
    ModelDetection,
}

impl DetectionType {
    /// Whether this rule type's matches become findings of their own.
    pub fn creates_findings(self) -> bool {
        !matches!(
            self,
            DetectionType::PlaceholderVsReal | DetectionType::ModelAssessment
        )
    }

    /// Whether this rule type runs a model instead of a pattern.
    pub fn uses_model(self) -> bool {
        matches!(
            self,
            DetectionType::ModelAssessment | DetectionType::ModelDetection
        )
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
    /// For likely-credential rules, values under these names in parsed JSON, YAML, or `.env`
    /// text are checked too, even where the pattern alone would miss them.
    pub key_names: Vec<String>,
    /// If set, the `value` group (or the whole match) needs at least this many bits of
    /// entropy per character. Range 0–8.
    pub min_entropy: Option<f64>,
    /// How the token format's checksum is built, if it has one. The matched value is checked
    /// against it to tell a real-format secret from a made-up one.
    pub checksum: Option<Checksum>,
    /// If set, a value only counts when it looks like a password a person made up, scoring at
    /// least `min_score` on password-like signals. Values that are clearly not secrets (URLs,
    /// paths, numbers, regular identifiers) never count. For likely-credential rules, every
    /// parsed key/value pair is checked too, whatever its key, unless `key_names` narrows it.
    pub password_shape: Option<PasswordShape>,
    pub remediation: Option<String>,
    /// The model a model rule runs. Other rule types ignore it.
    pub model: Option<ModelRef>,
    /// For model rules: a model score (0–100) at or above this counts as a secret. Other rule
    /// types ignore it.
    pub threshold: Option<i64>,
    /// If set, a model says what each matched value is (a credential, a non-secret random
    /// string, or a placeholder), and values it doesn't rate as credentials get lower
    /// confidence. Rules with no value (unsafe handling) ignore it.
    pub value_classifier: Option<ValueClassifierSetting>,
}

/// A rule's value classifier: which model to run on its matches, and how sure the model must be
/// that a value is a credential for the match to keep its confidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct ValueClassifierSetting {
    pub model: Option<ModelRef>,
    /// 0–100: a value whose credential score is below this gets lower confidence.
    pub min_score: Option<i64>,
}

/// Which model a model rule runs. The hash is what identifies it, so a rule set version always
/// names the exact model it scanned with.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct ModelRef {
    /// A readable name for the model, used in messages.
    pub id: Option<String>,
    /// The SHA-256 of the model file, as 64 hexadecimal characters.
    pub sha256: Option<String>,
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
    Checksum,
    PasswordShape,
    Remediation,
    Model,
    Threshold,
    ValueClassifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Required,
    InvalidRegex,
    TooLarge,
    OutOfRange,
    DuplicateName,
    InvalidFormat,
    /// The rule's model was not loaded into the engine, or does not fit the rule type.
    ModelUnavailable,
    /// The rule's model failed while running.
    ModelFailed,
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

/// How a compiled rule finds things: a pattern, or a model plus its threshold.
#[derive(Debug)]
pub(crate) enum Matcher {
    Pattern(Regex),
    Model {
        sha256: String,
        label: Option<String>,
        threshold: u8,
    },
}

/// A rule's value classifier, checked and ready to run.
#[derive(Debug)]
pub(crate) struct CompiledValueClassifier {
    pub sha256: String,
    pub label: Option<String>,
    pub min_score: u8,
}

/// A rule that passed its checks, ready to run.
#[derive(Debug)]
pub(crate) struct CompiledRule {
    pub id: i64,
    pub name: String,
    pub detection_type: DetectionType,
    /// Always set for rule types that create findings; placeholder and model assessment rules
    /// don't need one.
    pub severity: Option<Severity>,
    pub matcher: Matcher,
    pub prefix: Option<String>,
    pub key_names: Vec<String>,
    pub min_entropy: Option<f64>,
    pub checksum: Option<Checksum>,
    pub password_shape: Option<PasswordShape>,
    pub value_classifier: Option<CompiledValueClassifier>,
    pub remediation: String,
}

impl CompiledRule {
    /// How far back this rule stands when another rule found the same value: 0 for most rules.
    /// A rule that judges values by password shape alone, with no key names to narrow it, is 1:
    /// it only reports values no rank-0 rule found. A detection model is 2: it only reports
    /// values no other kind of rule found, so a key a pattern knows is one finding, not two.
    pub(crate) fn fallback_rank(&self) -> u8 {
        if self.detection_type == DetectionType::ModelDetection {
            2
        } else if self.password_shape.is_some() && self.key_names.is_empty() {
            1
        } else {
            0
        }
    }
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
    if let Some((code, message)) = definition.checksum.as_ref().and_then(Checksum::setup_error) {
        check
            .errors
            .push(error(RuleField::Checksum, code, &message, None));
    }
    if let Some(shape) = definition.password_shape
        && !(1..=PasswordShape::MAX_SCORE).contains(&shape.min_score)
    {
        let message = format!(
            "The minimum password score must be between 1 and {}.",
            PasswordShape::MAX_SCORE
        );
        check.errors.push(error(
            RuleField::PasswordShape,
            ErrorCode::OutOfRange,
            &message,
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

    let value_classifier = definition
        .value_classifier
        .as_ref()
        .and_then(|setting| check_value_classifier(setting, &error, &mut check.errors));

    let uses_model = definition
        .detection_type
        .is_some_and(DetectionType::uses_model);
    let model = if uses_model {
        check_model(definition, &error, &mut check.errors)
    } else {
        None
    };

    let pattern = definition.pattern.as_deref().unwrap_or("");
    let regex = if uses_model {
        None
    } else if pattern.is_empty() {
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

    let matcher = match (regex, model) {
        (Some(regex), _) => Some(Matcher::Pattern(regex)),
        (None, Some(model)) => Some(model),
        (None, None) => None,
    };
    let compiled = match (matcher, definition.detection_type) {
        (Some(matcher), Some(detection_type)) if check.is_valid() => Some(CompiledRule {
            id: rule.id,
            name: name.to_string(),
            detection_type,
            severity: definition.severity,
            matcher,
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
            checksum: definition.checksum.clone(),
            password_shape: definition.password_shape,
            value_classifier,
            remediation: definition.remediation.clone().unwrap_or_default(),
        }),
        _ => None,
    };
    (compiled, check)
}

type ErrorFn<'a> = &'a dyn Fn(RuleField, ErrorCode, &str, Option<(usize, usize)>) -> RuleError;

/// Checks a model rule's model and threshold, returning its matcher when both are valid.
fn check_model(
    definition: &RuleDefinition,
    error: ErrorFn,
    errors: &mut Vec<RuleError>,
) -> Option<Matcher> {
    let model = check_model_ref(definition.model.as_ref(), RuleField::Model, error, errors);
    let threshold = check_score(
        definition.threshold,
        RuleField::Threshold,
        "threshold",
        error,
        errors,
    );
    let (sha256, label) = model?;
    Some(Matcher::Model {
        sha256,
        label,
        threshold: threshold?,
    })
}

/// Checks a value classifier setting: its model and minimum score.
fn check_value_classifier(
    setting: &ValueClassifierSetting,
    error: ErrorFn,
    errors: &mut Vec<RuleError>,
) -> Option<CompiledValueClassifier> {
    let model = check_model_ref(
        setting.model.as_ref(),
        RuleField::ValueClassifier,
        error,
        errors,
    );
    let min_score = check_score(
        setting.min_score,
        RuleField::ValueClassifier,
        "minimum score",
        error,
        errors,
    );
    let (sha256, label) = model?;
    Some(CompiledValueClassifier {
        sha256,
        label,
        min_score: min_score?,
    })
}

/// A model's hash (lowercased) and readable name, when the hash is present and well formed.
fn check_model_ref(
    model: Option<&ModelRef>,
    field: RuleField,
    error: ErrorFn,
    errors: &mut Vec<RuleError>,
) -> Option<(String, Option<String>)> {
    let sha256 = model
        .and_then(|model| model.sha256.as_deref())
        .map(str::trim)
        .unwrap_or("");
    if sha256.is_empty() {
        errors.push(error(
            field,
            ErrorCode::Required,
            "A model, identified by its SHA-256 hash, is required.",
            None,
        ));
        return None;
    }
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        errors.push(error(
            field,
            ErrorCode::InvalidFormat,
            "The model hash must be 64 hexadecimal characters.",
            None,
        ));
        return None;
    }
    let label = model
        .and_then(|model| model.id.as_deref())
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(String::from);
    Some((sha256.to_ascii_lowercase(), label))
}

/// A required 0–100 score, such as a threshold.
fn check_score(
    score: Option<i64>,
    field: RuleField,
    name: &str,
    error: ErrorFn,
    errors: &mut Vec<RuleError>,
) -> Option<u8> {
    let Some(score) = score else {
        let message = format!("A {name} is required.");
        errors.push(error(field, ErrorCode::Required, &message, None));
        return None;
    };
    match u8::try_from(score) {
        Ok(score) if score <= 100 => Some(score),
        _ => {
            let message = format!("The {name} must be between 0 and 100.");
            errors.push(error(field, ErrorCode::OutOfRange, &message, None));
            None
        }
    }
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
