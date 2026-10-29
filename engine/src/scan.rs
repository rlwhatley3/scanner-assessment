use crate::fingerprint::FingerprintKey;
use crate::format::{self, Format, Structure};
use crate::location::{LineIndex, Location};
use crate::models::{
    LoadedModel, ModelUse, Models, encode_value, encode_window, line_bounds, to_score,
};
use crate::password_shape;
use crate::rules::{
    CompiledRule, DetectionType, ErrorCode, Matcher, Rule, RuleError, RuleField, RuleSet, Severity,
    check_and_compile, duplicate_name_errors,
};
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;

/// Inputs larger than this are rejected before scanning.
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;

/// At most this many matches are returned; the rest are reported as truncated. A rule broad
/// enough to hit this usually needs fixing, and showing thousands of highlights helps no one.
pub const MAX_FINDINGS: usize = 200;

/// A model detection span shorter than this many bytes is dropped: a few stray bytes are noise,
/// not a secret.
pub const MIN_DETECTION_BYTES: usize = 8;

/// The most a value classifier can raise a match's confidence to: a model alone is never surer
/// than a known format.
const MAX_CLASSIFIER_CONFIDENCE: u8 = 95;

/// The confidence a match keeps when its value classifier doesn't rate the value a credential,
/// the same as commented-out code.
const NOT_A_CREDENTIAL_CONFIDENCE: u8 = 30;

// How much each piece of evidence moves a match's confidence, in log-odds. Every match starts
// even (50) and the evidence about it moves it up or down, whatever the rule's type. A weight
// of 1 moves an even match to about 73, 2 to about 88, and 3.5 to about 97.

/// The value passes the rule's checksum, which a made-up value almost never does.
const CHECKSUM_VALID: f64 = 3.5;
/// The value fails the rule's checksum, so it isn't a value of the rule's format.
const CHECKSUM_FAILED: f64 = -3.5;
/// The match starts with the format's public prefix, which ordinary text rarely does.
const DECLARED_PREFIX: f64 = 2.0;
/// The value is assigned to one of the rule's key names.
const KEY_NAME: f64 = 1.0;
/// The pattern needed text around the value, such as a header name, to match.
const REQUIRED_CONTEXT: f64 = 1.0;
/// Per unit of randomness away from halfway, where randomness is the value's entropy as a share
/// of the most a value its length can have. Spans -1.5 (no variety) to 1.5 (every character
/// differs).
const RANDOMNESS: f64 = 3.0;
/// A password shape score of 3 is about even; each point above it adds this much.
const SHAPE_PER_POINT: f64 = 0.35;
const SHAPE_EVEN_SCORE: f64 = 3.0;
/// The secret name a match mentions is code, such as a variable or an interpolation.
const NAME_IN_CODE: f64 = 1.5;
/// The secret name labels the value logged with it, such as `"password:", pw` or
/// `f"token={t}"`: the code says outright that the value is a secret.
const NAME_LABELS_A_VALUE: f64 = 1.5;
/// The secret name is a word in a message that another value comes with, such as
/// `"password reset for", user`: the value might be the secret, but the message doesn't say so.
const NAME_BESIDE_A_VALUE: f64 = 0.5;
/// The secret name is only a word in a quoted message.
const NAME_IN_MESSAGE: f64 = -2.0;
/// The matched code is commented out, so it doesn't run.
const COMMENTED_OUT: f64 = -2.5;
/// Evidence alone never makes a match certain or rules it out.
const MIN_CONFIDENCE: u8 = 1;
const MAX_CONFIDENCE: u8 = 99;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// The rule found something in the text.
    Match,
    /// The rule could not run, which makes the scan partial.
    RuleError,
}

/// Everything about a match except the matched text itself.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MatchDetails {
    pub rule_name: String,
    pub detection_type: DetectionType,
    pub severity: Severity,
    /// How likely this match is what its rule describes, 0–100, from the evidence about this
    /// match (checksum, prefix, key name, randomness, where a secret name sits). Every kind of
    /// evidence weighs the same whatever the rule's type.
    pub confidence: u8,
    /// How likely the value is a placeholder or example rather than a real secret, 0–100.
    /// Absent for unsafe handling, which has no value.
    pub placeholder_score: Option<u8>,
    /// What the rule's value classifier says the value is. Absent when the rule has none.
    pub value_class: Option<ValueClass>,
    /// What each model assessment rule concluded about the value, in rule order. These sit
    /// beside the scores above and never change them.
    pub model_assessments: Vec<ModelAssessment>,
    pub location: Location,
    /// The rule's declared prefix plus an ellipsis, never taken from the match.
    pub redacted_preview: Option<String>,
    /// Explains the scores from signals only; never quotes the input.
    pub why_flagged: String,
    pub remediation: String,
    /// Findings whose ranges overlap share a group id, so callers draw them as one highlight.
    pub overlap_group: Option<u32>,
    /// Whether the match sits inside a comment, where examples and dead code usually live.
    pub in_comment: bool,
    /// Whether the value passed the rule's checksum; absent when the rule has none.
    pub checksum_valid: Option<bool>,
}

/// What a value classifier says a matched value is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueLabel {
    Credential,
    /// A random-looking string that isn't secret, such as a hash, ID, or encoded data.
    NonSecret,
    Placeholder,
}

/// A value classifier's scores (0–100, summing to about 100) and the class that scored highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValueClass {
    pub label: ValueLabel,
    pub credential: u8,
    pub non_secret: u8,
    pub placeholder: u8,
}

/// What a model assessment rule concluded about a finding's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelVerdict {
    LikelyReal,
    LikelyExample,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelAssessment {
    pub rule_id: i64,
    pub rule_name: String,
    /// How likely the model rates the value as a real secret, 0–100.
    pub score: u8,
    /// Likely real when the score is at or above the rule's threshold.
    pub verdict: ModelVerdict,
}

/// The machine-readable details of a finding: match details or the rule error.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Violation {
    Match(MatchDetails),
    RuleError(RuleError),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub rule_id: i64,
    pub kind: FindingKind,
    pub violation: Violation,
    /// A one-line human-readable summary.
    pub violation_pretty: String,
    /// Keyed Argon2id of the matched value under the caller's [`FingerprintKey`], so a later scan
    /// can recognize the same value without anyone storing it. Absent for rule errors and when
    /// the caller passed no key. Kept out of `violation`, so it is never shown as a detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// A log line about one scan. It never contains the scanned text or a matched value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEvent {
    pub scan_id: i64,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    /// Matches in text order, then rule errors.
    pub findings: Vec<Finding>,
    /// True when there were more than `MAX_FINDINGS` matches and the rest were dropped.
    pub truncated: bool,
    /// The format the text was read as.
    pub format: Format,
    pub log: Vec<LogEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    Empty,
    TooLarge { bytes: usize },
    NoRulesEnabled,
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Empty => f.write_str("There is no text to scan."),
            ScanError::TooLarge { bytes } => write!(
                f,
                "The text is {bytes} bytes; the limit is {MAX_INPUT_BYTES} bytes (1 MB)."
            ),
            ScanError::NoRulesEnabled => f.write_str("No rules are enabled in this rule set."),
        }
    }
}

impl std::error::Error for ScanError {}

struct Candidate<'r> {
    rule: &'r CompiledRule,
    start: usize,
    end: usize,
    entropy: Option<f64>,
    /// The most entropy a value this long can have: log2 of its length, reached when every
    /// character differs.
    max_entropy: f64,
    checksum_valid: Option<bool>,
    /// How password-like the value is, for rules with a password shape setting.
    shape: Option<password_shape::Assessment>,
    /// Whether the match starts with the rule's declared prefix.
    has_prefix: bool,
    /// Whether the pattern needed fixed syntax around the value to match, such as a header name.
    /// A name the value is assigned to doesn't count; key names weigh that.
    in_context: bool,
    /// For a match with no value, where the secret name in its `key` group sits.
    name_use: Option<NameUse>,
    placeholder_hit: bool,
    in_comment: bool,
    /// The model's score, for a model detection finding.
    model_score: Option<u8>,
    /// Each model assessment rule that scored the value, with its score.
    assessments: Vec<(&'r CompiledRule, u8)>,
    /// What the rule's value classifier says the value is.
    value_class: Option<ValueClass>,
}

/// What a scan runs with besides the text and the rules.
#[derive(Clone, Copy, Default)]
pub struct ScanOptions<'a> {
    /// Models for model rules to run. None runs every model rule as a rule error.
    pub models: Option<&'a Models>,
    /// Fingerprints each match's value with this key. None leaves findings without one.
    pub fingerprint_key: Option<&'a FingerprintKey>,
}

/// Scans `text` with the enabled rules. Rules that fail their checks are skipped and reported
/// as rule-error findings; the rest still run. Model rules need [`scan_with_models`].
pub fn scan(scan_id: i64, text: &str, rule_set: &RuleSet) -> Result<ScanResult, ScanError> {
    scan_with_options(scan_id, text, rule_set, ScanOptions::default())
}

/// Like [`scan`], with models for model rules to run. A model rule whose model is missing, does
/// not fit its rule type, or fails while running is reported as a rule error, and the rest of
/// the scan still runs.
pub fn scan_with_models(
    scan_id: i64,
    text: &str,
    rule_set: &RuleSet,
    models: &Models,
) -> Result<ScanResult, ScanError> {
    let options = ScanOptions {
        models: Some(models),
        ..ScanOptions::default()
    };
    scan_with_options(scan_id, text, rule_set, options)
}

/// Like [`scan_with_models`], with every option. With a fingerprint key, each match carries a
/// keyed hash of its value, computed here because this is the only place the value exists.
pub fn scan_with_options(
    scan_id: i64,
    text: &str,
    rule_set: &RuleSet,
    options: ScanOptions,
) -> Result<ScanResult, ScanError> {
    let no_models = Models::default();
    let models = options.models.unwrap_or(&no_models);
    if text.trim().is_empty() {
        return Err(ScanError::Empty);
    }
    if text.len() > MAX_INPUT_BYTES {
        return Err(ScanError::TooLarge { bytes: text.len() });
    }
    let enabled: Vec<Rule> = rule_set
        .rules
        .iter()
        .filter(|rule| rule.definition.is_enabled())
        .cloned()
        .collect();
    // Placeholder and model assessment rules only adjust other findings, so on their own
    // nothing can be found.
    let only_adjusting_rules = enabled.iter().all(|rule| {
        rule.definition
            .detection_type
            .is_some_and(|detection_type| !detection_type.creates_findings())
    });
    if only_adjusting_rules {
        return Err(ScanError::NoRulesEnabled);
    }

    let mut log = Vec::new();
    let mut log_line = |message: String| log.push(LogEvent { scan_id, message });

    let mut rule_errors = duplicate_name_errors(&enabled);
    let mut compiled = Vec::new();
    for rule in &enabled {
        let (rule_compiled, check) = check_and_compile(rule);
        rule_errors.extend(check.errors);
        if let Some(rule_compiled) = rule_compiled
            && !rule_errors.iter().any(|error| error.rule_id == rule.id)
        {
            compiled.push(rule_compiled);
        }
    }
    let mut runnable = Vec::new();
    for rule in compiled {
        match (rule_model(&rule, models), rule_value_model(&rule, models)) {
            (Ok(model), Ok(value_model)) => runnable.push((rule, model, value_model)),
            (Err(error), _) | (_, Err(error)) => rule_errors.push(error),
        }
    }
    log_line(format!(
        "{} of {} enabled rules ran; {} rule errors",
        runnable.len(),
        enabled.len(),
        rule_errors.len()
    ));

    let structure = format::parse(text);
    log_line(format!(
        "read as {:?} with {} key/value pairs",
        structure.format,
        structure.pairs.len()
    ));

    let mut placeholder_ranges = Vec::new();
    let mut candidates = Vec::new();
    let mut assessors = Vec::new();
    for (rule, model, _) in &runnable {
        let creates_findings = rule.detection_type.creates_findings();
        match (&rule.matcher, model) {
            (Matcher::Pattern(regex), _) if creates_findings => {
                candidates.extend(find_candidates(rule, regex, text, &structure));
            }
            (Matcher::Pattern(regex), _) => placeholder_ranges.extend(
                regex
                    .find_iter(text)
                    .filter(|found| !found.is_empty())
                    .map(|found| (found.start(), found.end())),
            ),
            (Matcher::Model { threshold, .. }, Some(model)) if creates_findings => {
                match detect(rule, *threshold, model, text) {
                    Ok(found) => candidates.extend(found),
                    Err(error) => rule_errors.push(error),
                }
            }
            (Matcher::Model { .. }, Some(model)) => assessors.push((rule, *model)),
            // `rule_model` always finds a model for a model rule that runs.
            (Matcher::Model { .. }, None) => {}
        }
    }
    candidates.sort_by_key(|candidate| (candidate.start, candidate.end, candidate.rule.id));
    // A value found both by a rule's pattern and by parsing is one finding.
    candidates.dedup_by(|a, b| (a.rule.id, a.start, a.end) == (b.rule.id, b.start, b.end));
    // Shape-only rules are a fallback, so they don't repeat a value another rule reported.
    let reported: Vec<(usize, usize)> = candidates
        .iter()
        .filter(|candidate| !candidate.rule.is_shape_fallback())
        .map(|candidate| (candidate.start, candidate.end))
        .collect();
    candidates.retain(|candidate| {
        !candidate.rule.is_shape_fallback()
            || !reported
                .iter()
                .any(|&(start, end)| start < candidate.end && candidate.start < end)
    });
    for candidate in &mut candidates {
        candidate.placeholder_hit = placeholder_ranges
            .iter()
            .any(|&(start, end)| candidate.start <= start && end <= candidate.end);
        candidate.in_comment = structure.in_comment(candidate.start, candidate.end);
    }

    let truncated = candidates.len() > MAX_FINDINGS;
    if truncated {
        log_line(format!(
            "found {} matches; kept the first {MAX_FINDINGS}",
            candidates.len()
        ));
        candidates.truncate(MAX_FINDINGS);
    }

    // Classify only the matches that are kept, each value once per model. A classifier that
    // fails makes its rule a rule error, so none of that rule's matches are reported.
    let value_models: HashMap<i64, &LoadedModel> = runnable
        .iter()
        .filter_map(|(rule, _, value_model)| value_model.map(|model| (rule.id, model)))
        .collect();
    let mut classified: HashMap<(usize, usize, &str), ValueClass> = HashMap::new();
    let mut failed = Vec::new();
    for candidate in &mut candidates {
        let rule = candidate.rule;
        let (Some(setting), Some(model)) = (&rule.value_classifier, value_models.get(&rule.id))
        else {
            continue;
        };
        if candidate.entropy.is_none() || failed.contains(&rule.id) {
            continue;
        }
        let key = (candidate.start, candidate.end, setting.sha256.as_str());
        let class = match classified.get(&key) {
            Some(class) => Some(*class),
            None => classify(model, text, candidate.start, candidate.end),
        };
        match class {
            Some(class) => {
                classified.insert(key, class);
                candidate.value_class = Some(class);
            }
            None => failed.push(rule.id),
        }
    }
    if !failed.is_empty() {
        candidates.retain(|candidate| !failed.contains(&candidate.rule.id));
        rule_errors.extend(
            failed
                .into_iter()
                .map(|rule_id| model_failed(rule_id, RuleField::ValueClassifier)),
        );
    }

    // Assess only the matches that are kept, so a flood of matches can't multiply model runs.
    for (rule, model) in assessors {
        match assess(rule, model, text, &candidates) {
            Ok(scores) => {
                for (candidate, score) in candidates.iter_mut().zip(scores) {
                    if let Some(score) = score {
                        candidate.assessments.push((rule, score));
                    }
                }
            }
            Err(error) => rule_errors.push(error),
        }
    }

    let groups = overlap_groups(&candidates);
    let index = LineIndex::new(text);
    let mut findings = Vec::new();
    // A fingerprint is deliberately slow, so a value found more than once is hashed once.
    let mut fingerprints: HashMap<&str, String> = HashMap::new();
    for (candidate, overlap_group) in candidates.iter().zip(groups) {
        let details = match_details(candidate, &index, overlap_group);
        let pretty = format!(
            "{} ({}) at line {}, column {}",
            details.rule_name,
            details.severity,
            details.location.start_line,
            details.location.start_column
        );
        log_line(format!(
            "rule {} matched at line {}, column {}{}",
            candidate.rule.id,
            details.location.start_line,
            details.location.start_column,
            details
                .redacted_preview
                .as_deref()
                .map(|preview| format!(", preview {preview}"))
                .unwrap_or_default()
        ));
        findings.push(Finding {
            rule_id: candidate.rule.id,
            kind: FindingKind::Match,
            violation: Violation::Match(details),
            violation_pretty: pretty,
            fingerprint: options.fingerprint_key.map(|key| {
                let value = &text[candidate.start..candidate.end];
                fingerprints
                    .entry(value)
                    .or_insert_with(|| key.fingerprint(value.as_bytes()))
                    .clone()
            }),
        });
    }
    for error in rule_errors {
        let name = enabled
            .iter()
            .find(|rule| rule.id == error.rule_id)
            .and_then(|rule| rule.definition.name.as_deref())
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map_or_else(|| format!("Rule {}", error.rule_id), String::from);
        log_line(format!(
            "rule {} could not run: {:?} in {:?}",
            error.rule_id, error.code, error.field
        ));
        findings.push(Finding {
            rule_id: error.rule_id,
            kind: FindingKind::RuleError,
            violation_pretty: format!("{name}: {}", error.message),
            violation: Violation::RuleError(error),
            fingerprint: None,
        });
    }

    Ok(ScanResult {
        findings,
        truncated,
        format: structure.format,
        log,
    })
}

fn find_candidates<'r>(
    rule: &'r CompiledRule,
    regex: &Regex,
    text: &str,
    structure: &Structure,
) -> Vec<Candidate<'r>> {
    let mut candidates = Vec::new();
    for captures in regex.captures_iter(text) {
        let whole = captures.get(0).expect("group 0 always matches");
        let value = captures.name("value").unwrap_or(whole);
        if value.is_empty() {
            continue;
        }
        if !rule.key_names.is_empty() {
            let key = captures
                .name("key")
                .unwrap_or(whole)
                .as_str()
                .to_lowercase();
            if !rule
                .key_names
                .iter()
                .any(|name| key.contains(name.as_str()))
            {
                continue;
            }
        }
        let found = Found {
            value: (value.start(), value.end()),
            whole: (whole.start(), whole.end()),
            secret_name: captures.name("key").map(|key| (key.start(), key.end())),
        };
        candidates.extend(candidate(rule, text, found));
    }

    // Parsed key/value pairs catch values the pattern can't, such as quoted values containing
    // `$` or `;`, and keys and values split across lines in JSON. A password shape rule checks
    // every pair, since a password can sit under any name; its shape check does the filtering.
    let shape_only = rule.password_shape.is_some() && rule.key_names.is_empty();
    if rule.detection_type == DetectionType::LikelyCredential
        && (!rule.key_names.is_empty() || shape_only)
    {
        let min_length = if rule.password_shape.is_some() { 6 } else { 8 };
        for pair in &structure.pairs {
            let key = text[pair.key.0..pair.key.1].to_lowercase();
            let value = &text[pair.value.0..pair.value.1];
            let suspicious = shape_only
                || rule
                    .key_names
                    .iter()
                    .any(|name| key.contains(name.as_str()));
            let reference = value.starts_with(['$', '{', '(']);
            if suspicious && !reference && value.chars().count() >= min_length {
                let found = Found {
                    value: pair.value,
                    whole: pair.value,
                    secret_name: None,
                };
                candidates.extend(candidate(rule, text, found));
            }
        }
    }
    candidates
}

/// Where a pattern matched, as byte ranges into the text.
struct Found {
    /// The `value` group, or the whole match without one.
    value: (usize, usize),
    whole: (usize, usize),
    /// The `key` group, if the pattern has one.
    secret_name: Option<(usize, usize)>,
}

/// A candidate for the found value, unless it falls short of the rule's entropy or password
/// shape.
fn candidate<'r>(rule: &'r CompiledRule, text: &str, found: Found) -> Option<Candidate<'r>> {
    let (start, end) = found.value;
    let value = &text[start..end];
    let entropy =
        (rule.detection_type != DetectionType::UnsafeHandling).then(|| shannon_entropy(value));
    if let (Some(minimum), Some(entropy)) = (rule.min_entropy, entropy)
        && entropy < minimum
    {
        return None;
    }
    let shape = match rule.password_shape {
        Some(setting) => {
            let assessment = password_shape::assess(value)?;
            if assessment.score < setting.min_score {
                return None;
            }
            Some(assessment)
        }
        None => None,
    };
    Some(Candidate {
        rule,
        start,
        end,
        entropy,
        max_entropy: max_entropy(value),
        checksum_valid: rule.checksum.map(|checksum| checksum.is_valid(value)),
        shape,
        has_prefix: rule.prefix.as_deref().is_some_and(|prefix| {
            text[found.whole.0..].starts_with(prefix) || value.starts_with(prefix)
        }),
        in_context: found.whole != found.value
            && found.secret_name.is_none()
            && rule.key_names.is_empty(),
        name_use: found
            .secret_name
            .filter(|_| entropy.is_none())
            .map(|(name_start, name_end)| name_use(text, name_start, name_end)),
        // Both set once every rule has run and the text has been parsed.
        placeholder_hit: false,
        in_comment: false,
        model_score: None,
        assessments: Vec::new(),
        value_class: None,
    })
}

/// The model a model rule runs, checked against what its rule type needs: an assessment
/// returns one score for a value, a detection one score per byte of its window. Rules without
/// a model get `None`.
fn rule_model<'m>(
    rule: &CompiledRule,
    models: &'m Models,
) -> Result<Option<&'m LoadedModel>, RuleError> {
    let Matcher::Model { sha256, label, .. } = &rule.matcher else {
        return Ok(None);
    };
    let unavailable = |message: String| RuleError {
        rule_id: rule.id,
        field: RuleField::Model,
        code: ErrorCode::ModelUnavailable,
        message,
        span: None,
    };
    let name = label
        .clone()
        .unwrap_or_else(|| format!("{}…", &sha256[..12]));
    let Some(model) = models.get(sha256) else {
        return Err(unavailable(if cfg!(feature = "ml") {
            format!("The model {name} was not loaded into the engine.")
        } else {
            "This engine was built without model support.".to_string()
        }));
    };
    let model_use = if rule.detection_type == DetectionType::ModelDetection {
        ModelUse::ModelDetection
    } else {
        ModelUse::ModelAssessment
    };
    if !model.fits(model_use) {
        return Err(unavailable(
            if rule.detection_type == DetectionType::ModelDetection {
                format!(
                    "The model {name} must return one score per input position to detect secrets."
                )
            } else {
                format!(
                    "The model {name} must return a single score, and have room for a value, to \
                     assess findings."
                )
            },
        ));
    }
    Ok(Some(model))
}

/// The model a rule's value classifier setting runs, if it has one, checked to return one score
/// per class.
fn rule_value_model<'m>(
    rule: &CompiledRule,
    models: &'m Models,
) -> Result<Option<&'m LoadedModel>, RuleError> {
    let Some(setting) = &rule.value_classifier else {
        return Ok(None);
    };
    let unavailable = |message: String| RuleError {
        rule_id: rule.id,
        field: RuleField::ValueClassifier,
        code: ErrorCode::ModelUnavailable,
        message,
        span: None,
    };
    let name = setting
        .label
        .clone()
        .unwrap_or_else(|| format!("{}…", &setting.sha256[..12]));
    let Some(model) = models.get(&setting.sha256) else {
        return Err(unavailable(if cfg!(feature = "ml") {
            format!("The value classifier model {name} was not loaded into the engine.")
        } else {
            "This engine was built without model support.".to_string()
        }));
    };
    if !model.fits(ModelUse::ValueClassifier) {
        return Err(unavailable(format!(
            "The model {name} must return three scores (credential, non-secret, placeholder) to \
             classify values."
        )));
    }
    Ok(Some(model))
}

/// What a value classifier says the value at `start..end` is, or `None` if the model failed.
/// The model sees only the value's own line, so the name it's assigned to counts but other lines
/// don't.
fn classify(model: &LoadedModel, text: &str, start: usize, end: usize) -> Option<ValueClass> {
    let (line_start, line_end) = line_bounds(text.as_bytes(), start, end);
    let line = &text.as_bytes()[line_start..line_end];
    let ids = encode_value(
        line,
        start - line_start,
        end - line_start,
        model.input_len(),
    );
    let output = model.run(&ids).ok()?;
    let &[credential, non_secret, placeholder] = output.as_slice() else {
        return None;
    };
    let (credential, non_secret, placeholder) = (
        to_score(credential),
        to_score(non_secret),
        to_score(placeholder),
    );
    // The highest score wins; on a tie, the earlier class in this order.
    let label = if credential >= non_secret && credential >= placeholder {
        ValueLabel::Credential
    } else if non_secret >= placeholder {
        ValueLabel::NonSecret
    } else {
        ValueLabel::Placeholder
    };
    Some(ValueClass {
        label,
        credential,
        non_secret,
        placeholder,
    })
}

fn model_failed(rule_id: i64, field: RuleField) -> RuleError {
    RuleError {
        rule_id,
        field,
        code: ErrorCode::ModelFailed,
        message: "The model failed while running.".to_string(),
        span: None,
    }
}

/// Runs a detection model over the text in overlapping windows (each starts half a window after
/// the last) and turns every run of bytes scoring at or above the threshold into a candidate.
/// Each byte keeps the highest score any window gave it, and spans widen to whole characters.
fn detect<'r>(
    rule: &'r CompiledRule,
    threshold: u8,
    model: &LoadedModel,
    text: &str,
) -> Result<Vec<Candidate<'r>>, RuleError> {
    let bytes = text.as_bytes();
    let window = model.input_len();
    let stride = (window / 2).max(1);
    let mut scores = vec![0_u8; bytes.len()];
    let mut start = 0;
    loop {
        let end = (start + window).min(bytes.len());
        let output = model
            .run(&encode_window(&bytes[start..end], window))
            .map_err(|()| model_failed(rule.id, RuleField::Model))?;
        for (score, &probability) in scores[start..end].iter_mut().zip(&output) {
            *score = (*score).max(to_score(probability));
        }
        if end == bytes.len() {
            break;
        }
        start += stride;
    }

    let mut candidates = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if scores[index] < threshold {
            index += 1;
            continue;
        }
        let run_start = index;
        while index < bytes.len() && scores[index] >= threshold {
            index += 1;
        }
        let start = text.floor_char_boundary(run_start);
        let end = text.ceil_char_boundary(index);
        if end - start < MIN_DETECTION_BYTES {
            continue;
        }
        candidates.push(Candidate {
            rule,
            start,
            end,
            entropy: Some(shannon_entropy(&text[start..end])),
            max_entropy: max_entropy(&text[start..end]),
            checksum_valid: None,
            shape: None,
            has_prefix: false,
            in_context: false,
            name_use: None,
            // Both set once every rule has run and the text has been parsed.
            placeholder_hit: false,
            in_comment: false,
            model_score: scores[run_start..index].iter().max().copied(),
            assessments: Vec::new(),
            value_class: None,
        });
    }
    Ok(candidates)
}

/// Scores each candidate's value with a model assessment rule. Candidates with no value
/// (unsafe handling) get no score.
fn assess(
    rule: &CompiledRule,
    model: &LoadedModel,
    text: &str,
    candidates: &[Candidate],
) -> Result<Vec<Option<u8>>, RuleError> {
    candidates
        .iter()
        .map(|candidate| {
            if candidate.entropy.is_none() {
                return Ok(None);
            }
            let ids = encode_value(
                text.as_bytes(),
                candidate.start,
                candidate.end,
                model.input_len(),
            );
            let output = model
                .run(&ids)
                .map_err(|()| model_failed(rule.id, RuleField::Model))?;
            Ok(output.first().copied().map(to_score))
        })
        .collect()
}

fn threshold(rule: &CompiledRule) -> u8 {
    match rule.matcher {
        Matcher::Model { threshold, .. } => threshold,
        Matcher::Pattern(_) => 0,
    }
}

/// Gives every run of overlapping candidates (sorted by start) a shared group id, numbered from
/// 1 in text order. Candidates that overlap nothing get no group.
fn overlap_groups(candidates: &[Candidate]) -> Vec<Option<u32>> {
    let mut groups = vec![None; candidates.len()];
    let mut next_group = 1;
    let mut run_start = 0;
    let mut run_end = 0;
    for index in 0..=candidates.len() {
        let continues = candidates
            .get(index)
            .is_some_and(|candidate| index > run_start && candidate.start < run_end);
        if continues {
            run_end = run_end.max(candidates[index].end);
            continue;
        }
        if index - run_start > 1 {
            groups[run_start..index].fill(Some(next_group));
            next_group += 1;
        }
        if let Some(candidate) = candidates.get(index) {
            run_start = index;
            run_end = candidate.end;
        }
    }
    groups
}

fn match_details(
    candidate: &Candidate,
    index: &LineIndex,
    overlap_group: Option<u32>,
) -> MatchDetails {
    let rule = candidate.rule;
    // Signals that a value is an example rather than a real secret. A known placeholder value is
    // the strongest; the others each make an example likely.
    let example_signals: Vec<&str> = [
        (
            candidate.placeholder_hit,
            "contains a known placeholder value",
        ),
        (
            // Under 2 bits per character, and under two thirds of what a value this long can
            // have, so a short value isn't an example just because it's short. From 8
            // characters on, the second limit is never the lower one.
            candidate
                .entropy
                .is_some_and(|entropy| entropy < 2.0_f64.min(candidate.max_entropy * 2.0 / 3.0)),
            "very little randomness",
        ),
        (
            candidate.checksum_valid == Some(false),
            "its checksum doesn't match, so it's likely made up",
        ),
        (candidate.in_comment, "it's in a comment"),
        (
            candidate
                .value_class
                .is_some_and(|class| class.label == ValueLabel::Placeholder),
            "the value classifier rates it a placeholder",
        ),
    ]
    .into_iter()
    .filter_map(|(present, signal)| present.then_some(signal))
    .collect();
    let placeholder_score = candidate.entropy.map(|_| {
        if candidate.placeholder_hit {
            95
        } else if !example_signals.is_empty() {
            70
        } else {
            5
        }
    });
    let (mut confidence, mut why) = match candidate.model_score {
        // A detection model's score is already its judgment of this span.
        Some(score) => (
            score,
            format!(
                "Flagged by the {} model (score {score}, threshold {}).",
                rule.name,
                threshold(rule)
            ),
        ),
        None => {
            let evidence = evidence(candidate);
            let total: f64 = evidence.iter().map(|(weight, _)| weight).sum();
            let what = if candidate.entropy.is_some() {
                "format"
            } else {
                "pattern"
            };
            let mut why = format!("Matches the {} {what}", rule.name);
            if evidence.is_empty() {
                why.push_str("; nothing else about this match raises or lowers confidence.");
            } else {
                let reasons: Vec<&str> =
                    evidence.iter().map(|(_, reason)| reason.as_str()).collect();
                why.push_str(&format!(": {}.", reasons.join("; ")));
            }
            (to_confidence(total), why)
        }
    };
    if placeholder_score.is_some() {
        if example_signals.is_empty() {
            why.push_str(" Does not look like a placeholder.");
        } else {
            why.push_str(&format!(
                " Looks like an example: {}.",
                example_signals.join("; ")
            ));
        }
    }
    if let (Some(class), Some(setting)) = (candidate.value_class, &rule.value_classifier) {
        if class.credential < setting.min_score {
            confidence = confidence.min(NOT_A_CREDENTIAL_CONFIDENCE);
            let looks_like = match class.label {
                ValueLabel::NonSecret => {
                    "; it looks more like a non-secret string such as a hash or ID"
                }
                ValueLabel::Placeholder => "; it looks more like a placeholder",
                ValueLabel::Credential => "",
            };
            why.push_str(&format!(
                " The value classifier doesn't rate it a credential (score {}, minimum {}){looks_like}.",
                class.credential, setting.min_score
            ));
        } else if class.credential > confidence && confidence < MAX_CLASSIFIER_CONFIDENCE {
            // Halfway from the rule's confidence to the classifier's score.
            let raised =
                (confidence + (class.credential - confidence) / 2).min(MAX_CLASSIFIER_CONFIDENCE);
            why.push_str(&format!(
                " The value classifier rates it a credential (score {}), raising confidence from \
                 {confidence} to {raised}.",
                class.credential
            ));
            confidence = raised;
        } else {
            why.push_str(&format!(
                " The value classifier rates it a credential (score {}).",
                class.credential
            ));
        }
    }
    let mut model_assessments = Vec::new();
    for &(assessor, score) in &candidate.assessments {
        let threshold = threshold(assessor);
        let (verdict, label) = if score >= threshold {
            (ModelVerdict::LikelyReal, "likely real")
        } else {
            (ModelVerdict::LikelyExample, "likely an example")
        };
        why.push_str(&format!(
            " The {} model rates it {label} (score {score}, threshold {threshold}).",
            assessor.name
        ));
        model_assessments.push(ModelAssessment {
            rule_id: assessor.id,
            rule_name: assessor.name.clone(),
            score,
            verdict,
        });
    }

    MatchDetails {
        rule_name: rule.name.clone(),
        detection_type: rule.detection_type,
        severity: rule
            .severity
            .expect("rules that create findings always have a severity"),
        confidence,
        placeholder_score,
        value_class: candidate.value_class,
        model_assessments,
        location: index.location(candidate.start, candidate.end),
        redacted_preview: rule.prefix.as_ref().map(|prefix| format!("{prefix}…")),
        why_flagged: why,
        remediation: rule.remediation.clone(),
        overlap_group,
        in_comment: candidate.in_comment,
        checksum_valid: candidate.checksum_valid,
    }
}

/// The evidence about a match, as (weight, reason) pairs. Each rule type has its own kinds of
/// evidence available (a match with no value has no entropy, for example), but every kind
/// weighs the same whichever rule found it.
fn evidence(candidate: &Candidate) -> Vec<(f64, String)> {
    let rule = candidate.rule;
    let mut evidence = Vec::new();
    match candidate.checksum_valid {
        Some(true) => evidence.push((CHECKSUM_VALID, "its checksum is valid".to_string())),
        Some(false) => evidence.push((CHECKSUM_FAILED, "its checksum doesn't match".to_string())),
        None => {}
    }
    if candidate.has_prefix {
        evidence.push((
            DECLARED_PREFIX,
            "it starts with the format's prefix".to_string(),
        ));
    }
    if !rule.key_names.is_empty() {
        evidence.push((
            KEY_NAME,
            "it's assigned to a name that suggests a secret".to_string(),
        ));
    }
    if candidate.in_context {
        evidence.push((
            REQUIRED_CONTEXT,
            "it sits in the syntax the rule looks for".to_string(),
        ));
    }
    if let Some(shape) = &candidate.shape {
        // A password a person made up isn't random, so its shape stands in for entropy.
        evidence.push((
            (f64::from(shape.score) - SHAPE_EVEN_SCORE) * SHAPE_PER_POINT,
            format!(
                "it looks like a password a person made up (shape score {}: it {}){}",
                shape.score,
                shape.signals.join(", "),
                if rule.key_names.is_empty() {
                    ", though its name doesn't suggest a secret"
                } else {
                    ""
                }
            ),
        ));
    } else if let Some(entropy) = candidate.entropy {
        // Judged against the most a value this long can have, since a short value can't reach
        // a long one's entropy however random it is.
        let randomness = if candidate.max_entropy > 0.0 {
            (entropy / candidate.max_entropy).min(1.0)
        } else {
            0.0
        };
        let how = if randomness >= 0.75 {
            "highly random"
        } else if randomness >= 0.4 {
            "somewhat random"
        } else {
            "barely random"
        };
        let mut reason = format!(
            "it's {how} ({entropy:.1} of a possible {:.1} bits per character for its length",
            candidate.max_entropy
        );
        if let Some(minimum) = rule.min_entropy {
            reason.push_str(&format!(", threshold {minimum:.1}"));
        }
        reason.push(')');
        evidence.push(((randomness - 0.5) * RANDOMNESS, reason));
    }
    // Evidence for a match with no value: code that mishandles a secret.
    if candidate.entropy.is_none() {
        if let Some(name_use) = candidate.name_use {
            evidence.push(match name_use {
                NameUse::Code => (
                    NAME_IN_CODE,
                    "the secret name it mentions is code, not just a word in a message".to_string(),
                ),
                NameUse::Label => (
                    NAME_LABELS_A_VALUE,
                    "the secret name it mentions labels the value it logs".to_string(),
                ),
                NameUse::Beside => (
                    NAME_BESIDE_A_VALUE,
                    "the secret name it mentions is a word in a message logged with another value"
                        .to_string(),
                ),
                NameUse::Message => (
                    NAME_IN_MESSAGE,
                    "the secret name it mentions is only a word in a quoted message".to_string(),
                ),
            });
        }
        if candidate.in_comment {
            evidence.push((
                COMMENTED_OUT,
                "it's commented out, so it doesn't run".to_string(),
            ));
        }
    }
    evidence
}

/// Turns summed log-odds evidence into a 0–100 confidence.
fn to_confidence(total: f64) -> u8 {
    let probability = 1.0 / (1.0 + (-total).exp());
    ((probability * 100.0).round() as u8).clamp(MIN_CONFIDENCE, MAX_CONFIDENCE)
}

/// Where a secret name sits in a line of code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameUse {
    /// Outside any string, or inside an interpolation such as `{token}` or `${token}`.
    Code,
    /// A label for the value logged with it: in a string that ends right after the name, apart
    /// from separators and placeholders, with a value following the string or interpolated in
    /// it, such as `"password:", pw`, `"token=%s" % t`, or `f"secret: {s}"`.
    Label,
    /// A word in a longer message that another value follows, such as
    /// `"password reset for", user`.
    Beside,
    /// Only inside a quoted message, such as `"token refresh scheduled"`.
    Message,
}

/// Tracks whether a scan through a line is inside a quoted string, and inside an interpolation
/// within it. It reads one line and doesn't know the language, so it's a close guess: nested
/// strings inside an interpolation aren't tracked.
#[derive(Default)]
struct Quotes {
    quote: Option<char>,
    braces: usize,
    escaped: bool,
}

impl Quotes {
    fn step(&mut self, character: char) {
        let Some(quote) = self.quote else {
            if matches!(character, '"' | '\'' | '`') {
                self.quote = Some(character);
            }
            return;
        };
        if self.escaped {
            self.escaped = false;
        } else if character == '\\' {
            self.escaped = true;
        } else if self.braces > 0 {
            match character {
                '{' => self.braces += 1,
                '}' => self.braces -= 1,
                _ => {}
            }
        } else if character == '{' {
            self.braces = 1;
        } else if character == quote {
            self.quote = None;
        }
    }

    fn in_plain_string(&self) -> bool {
        self.quote.is_some() && self.braces == 0
    }
}

/// Whether the secret name at `start..end` is code or part of a quoted string, judged from its
/// own line.
fn name_use(text: &str, start: usize, end: usize) -> NameUse {
    let line_start = text[..start].rfind('\n').map_or(0, |newline| newline + 1);
    let line_end = text[end..]
        .find('\n')
        .map_or(text.len(), |newline| end + newline);
    let mut quotes = Quotes::default();
    text[line_start..start]
        .chars()
        .for_each(|character| quotes.step(character));
    if !quotes.in_plain_string() {
        return NameUse::Code;
    }
    // Read to the end of the string, then see whether another value follows it.
    let mut tail = &text[end..line_end];
    let mut rest = "";
    for (offset, character) in tail.char_indices() {
        quotes.step(character);
        if quotes.quote.is_none() {
            rest = &tail[offset + character.len_utf8()..];
            tail = &tail[..offset];
            break;
        }
    }
    let value_follows = quotes.quote.is_none() && rest.trim_start().starts_with([',', '+', '%']);
    match label_tail(tail) {
        Some(interpolates) if value_follows || interpolates => NameUse::Label,
        _ if value_follows => NameUse::Beside,
        _ => NameUse::Message,
    }
}

/// Whether the rest of a string after a secret name only finishes a label: the rest of the word
/// (`tokens`, `passwordHash`), then separators (`:`, `=`, `-`, spaces) and placeholders (`%s`,
/// `{}`, `{pw}`). Returns whether it has a placeholder, or `None` when other words follow.
fn label_tail(tail: &str) -> Option<bool> {
    let mut characters = tail
        .trim_start_matches(|character: char| character.is_alphanumeric() || character == '_')
        .chars();
    let mut placeholder = false;
    while let Some(character) = characters.next() {
        match character {
            ' ' | '\t' | ':' | '=' | '-' => {}
            '%' => {
                placeholder = true;
                // A printf-style conversion: `%s`, `%d`, `%r`, `%v`.
                characters.next();
            }
            '{' => {
                placeholder = true;
                characters.find(|&character| character == '}')?;
            }
            _ => return None,
        }
    }
    Some(placeholder)
}

/// The most entropy per character a value this long can have: log2 of its length in characters.
fn max_entropy(value: &str) -> f64 {
    (value.chars().count() as f64).log2().max(0.0)
}

/// Shannon entropy in bits per character.
pub(crate) fn shannon_entropy(value: &str) -> f64 {
    let mut counts = std::collections::HashMap::<char, f64>::new();
    let mut total = 0.0_f64;
    for character in value.chars() {
        *counts.entry(character).or_insert(0.0) += 1.0;
        total += 1.0;
    }
    counts
        .values()
        .map(|count| {
            let probability = count / total;
            -probability * probability.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::shannon_entropy;

    #[test]
    fn entropy_is_zero_for_one_repeated_character_and_grows_with_variety() {
        assert_eq!(shannon_entropy("aaaaaaaa"), 0.0);
        assert!((shannon_entropy("abcd") - 2.0).abs() < 1e-9);
        assert!(shannon_entropy("q8Z!fP2x@L7m") > 3.5);
    }
}
