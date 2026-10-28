use crate::location::{LineIndex, Location};
use crate::models::{LoadedModel, Models, encode_value, encode_window, to_score};
use crate::rules::{
    CompiledRule, DetectionType, ErrorCode, Matcher, Rule, RuleError, RuleField, RuleSet, Severity,
    check_and_compile, duplicate_name_errors,
};
use regex::Regex;
use serde::Serialize;

/// Inputs larger than this are rejected before scanning.
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;

/// At most this many matches are returned; the rest are reported as truncated. A rule broad
/// enough to hit this usually needs fixing, and showing thousands of highlights helps no one.
pub const MAX_FINDINGS: usize = 200;

/// A model detection span shorter than this many bytes is dropped: a few stray bytes are noise,
/// not a secret.
pub const MIN_DETECTION_BYTES: usize = 8;

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
    /// How sure the engine is that this is a secret of the rule's kind, 0–100.
    pub confidence: u8,
    /// How likely the value is a placeholder or example rather than a real secret, 0–100.
    /// Absent for unsafe handling, which has no value.
    pub placeholder_score: Option<u8>,
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
    placeholder_hit: bool,
    /// The model's score, for a model detection finding.
    model_score: Option<u8>,
    /// Each model assessment rule that scored the value, with its score.
    assessments: Vec<(&'r CompiledRule, u8)>,
}

/// Scans `text` with the enabled rules. Rules that fail their checks are skipped and reported
/// as rule-error findings; the rest still run. Model rules need [`scan_with_models`].
pub fn scan(scan_id: i64, text: &str, rule_set: &RuleSet) -> Result<ScanResult, ScanError> {
    scan_with_models(scan_id, text, rule_set, &Models::default())
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
        match rule_model(&rule, models) {
            Ok(model) => runnable.push((rule, model)),
            Err(error) => rule_errors.push(error),
        }
    }
    log_line(format!(
        "{} of {} enabled rules ran; {} rule errors",
        runnable.len(),
        enabled.len(),
        rule_errors.len()
    ));

    let mut placeholder_ranges = Vec::new();
    let mut candidates = Vec::new();
    let mut assessors = Vec::new();
    for (rule, model) in &runnable {
        let creates_findings = rule.detection_type.creates_findings();
        match (&rule.matcher, model) {
            (Matcher::Pattern(regex), _) if creates_findings => {
                candidates.extend(find_candidates(rule, regex, text));
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
    for candidate in &mut candidates {
        candidate.placeholder_hit = placeholder_ranges
            .iter()
            .any(|&(start, end)| candidate.start <= start && end <= candidate.end);
    }
    candidates.sort_by_key(|candidate| (candidate.start, candidate.end, candidate.rule.id));

    let truncated = candidates.len() > MAX_FINDINGS;
    if truncated {
        log_line(format!(
            "found {} matches; kept the first {MAX_FINDINGS}",
            candidates.len()
        ));
        candidates.truncate(MAX_FINDINGS);
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
        });
    }

    Ok(ScanResult {
        findings,
        truncated,
        log,
    })
}

fn find_candidates<'r>(rule: &'r CompiledRule, regex: &Regex, text: &str) -> Vec<Candidate<'r>> {
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
        let entropy = (rule.detection_type != DetectionType::UnsafeHandling)
            .then(|| shannon_entropy(value.as_str()));
        if let (Some(minimum), Some(entropy)) = (rule.min_entropy, entropy)
            && entropy < minimum
        {
            continue;
        }
        candidates.push(Candidate {
            rule,
            start: value.start(),
            end: value.end(),
            entropy,
            // Set once placeholder rules have run.
            placeholder_hit: false,
            model_score: None,
            assessments: Vec::new(),
        });
    }
    candidates
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
    if rule.detection_type == DetectionType::ModelDetection {
        if model.output_len() != model.input_len() {
            return Err(unavailable(format!(
                "The model {name} must return one score per input position to detect secrets."
            )));
        }
    } else if model.output_len() != 1 || model.input_len() < 3 {
        return Err(unavailable(format!(
            "The model {name} must return a single score, and have room for a value, to assess \
             findings."
        )));
    }
    Ok(Some(model))
}

fn model_failed(rule: &CompiledRule) -> RuleError {
    RuleError {
        rule_id: rule.id,
        field: RuleField::Model,
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
            .map_err(|()| model_failed(rule))?;
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
            placeholder_hit: false,
            model_score: scores[run_start..index].iter().max().copied(),
            assessments: Vec::new(),
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
            let output = model.run(&ids).map_err(|()| model_failed(rule))?;
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
    let placeholder_score = candidate.entropy.map(|entropy| {
        if candidate.placeholder_hit {
            95
        } else if entropy < 2.0 {
            70
        } else {
            5
        }
    });
    let (confidence, mut why) = match (rule.detection_type, candidate.entropy) {
        (DetectionType::DirectCredential, _) => (95, format!("Matches the {} format.", rule.name)),
        (DetectionType::LikelyCredential, Some(entropy)) => {
            let minimum = rule.min_entropy.unwrap_or(0.0);
            let confidence = (50.0 + (entropy - minimum).max(0.0) * 15.0).min(90.0) as u8;
            let mut why = format!("High-entropy value ({entropy:.1} bits per character");
            if rule.min_entropy.is_some() {
                why.push_str(&format!(", threshold {minimum:.1}"));
            }
            why.push(')');
            if !rule.key_names.is_empty() {
                why.push_str(" assigned to a name that suggests a secret");
            }
            why.push('.');
            (confidence, why)
        }
        (DetectionType::ModelDetection, _) => {
            let score = candidate.model_score.unwrap_or(0);
            (
                score,
                format!(
                    "Flagged by the {} model (score {score}, threshold {}).",
                    rule.name,
                    threshold(rule)
                ),
            )
        }
        _ => (
            70,
            format!(
                "Matches the {} pattern; no secret value is involved.",
                rule.name
            ),
        ),
    };
    match placeholder_score {
        Some(95) => why.push_str(" Looks like an example: contains a known placeholder value."),
        Some(70) => why.push_str(" Looks like an example: very little randomness."),
        Some(_) => why.push_str(" Does not look like a placeholder."),
        None => {}
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
        model_assessments,
        location: index.location(candidate.start, candidate.end),
        redacted_preview: rule.prefix.as_ref().map(|prefix| format!("{prefix}…")),
        why_flagged: why,
        remediation: rule.remediation.clone(),
        overlap_group,
    }
}

/// Shannon entropy in bits per character.
fn shannon_entropy(value: &str) -> f64 {
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
