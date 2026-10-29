//! Labeled test data for a rule set: values each rule should find, copies it should mark as
//! examples, and lookalikes it should leave alone, laid out in documents ready to scan.
//!
//! Generation walks each rule's own pattern, so the data fits the rule as written, and every
//! case is checked against the rule before it is kept: a positive is one the rule finds, and a
//! lookalike is one it doesn't. It is seeded and deterministic, so the same rule set and seed
//! always give the same data and nothing has to be stored to run it again. Every value is made
//! up here; none is a real secret.

use crate::checksum::Checksum;
use crate::format;
use crate::password_shape;
use crate::rules::{CompiledRule, DetectionType, Rule, RuleSet, check_and_compile};
use crate::scan::rule_value_spans;
use regex::Regex;
use regex_syntax::hir::{Class, Hir, HirKind, Repetition};
use serde::Serialize;
use std::collections::HashMap;

/// How many times generation retries a case before giving up on it.
const ATTEMPTS: usize = 64;

/// The most cases in one generated document, so a document's findings stay well under the
/// scan's findings cap.
const MAX_CASES_PER_DOCUMENT: usize = 40;

/// Made-up passwords in the shapes people choose, for rules with a password shape setting.
const HUMAN_PASSWORDS: &[&str] = &[
    "Summer2024!",
    "Tr0ub4dor&3",
    "Bluebird#1987",
    "Gr33nTea#42",
    "Winter@2023x",
    "Dragon$Fly77",
    "MonkeyBread9!",
    "Sunshine2025?",
    "P4ssw0rd!Lake",
    "Kitten#Rain88",
];

/// Names that hold ordinary settings, for lookalikes under a name that isn't a key name.
const NEUTRAL_KEYS: &[&str] = &[
    "build_label",
    "release_channel",
    "theme_color",
    "owner_team",
    "feature_flag",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseKind {
    /// A value in the rule's format that passes its checks and its checksum.
    Positive,
    /// A positive value assigned to one of the rule's key names in a `.env`, YAML, or JSON file.
    Assignment,
    /// A positive value with one covered character changed, so its checksum fails.
    BrokenChecksum,
    /// A positive value with a value from one of the set's placeholder rules inside it.
    Placeholder,
    /// The format with one character of its prefix changed.
    WrongPrefix,
    /// The value one character short.
    OneShort,
    /// The value with too little randomness for the rule's minimum entropy.
    LowEntropy,
    /// An assignment value under a name that isn't one of the rule's key names.
    NeutralKey,
    /// An ordinary value that isn't secret (a hash, UUID, URL, version, ...), for no rule in
    /// particular.
    Lookalike,
}

/// What a case should get from a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Expectation {
    /// Reported, and not marked as an example.
    Secret,
    /// Not reported, or reported as a likely example.
    Example,
    /// Not reported.
    NotSecret,
}

/// One labeled value in a generated document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestCase {
    /// Stable for the same rule set and seed, such as `r4-assignment-env`.
    pub id: String,
    /// The rule the case was made for. None for lookalikes meant for no rule.
    pub rule_id: Option<i64>,
    pub kind: CaseKind,
    pub expect: Expectation,
    /// Byte range of the value in the document: what the rule found for a positive, or where
    /// the changed value sits for the others.
    pub start: usize,
    pub end: usize,
    /// What the case is, from its shape only. Never quotes the value.
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestDocument {
    /// A file name whose extension says what the document holds, such as `assignments.env`.
    pub name: String,
    pub text: String,
    pub cases: Vec<TestCase>,
}

/// A case that wasn't generated, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedCase {
    pub rule_id: i64,
    pub kind: CaseKind,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestSuite {
    pub seed: u64,
    pub documents: Vec<TestDocument>,
    pub skipped: Vec<SkippedCase>,
}

/// Generates labeled test data for the enabled pattern rules in `rule_set`, or only the listed
/// ones. Placeholder rules are always read, to plant their values inside other rules' values.
/// The same rule set and seed always give the same suite, and each rule's cases depend only on
/// the seed and that rule, so adding a rule doesn't change the others' data.
pub fn generate_test_data(rule_set: &RuleSet, rule_ids: Option<&[i64]>, seed: u64) -> TestSuite {
    let mut compiled: HashMap<i64, CompiledRule> = HashMap::new();
    let mut targets = Vec::new();
    let mut skipped = Vec::new();

    for rule in &rule_set.rules {
        let listed = rule_ids.is_none_or(|ids| ids.contains(&rule.id));
        let (rule_compiled, check) = check_and_compile(rule);
        let reason = match &rule_compiled {
            _ if !check.is_valid() => Some("The rule doesn't pass its checks, so it can't run."),
            _ if !rule.definition.is_enabled() => Some("The rule is disabled, so scans skip it."),
            Some(rule) if rule.detection_type == DetectionType::PlaceholderVsReal => Some(
                "Placeholder rules create no findings; their values are planted inside other \
                 rules' values instead.",
            ),
            Some(rule) if rule.detection_type.uses_model() => {
                Some("Model rules have no pattern to generate values from.")
            }
            _ => None,
        };
        if let Some(reason) = reason
            && listed
        {
            skipped.push(skipped_case(rule.id, CaseKind::Positive, reason));
        }
        let Some(rule_compiled) = rule_compiled.filter(|_| check.is_valid()) else {
            continue;
        };
        if !rule.definition.is_enabled() || rule_compiled.detection_type.uses_model() {
            continue;
        }
        if reason.is_none() && listed {
            targets.push((rule.id, rule.definition.pattern.clone().unwrap_or_default()));
        }
        compiled.insert(rule.id, rule_compiled);
    }

    let placeholders: Vec<Placeholder> = rule_set
        .rules
        .iter()
        .filter(|rule| {
            compiled
                .get(&rule.id)
                .is_some_and(|compiled| compiled.detection_type == DetectionType::PlaceholderVsReal)
        })
        .filter_map(|rule| Placeholder::new(seed, rule))
        .collect();

    let mut plain = Vec::new();
    let mut assignments: [Vec<Snippet>; 3] = Default::default();
    for (rule_id, pattern) in targets {
        let rule = &compiled[&rule_id];
        let Some(hir) = parse_pattern(&pattern) else {
            continue;
        };
        let mut rng = Rng::new(seed, rule_id);
        let shape = Shape::new(rule, &hir);
        let Some(positive) = plant(rule, &hir, &shape, &mut rng) else {
            skipped.push(skipped_case(
                rule_id,
                CaseKind::Positive,
                format!(
                    "No generated match passed the rule's own checks in {ATTEMPTS} tries{}.",
                    filters_note(rule)
                ),
            ));
            continue;
        };
        let mut cases = RuleCases {
            rule,
            plain: &mut plain,
            skipped: &mut skipped,
        };
        cases.push(&positive, CaseKind::Positive, Expectation::Secret, true);
        let broken = rule
            .checksum
            .and_then(|checksum| cases.broken_checksum(&positive, checksum, &mut rng));
        if rule.detection_type != DetectionType::UnsafeHandling {
            cases.placeholder(&positive, &placeholders);
            cases.wrong_prefix(&positive);
            cases.one_short(&positive);
            cases.low_entropy(&positive);
        }
        if rule.detection_type == DetectionType::LikelyCredential && !rule.key_names.is_empty() {
            assignment_cases(rule, &positive, &mut rng, &mut assignments, &mut skipped);
        }
        // A broken value assigned to a token name, where another rule that goes by names can
        // match it too and score it on its own evidence.
        if let Some(broken) = broken.filter(|broken| safe_assignment_value(broken)) {
            let format = AssignmentFormat::Env;
            let (line, region) = format.line("APP_TOKEN", &broken);
            let (alone, alone_region) = format.frame().alone(&line, region);
            let found = found_in(rule, &alone, alone_region).is_some();
            assignments[0].push(Snippet {
                text: line,
                cases: vec![(
                    TestCase {
                        id: format!("r{rule_id}-broken-checksum-env"),
                        rule_id: Some(rule_id),
                        kind: CaseKind::BrokenChecksum,
                        expect: Expectation::Example,
                        start: region.0,
                        end: region.1,
                        note: format!(
                            "{} Assigned to a token name, where rules that go by names can \
                             match it too.",
                            note(rule, CaseKind::BrokenChecksum)
                        ),
                    },
                    found,
                )],
            });
        }
    }

    let mut documents = Vec::new();
    for (index, layout) in lay_out(plain, &compiled, Frame::PLAIN, &mut skipped)
        .into_iter()
        .enumerate()
    {
        documents.push(layout.into_document(format!("patterns-{}.txt", index + 1)));
    }
    for (format, snippets) in AssignmentFormat::ALL.into_iter().zip(assignments) {
        for (index, layout) in lay_out(snippets, &compiled, format.frame(), &mut skipped)
            .into_iter()
            .enumerate()
        {
            let name = match index {
                0 => format!("assignments.{}", format.slug()),
                _ => format!("assignments-{}.{}", index + 1, format.slug()),
            };
            documents.push(layout.into_document(name));
        }
    }
    documents.push(lookalikes(seed));

    TestSuite {
        seed,
        documents,
        skipped,
    }
}

fn skipped_case(rule_id: i64, kind: CaseKind, reason: impl Into<String>) -> SkippedCase {
    SkippedCase {
        rule_id,
        kind,
        reason: reason.into(),
    }
}

fn filters_note(rule: &CompiledRule) -> String {
    let mut filters = Vec::new();
    if !rule.key_names.is_empty() {
        filters.push("key names".to_string());
    }
    if let Some(minimum) = rule.min_entropy {
        filters.push(format!("minimum entropy {minimum}"));
    }
    if let Some(shape) = rule.password_shape {
        filters.push(format!("password shape score {}", shape.min_score));
    }
    if filters.is_empty() {
        String::new()
    } else {
        format!(" ({})", filters.join(", "))
    }
}

fn parse_pattern(pattern: &str) -> Option<Hir> {
    regex_syntax::ParserBuilder::new()
        .build()
        .parse(pattern)
        .ok()
}

/// SplitMix64: small, fast, and the same everywhere, which is all test data needs.
struct Rng(u64);

impl Rng {
    /// A stream for one rule, so each rule's data depends only on the seed and the rule.
    fn new(seed: u64, stream: i64) -> Self {
        let mut rng = Rng(seed ^ (stream as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        rng.next();
        rng
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number in `0..n`; `n` must be above zero.
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    fn string(&mut self, alphabet: &[u8], length: usize) -> String {
        (0..length).map(|_| *self.pick(alphabet) as char).collect()
    }
}

const ALPHANUMERIC: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const HEX_DIGITS: &[u8] = b"0123456789abcdef";

/// Choices that make a generated match more likely to pass the rule's own filters.
struct Shape {
    /// Names for the `key` group that hold one of the rule's key names.
    key_choices: Vec<String>,
    /// Values for the `value` group that pass the rule's password shape.
    value_choices: Vec<String>,
}

impl Shape {
    fn new(rule: &CompiledRule, hir: &Hir) -> Self {
        let key_choices = match full_match(hir, "key") {
            Some(key) if !rule.key_names.is_empty() => rule
                .key_names
                .iter()
                .flat_map(|name| {
                    let upper = name.to_uppercase();
                    [
                        name.clone(),
                        upper.clone(),
                        format!("db_{name}"),
                        format!("APP_{upper}"),
                        format!("my{name}"),
                    ]
                })
                .filter(|candidate| key.is_match(candidate))
                .collect(),
            _ => Vec::new(),
        };
        let value_choices = match (full_match(hir, "value"), rule.password_shape) {
            (Some(value), Some(setting)) => HUMAN_PASSWORDS
                .iter()
                .filter(|candidate| value.is_match(candidate))
                .filter(|candidate| {
                    password_shape::assess(candidate)
                        .is_some_and(|assessment| assessment.score >= setting.min_score)
                })
                .map(|candidate| candidate.to_string())
                .collect(),
            _ => Vec::new(),
        };
        Shape {
            key_choices,
            value_choices,
        }
    }
}

/// A regex that matches exactly what the named group's part of the pattern matches.
fn full_match(hir: &Hir, name: &str) -> Option<Regex> {
    let group = find_group(hir, name)?;
    Regex::new(&format!("^(?:{group})$")).ok()
}

fn find_group<'h>(hir: &'h Hir, name: &str) -> Option<&'h Hir> {
    match hir.kind() {
        HirKind::Capture(capture) if capture.name.as_deref() == Some(name) => Some(&capture.sub),
        HirKind::Capture(capture) => find_group(&capture.sub, name),
        HirKind::Repetition(repetition) => find_group(&repetition.sub, name),
        HirKind::Concat(items) | HirKind::Alternation(items) => {
            items.iter().find_map(|item| find_group(item, name))
        }
        _ => None,
    }
}

/// Where the named groups landed in a generated match.
#[derive(Default)]
struct Spans {
    key: Option<(usize, usize)>,
    value: Option<(usize, usize)>,
}

/// Writes one random match of `hir`. Repetitions run up to `extra` times past their minimum.
fn write(
    hir: &Hir,
    shape: &Shape,
    extra: usize,
    rng: &mut Rng,
    out: &mut String,
    spans: &mut Spans,
) {
    match hir.kind() {
        HirKind::Empty | HirKind::Look(_) => {}
        HirKind::Literal(literal) => out.push_str(&String::from_utf8_lossy(&literal.0)),
        HirKind::Class(class) => {
            if let Some(character) = pick_char(class, rng) {
                out.push(character);
            }
        }
        HirKind::Repetition(repetition) => {
            for _ in 0..repeat_count(repetition, extra, rng) {
                write(&repetition.sub, shape, extra, rng, out, spans);
            }
        }
        HirKind::Capture(capture) => {
            let start = out.len();
            let choices: &[String] = match capture.name.as_deref() {
                Some("key") => &shape.key_choices,
                Some("value") => &shape.value_choices,
                _ => &[],
            };
            if !choices.is_empty() && rng.chance(85) {
                out.push_str(rng.pick(choices));
            } else {
                write(&capture.sub, shape, extra, rng, out, spans);
            }
            let span = Some((start, out.len()));
            match capture.name.as_deref() {
                Some("key") if spans.key.is_none() => spans.key = span,
                Some("value") => spans.value = span,
                _ => {}
            }
        }
        HirKind::Concat(items) => {
            for item in items {
                write(item, shape, extra, rng, out, spans);
            }
        }
        HirKind::Alternation(items) => write(rng.pick(items), shape, extra, rng, out, spans),
    }
}

fn repeat_count(repetition: &Repetition, extra: usize, rng: &mut Rng) -> usize {
    let min = repetition.min as usize;
    // Optional line-ending carriage returns (`\r?`) are left out, so documents keep `\n` only.
    if let HirKind::Literal(literal) = repetition.sub.kind()
        && &*literal.0 == b"\r"
    {
        return min;
    }
    // Runs of spacing (`\s*`) stay short, as people write them.
    let extra = match repetition.sub.kind() {
        HirKind::Class(class) if pick_char(class, &mut Rng(0)) == Some(' ') => 1,
        _ => extra,
    };
    let room = repetition
        .max
        .map_or(extra, |max| (max as usize - min).min(extra));
    min + rng.below(room + 1)
}

/// A character from the class: usually a letter or digit when it allows one, so values look like
/// real tokens, then other printable characters, then whitespace. A case-insensitive letter is
/// written in lowercase.
fn pick_char(class: &Class, rng: &mut Rng) -> Option<char> {
    let contains = |character: char| match class {
        Class::Unicode(class) => class
            .ranges()
            .iter()
            .any(|range| range.start() <= character && character <= range.end()),
        Class::Bytes(class) => {
            character.is_ascii()
                && class
                    .ranges()
                    .iter()
                    .any(|range| range.start() <= character as u8 && character as u8 <= range.end())
        }
    };
    let alphanumeric: Vec<char> = ALPHANUMERIC
        .iter()
        .map(|&byte| byte as char)
        .filter(|&character| contains(character))
        .collect();
    if let &[upper, lower] = &alphanumeric[..]
        && upper.to_ascii_lowercase() == lower
        && upper != lower
    {
        return Some(lower);
    }
    // Quotes and backslashes end or escape strings in most files, so they come last.
    let punctuation: Vec<char> = ('!'..='~')
        .filter(|character| {
            !character.is_ascii_alphanumeric()
                && !"\"'`\\".contains(*character)
                && contains(*character)
        })
        .collect();
    if !alphanumeric.is_empty() && (punctuation.is_empty() || rng.chance(92)) {
        return Some(*rng.pick(&alphanumeric));
    }
    if !punctuation.is_empty() {
        return Some(*rng.pick(&punctuation));
    }
    [' ', '\t', '\n', '"', '\'', '`', '\\']
        .into_iter()
        .find(|&character| contains(character))
        .or_else(|| match class {
            Class::Unicode(class) => class.ranges().first().map(|range| range.start()),
            Class::Bytes(class) => class
                .ranges()
                .first()
                .map(|range| range.start())
                .filter(u8::is_ascii)
                .map(char::from),
        })
}

/// A generated match the rule finds: the snippet, and the value range the rule reported.
struct Planted {
    text: String,
    value: (usize, usize),
}

impl Planted {
    fn value(&self) -> &str {
        &self.text[self.value.0..self.value.1]
    }

    /// The snippet with the value replaced.
    fn with_value(&self, value: &str) -> (String, (usize, usize)) {
        let (start, end) = self.value;
        (
            format!("{}{value}{}", &self.text[..start], &self.text[end..]),
            (start, start + value.len()),
        )
    }

    /// How much of the value's start to leave alone: the rule's prefix and the part a CRC32
    /// doesn't cover.
    fn head(&self, rule: &CompiledRule) -> usize {
        let prefix = rule
            .prefix
            .as_deref()
            .filter(|prefix| self.value().starts_with(prefix))
            .map_or(0, str::len);
        let uncovered = match rule.checksum {
            Some(Checksum::Crc32(checksum)) => checksum.prefix_length,
            _ => 0,
        };
        prefix.max(uncovered).min(self.value().len())
    }

    /// How much of the value's end holds a checksum.
    fn tail(&self, rule: &CompiledRule) -> usize {
        match rule.checksum {
            Some(Checksum::Crc32(checksum)) => checksum.length,
            Some(Checksum::Luhn) => 1,
            _ => 0,
        }
    }
}

/// The value range the rule finds in `text` overlapping `region`, if any.
fn found_in(rule: &CompiledRule, text: &str, region: (usize, usize)) -> Option<(usize, usize)> {
    rule_value_spans(rule, text, &format::parse(text))
        .into_iter()
        .find(|&(start, end)| start < region.1 && region.0 < end)
}

fn plant(rule: &CompiledRule, hir: &Hir, shape: &Shape, rng: &mut Rng) -> Option<Planted> {
    for attempt in 0..ATTEMPTS {
        let extra = [8, 16, 30][attempt % 3];
        let mut text = String::new();
        let mut spans = Spans::default();
        write(hir, shape, extra, rng, &mut text, &mut spans);
        let mut value = spans.value.unwrap_or((0, text.len()));
        // Every match should start with the rule's declared prefix, so write it in when the
        // pattern left room for something else there.
        if let Some(prefix) = rule.prefix.as_deref().filter(|prefix| !prefix.is_empty())
            && !text[value.0..].starts_with(prefix)
            && !text[..value.0].ends_with(prefix)
            && text.is_char_boundary(value.0 + prefix.len().min(value.1 - value.0))
            && value.1 - value.0 > prefix.len()
        {
            text.replace_range(value.0..value.0 + prefix.len(), prefix);
        }
        if let Some(checksum) = rule.checksum {
            let Some(repaired) = checksum.repair(&text[value.0..value.1]) else {
                continue;
            };
            text = format!("{}{repaired}{}", &text[..value.0], &text[value.1..]);
            value.1 = value.0 + repaired.len();
        }
        if text.trim().is_empty() || text.contains('\r') {
            continue;
        }
        let Some(found) = found_in(rule, &text, value) else {
            continue;
        };
        // Values under 8 characters are out of the scanner's scope, so prefer longer ones
        // while there are tries left.
        if found.1 - found.0 < 8 && attempt < ATTEMPTS / 2 {
            continue;
        }
        if rule
            .checksum
            .is_some_and(|checksum| !checksum.is_valid(&text[found.0..found.1]))
        {
            continue;
        }
        return Some(Planted { text, value: found });
    }
    None
}

/// A placeholder rule's pattern and a few values it matches.
struct Placeholder {
    name: String,
    regex: Regex,
    samples: Vec<String>,
}

impl Placeholder {
    fn new(seed: u64, rule: &Rule) -> Option<Self> {
        let pattern = rule.definition.pattern.as_deref()?;
        let regex = Regex::new(pattern).ok()?;
        let hir = parse_pattern(pattern)?;
        let mut rng = Rng::new(seed, rule.id);
        let shape = Shape {
            key_choices: Vec::new(),
            value_choices: Vec::new(),
        };
        let mut samples: Vec<String> = Vec::new();
        for _ in 0..ATTEMPTS {
            let mut sample = String::new();
            write(
                &hir,
                &shape,
                3,
                &mut rng,
                &mut sample,
                &mut Spans::default(),
            );
            for variant in [sample.clone(), sample.to_uppercase()] {
                if !variant.is_empty()
                    && variant.len() <= 24
                    && regex.is_match(&variant)
                    && !samples.contains(&variant)
                {
                    samples.push(variant);
                }
            }
            if samples.len() >= 8 {
                break;
            }
        }
        Some(Placeholder {
            name: rule.definition.name.clone().unwrap_or_default(),
            regex,
            samples,
        })
    }

    /// Whether a match of this placeholder lies inside `region` of `text`, which is how a scan
    /// marks a finding as a likely example.
    fn inside(&self, text: &str, region: (usize, usize)) -> bool {
        self.regex
            .find_iter(text)
            .any(|found| region.0 <= found.start() && found.end() <= region.1 && !found.is_empty())
    }
}

/// A snippet of a document: its text and the cases in it, with ranges relative to the snippet.
struct Snippet {
    text: String,
    cases: Vec<(TestCase, bool)>,
}

/// Collects one rule's pattern cases into plain-text snippets.
struct RuleCases<'a> {
    rule: &'a CompiledRule,
    plain: &'a mut Vec<Snippet>,
    skipped: &'a mut Vec<SkippedCase>,
}

impl RuleCases<'_> {
    fn push(&mut self, planted: &Planted, kind: CaseKind, expect: Expectation, found: bool) {
        self.push_text(planted.text.clone(), planted.value, kind, expect, found);
    }

    /// Adds a case. `found` says whether the rule finds it, which is checked again once it sits
    /// in its document.
    fn push_text(
        &mut self,
        text: String,
        value: (usize, usize),
        kind: CaseKind,
        expect: Expectation,
        found: bool,
    ) {
        let case = TestCase {
            id: format!("r{}-{}", self.rule.id, kind_slug(kind)),
            rule_id: Some(self.rule.id),
            kind,
            expect,
            start: value.0,
            end: value.1,
            note: note(self.rule, kind),
        };
        self.plain.push(Snippet {
            text,
            cases: vec![(case, found)],
        });
    }

    fn skip(&mut self, kind: CaseKind, reason: impl Into<String>) {
        self.skipped.push(skipped_case(self.rule.id, kind, reason));
    }

    /// Adds a copy of the positive whose checksum fails, and returns its value.
    fn broken_checksum(
        &mut self,
        positive: &Planted,
        checksum: Checksum,
        rng: &mut Rng,
    ) -> Option<String> {
        let value = positive.value();
        let (start, end) = checksum.covered(value)?;
        for _ in 0..ATTEMPTS {
            let index = start + rng.below(end - start);
            if !value.is_char_boundary(index) || !value.is_char_boundary(index + 1) {
                continue;
            }
            let Some(changed) = sibling(value.as_bytes()[index], rng) else {
                continue;
            };
            let broken = format!("{}{changed}{}", &value[..index], &value[index + 1..]);
            let (text, region) = positive.with_value(&broken);
            if let Some(found) = found_in(self.rule, &text, region)
                && !checksum.is_valid(&text[found.0..found.1])
            {
                let value = text[found.0..found.1].to_string();
                self.push_text(
                    text,
                    found,
                    CaseKind::BrokenChecksum,
                    Expectation::Example,
                    true,
                );
                return Some(value);
            }
        }
        self.skip(
            CaseKind::BrokenChecksum,
            "No one-character change to the covered part kept the value in the rule's format.",
        );
        None
    }

    fn placeholder(&mut self, positive: &Planted, placeholders: &[Placeholder]) {
        if placeholders.is_empty() {
            self.skip(
                CaseKind::Placeholder,
                "The rule set has no enabled placeholder rules.",
            );
            return;
        }
        let value = positive.value();
        let head = positive.head(self.rule);
        let tail = positive.tail(self.rule);
        for placeholder in placeholders {
            for sample in &placeholder.samples {
                let Some(last) = value.len().checked_sub(tail + sample.len()) else {
                    continue;
                };
                if last < head {
                    continue;
                }
                // A few spread-out positions, from just after the prefix to just before the
                // checksum.
                let positions: Vec<usize> =
                    (0..6).map(|step| head + (last - head) * step / 5).collect();
                for index in positions {
                    if !value.is_char_boundary(index)
                        || !value.is_char_boundary(index + sample.len())
                    {
                        continue;
                    }
                    let mut planted = format!(
                        "{}{sample}{}",
                        &value[..index],
                        &value[index + sample.len()..]
                    );
                    if let Some(checksum) = self.rule.checksum {
                        match checksum.repair(&planted) {
                            Some(repaired) => planted = repaired,
                            None => continue,
                        }
                    }
                    let (text, region) = positive.with_value(&planted);
                    let Some(found) = found_in(self.rule, &text, region) else {
                        continue;
                    };
                    let valid = self
                        .rule
                        .checksum
                        .is_none_or(|checksum| checksum.is_valid(&text[found.0..found.1]));
                    if valid && placeholders.iter().any(|any| any.inside(&text, found)) {
                        self.push_text(
                            text,
                            found,
                            CaseKind::Placeholder,
                            Expectation::Example,
                            true,
                        );
                        return;
                    }
                }
            }
        }
        let names: Vec<&str> = placeholders.iter().map(|p| p.name.as_str()).collect();
        self.skip(
            CaseKind::Placeholder,
            format!(
                "No value from the placeholder rules ({}) fits inside this rule's format and is \
                 still found, so this rule's examples can't be told from real values by a \
                 placeholder rule.",
                names.join(", ")
            ),
        );
    }

    fn wrong_prefix(&mut self, positive: &Planted) {
        let Some(prefix) = self
            .rule
            .prefix
            .as_deref()
            .filter(|prefix| !prefix.is_empty())
        else {
            return;
        };
        let text = &positive.text;
        // The prefix where the match starts, at or just before the value.
        let limit = (positive.value.0 + prefix.len()).min(text.len());
        let Some(at) = text.get(..limit).and_then(|before| before.rfind(prefix)) else {
            return;
        };
        // Change the prefix's last letter or digit.
        let Some(index) = (at..at + prefix.len())
            .rev()
            .find(|&index| text.as_bytes()[index].is_ascii_alphanumeric())
        else {
            return;
        };
        let changed = next_in_class(text.as_bytes()[index]);
        let changed_text = format!("{}{changed}{}", &text[..index], &text[index + 1..]);
        let region = (at, positive.value.1.max(at + prefix.len()));
        if found_in(self.rule, &changed_text, region).is_some() {
            self.skip(
                CaseKind::WrongPrefix,
                format!(
                    "The rule still finds the value with its prefix changed to \"{}\", so the \
                     pattern doesn't require the prefix \"{prefix}\".",
                    &changed_text[at..at + prefix.len()]
                ),
            );
            return;
        }
        self.push_text(
            changed_text,
            region,
            CaseKind::WrongPrefix,
            Expectation::NotSecret,
            false,
        );
    }

    fn one_short(&mut self, positive: &Planted) {
        let value = positive.value();
        let head = positive.head(self.rule);
        if value.len() <= head + 1 {
            return;
        }
        let index = head + (value.len() - head) / 2;
        if !value.is_char_boundary(index) || !value.is_char_boundary(index + 1) {
            return;
        }
        let shorter = format!("{}{}", &value[..index], &value[index + 1..]);
        let (text, region) = positive.with_value(&shorter);
        // A pattern that takes a range of lengths still finds it, which is no near miss.
        if found_in(self.rule, &text, region).is_none() {
            self.push_text(
                text,
                region,
                CaseKind::OneShort,
                Expectation::NotSecret,
                false,
            );
        }
    }

    fn low_entropy(&mut self, positive: &Planted) {
        if self.rule.min_entropy.is_none() {
            return;
        }
        let value = positive.value();
        let head = positive.head(self.rule);
        let mut distinct: Vec<char> = Vec::new();
        for character in value[head..].chars() {
            if character.is_ascii_alphanumeric() && !distinct.contains(&character) {
                distinct.push(character);
            }
            if distinct.len() == 2 {
                break;
            }
        }
        let &[first, second] = &distinct[..] else {
            return;
        };
        let fill: String = (0..value[head..].chars().count())
            .map(|index| if index % 2 == 0 { first } else { second })
            .collect();
        let (text, region) = positive.with_value(&format!("{}{fill}", &value[..head]));
        if found_in(self.rule, &text, region).is_none() {
            self.push_text(
                text,
                region,
                CaseKind::LowEntropy,
                Expectation::Example,
                false,
            );
        }
    }
}

/// Another character of the same kind (digit, lowercase, or uppercase letter).
fn sibling(byte: u8, rng: &mut Rng) -> Option<char> {
    let alphabet: &[u8] = match byte {
        b'0'..=b'9' => b"0123456789",
        b'a'..=b'z' => b"abcdefghijklmnopqrstuvwxyz",
        b'A'..=b'Z' => b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        _ => return None,
    };
    loop {
        let candidate = *rng.pick(alphabet);
        if candidate != byte {
            return Some(candidate as char);
        }
    }
}

/// The next letter or digit of the same kind, wrapping around.
fn next_in_class(byte: u8) -> char {
    (match byte {
        b'9' => b'0',
        b'z' => b'a',
        b'Z' => b'A',
        _ => byte + 1,
    }) as char
}

fn kind_slug(kind: CaseKind) -> &'static str {
    match kind {
        CaseKind::Positive => "positive",
        CaseKind::Assignment => "assignment",
        CaseKind::BrokenChecksum => "broken-checksum",
        CaseKind::Placeholder => "placeholder",
        CaseKind::WrongPrefix => "wrong-prefix",
        CaseKind::OneShort => "one-short",
        CaseKind::LowEntropy => "low-entropy",
        CaseKind::NeutralKey => "neutral-key",
        CaseKind::Lookalike => "lookalike",
    }
}

fn note(rule: &CompiledRule, kind: CaseKind) -> String {
    let name = &rule.name;
    match kind {
        CaseKind::Positive if rule.checksum.is_some() => {
            format!("A match of {name} with a valid checksum.")
        }
        CaseKind::Positive => format!("A match of {name} that passes its checks."),
        CaseKind::Assignment => format!("A value for {name} assigned to one of its key names."),
        CaseKind::BrokenChecksum => {
            format!("A match of {name} with one covered character changed, so its checksum fails.")
        }
        CaseKind::Placeholder => {
            format!("A match of {name} with a known placeholder value inside it.")
        }
        CaseKind::WrongPrefix => {
            format!("The {name} format with one character of its prefix changed.")
        }
        CaseKind::OneShort => format!("A {name} value one character short."),
        CaseKind::LowEntropy => {
            format!("A {name} value with too little randomness for its minimum entropy.")
        }
        CaseKind::NeutralKey => {
            format!("A {name} value under a name that isn't one of its key names.")
        }
        CaseKind::Lookalike => String::new(),
    }
}

/// What surrounds a document's snippets: text before the first, between each two, and after
/// the last.
#[derive(Clone, Copy)]
struct Frame {
    header: &'static str,
    separator: &'static str,
    footer: &'static str,
}

impl Frame {
    /// Plain text: one blank line between snippets.
    const PLAIN: Frame = Frame {
        header: "",
        separator: "\n\n",
        footer: "\n",
    };

    /// One snippet framed as a document of its own, and `range` moved to match.
    fn alone(self, snippet: &str, range: (usize, usize)) -> (String, (usize, usize)) {
        let offset = self.header.len();
        (
            format!("{}{snippet}{}", self.header, self.footer),
            (range.0 + offset, range.1 + offset),
        )
    }
}

#[derive(Clone, Copy)]
enum AssignmentFormat {
    Env,
    Yaml,
    Json,
}

impl AssignmentFormat {
    const ALL: [AssignmentFormat; 3] = [Self::Env, Self::Yaml, Self::Json];

    fn slug(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Yaml => "yaml",
            Self::Json => "json",
        }
    }

    fn frame(self) -> Frame {
        match self {
            Self::Env | Self::Yaml => Frame {
                header: "",
                separator: "\n",
                footer: "\n",
            },
            Self::Json => Frame {
                header: "{\n",
                separator: ",\n",
                footer: "\n}\n",
            },
        }
    }

    /// The key to assign a value to, holding `name`, if this format allows its characters.
    fn key(self, name: &str) -> Option<String> {
        match self {
            Self::Env => name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.')
                .then(|| format!("APP_{}", name.to_uppercase())),
            Self::Yaml => name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
                .then(|| format!("app_{name}")),
            Self::Json => name
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
                .then(|| format!("app_{name}")),
        }
    }

    /// One line assigning `value` to `key`, and the value's range in it.
    fn line(self, key: &str, value: &str) -> (String, (usize, usize)) {
        let (line, start) = match self {
            Self::Env => (format!("{key}={value}"), key.len() + 1),
            Self::Yaml => (format!("{key}: {value}"), key.len() + 2),
            Self::Json => (format!("  \"{key}\": \"{value}\""), key.len() + 7),
        };
        (line, (start, start + value.len()))
    }
}

/// Characters an assignment value may hold without quoting or escaping in any of the formats.
fn safe_assignment_value(value: &str) -> bool {
    (8..=64).contains(&value.len())
        && value.starts_with(|character: char| character.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-+/=.~".contains(&byte))
}

fn assignment_cases(
    rule: &CompiledRule,
    positive: &Planted,
    rng: &mut Rng,
    documents: &mut [Vec<Snippet>; 3],
    skipped: &mut Vec<SkippedCase>,
) {
    let mut values: Vec<String> = Vec::new();
    if safe_assignment_value(positive.value()) {
        values.push(positive.value().to_string());
    }
    if rule.password_shape.is_some() {
        values.extend(HUMAN_PASSWORDS.iter().map(|value| value.to_string()));
    }
    for _ in 0..4 {
        values.push(rng.string(ALPHANUMERIC, 24));
    }
    let neutral: Vec<&str> = NEUTRAL_KEYS
        .iter()
        .copied()
        .filter(|key| {
            !rule
                .key_names
                .iter()
                .any(|name| key.contains(name.as_str()))
        })
        .collect();

    for (format, snippets) in AssignmentFormat::ALL.into_iter().zip(documents.iter_mut()) {
        let mut names: Vec<&String> = rule.key_names.iter().collect();
        // A seeded shuffle, so each format tends to use a different key name.
        for index in (1..names.len()).rev() {
            names.swap(index, rng.below(index + 1));
        }
        let found = names.iter().find_map(|name| {
            let key = format.key(name)?;
            values.iter().find_map(|value| {
                let (line, region) = format.line(&key, value);
                let (alone, alone_region) = format.frame().alone(&line, region);
                found_in(rule, &alone, alone_region).map(|_| (line, region, value.clone()))
            })
        });
        let Some((line, region, value)) = found else {
            skipped.push(SkippedCase {
                rule_id: rule.id,
                kind: CaseKind::Assignment,
                reason: format!(
                    "No generated value under one of the rule's key names was found in a {} \
                     file{}.",
                    format.slug(),
                    filters_note(rule)
                ),
            });
            continue;
        };
        let case = |kind, expect, region: (usize, usize)| TestCase {
            id: format!("r{}-{}-{}", rule.id, kind_slug(kind), format.slug()),
            rule_id: Some(rule.id),
            kind,
            expect,
            start: region.0,
            end: region.1,
            note: note(rule, kind),
        };
        snippets.push(Snippet {
            text: line,
            cases: vec![(
                case(CaseKind::Assignment, Expectation::Secret, region),
                true,
            )],
        });
        if let Some(key) = neutral.first().and_then(|key| format.key(key)) {
            let (line, region) = format.line(&key, &value);
            let (alone, alone_region) = format.frame().alone(&line, region);
            if found_in(rule, &alone, alone_region).is_none() {
                snippets.push(Snippet {
                    text: line,
                    cases: vec![(
                        case(CaseKind::NeutralKey, Expectation::NotSecret, region),
                        false,
                    )],
                });
            }
        }
    }
}

/// A document being laid out: its snippets' text, and each case with the range of its snippet,
/// as positions in the framed document.
#[derive(Clone)]
struct Layout {
    frame: Frame,
    body: String,
    cases: Vec<(TestCase, bool, (usize, usize))>,
}

impl Layout {
    fn new(frame: Frame) -> Self {
        Layout {
            frame,
            body: String::new(),
            cases: Vec::new(),
        }
    }

    fn text(&self) -> String {
        format!("{}{}{}", self.frame.header, self.body, self.frame.footer)
    }

    /// This layout with `snippet` added at the end.
    fn with(&self, snippet: &Snippet) -> Layout {
        let mut next = self.clone();
        if !next.body.is_empty() {
            next.body.push_str(self.frame.separator);
        }
        let offset = self.frame.header.len() + next.body.len();
        next.body.push_str(&snippet.text);
        let range = (offset, offset + snippet.text.len());
        for (case, found) in &snippet.cases {
            let mut case = case.clone();
            case.start += offset;
            case.end += offset;
            next.cases.push((case, *found, range));
        }
        next
    }

    fn into_document(self, name: String) -> TestDocument {
        TestDocument {
            name,
            text: self.text(),
            cases: self.cases.into_iter().map(|(case, _, _)| case).collect(),
        }
    }

    /// Whether every case still gets what it should with the others beside it: a rule that
    /// should find its case does, one that shouldn't doesn't, and no rule's match runs from
    /// one snippet into another.
    fn holds(&self, rules: &HashMap<i64, CompiledRule>) -> bool {
        let text = self.text();
        let structure = format::parse(&text);
        let mut spans: HashMap<i64, Vec<(usize, usize)>> = HashMap::new();
        let snippet_of = |position: usize| {
            self.cases
                .iter()
                .position(|(_, _, range)| range.0 <= position && position < range.1)
        };
        self.cases.iter().all(|(case, found, _)| {
            let Some(rule_id) = case.rule_id else {
                return true;
            };
            let rule_spans = spans
                .entry(rule_id)
                .or_insert_with(|| rule_value_spans(&rules[&rule_id], &text, &structure));
            let crosses = rule_spans
                .iter()
                .any(|&(start, end)| end > start && snippet_of(start) != snippet_of(end - 1));
            let hit = rule_spans
                .iter()
                .any(|&(start, end)| start < case.end && case.start < end);
            !crosses && hit == *found
        })
    }
}

/// Lays snippets out into documents, starting a new one when the current one is full or when a
/// snippet would change what the cases already in it get. A snippet that doesn't hold in a
/// document of its own is skipped.
fn lay_out(
    snippets: Vec<Snippet>,
    rules: &HashMap<i64, CompiledRule>,
    frame: Frame,
    skipped: &mut Vec<SkippedCase>,
) -> Vec<Layout> {
    let mut layouts: Vec<Layout> = Vec::new();
    for snippet in snippets {
        let added = layouts
            .last()
            .filter(|layout| layout.cases.len() < MAX_CASES_PER_DOCUMENT)
            .map(|layout| layout.with(&snippet))
            .filter(|next| next.holds(rules));
        if let Some(next) = added {
            *layouts.last_mut().expect("a layout was just extended") = next;
            continue;
        }
        let alone = Layout::new(frame).with(&snippet);
        if alone.holds(rules) {
            layouts.push(alone);
        } else {
            skipped.extend(snippet.cases.iter().filter_map(|(case, _)| {
                Some(skipped_case(
                    case.rule_id?,
                    case.kind,
                    "The case changed once it was framed as a document, so it was left out.",
                ))
            }));
        }
    }
    layouts
}

/// Ordinary values that are not secrets, in a YAML file, for no rule in particular. Two sit under
/// secret-sounding names, which is where rules that go by names tend to raise false alarms.
fn lookalikes(seed: u64) -> TestDocument {
    let mut rng = Rng::new(seed, -1);
    let hex = |rng: &mut Rng, length| rng.string(HEX_DIGITS, length);
    let uuid = |rng: &mut Rng| {
        format!(
            "{}-{}-4{}-a{}-{}",
            hex(rng, 8),
            hex(rng, 4),
            hex(rng, 3),
            hex(rng, 3),
            hex(rng, 12)
        )
    };
    let entries: Vec<(&str, String, &str)> = vec![
        ("commit", hex(&mut rng, 40), "A git commit SHA."),
        ("build_id", uuid(&mut rng), "A UUID."),
        (
            "image_digest",
            format!("sha256:{}", hex(&mut rng, 64)),
            "A container image digest.",
        ),
        (
            "docs_url",
            "https://docs.example.com/guides/setup?page=2&lang=en".into(),
            "A URL with no credentials in it.",
        ),
        ("version", "4.12.7".into(), "A version number."),
        (
            "log_file",
            "/var/log/app/worker-2.log".into(),
            "A file path.",
        ),
        (
            "owner_email",
            "platform-team@example.com".into(),
            "An email address.",
        ),
        (
            "db_password",
            "${DB_PASSWORD}".into(),
            "A reference to a secret kept elsewhere, not the secret itself.",
        ),
        (
            "signing_key_fingerprint",
            hex(&mut rng, 40),
            "A public key fingerprint under a secret-sounding name.",
        ),
        (
            "session_token_id",
            uuid(&mut rng),
            "A UUID under a secret-sounding name.",
        ),
        (
            "banner_b64",
            "V2VsY29tZSB0byB0aGUgc3RhZ2luZyBjbHVzdGVy".into(),
            "Base64 of an ordinary sentence.",
        ),
    ];
    let mut text = String::from("# Ordinary settings: none of these values is a secret.\n");
    let mut cases = Vec::new();
    for (key, value, note) in entries {
        let start = text.len() + key.len() + 2;
        text.push_str(&format!("{key}: {value}\n"));
        cases.push(TestCase {
            id: format!("lookalike-{}", key.replace('_', "-")),
            rule_id: None,
            kind: CaseKind::Lookalike,
            expect: Expectation::NotSecret,
            start,
            end: start + value.len(),
            note: note.into(),
        });
    }
    TestDocument {
        name: "lookalikes.yaml".into(),
        text,
        cases,
    }
}
