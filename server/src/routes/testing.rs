//! Test data and test runs for rule sets. Generated test data is labeled cases for each rule of a
//! version: values it should find, copies it should mark as examples, and lookalikes it should
//! leave alone. A test run scans labeled documents in a scan session and compares what each case
//! expected with what was found. Shared by the REST routes and the MCP tools.
//!
//! The engine generates the data deterministically from a seed, so it is never stored: a run
//! regenerates it. A run's documents go through `scans::scan_in_session` like any scan, so their
//! text is never stored or logged either; only the findings are saved, and the labels live in the
//! report alone.

use super::{
    AppState,
    models::{self, ModelResponse},
    scans::{self, ApiError, ErrorResponse, FindingResponse},
};
use crate::store::{self, StoreError};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use secrets_scanner_engine::{
    CaseKind, DetectionType, Expectation, MAX_INPUT_BYTES, Rule, RuleDefinition, RuleSet,
    generate_test_data, pattern_matches_value,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// A placeholder score at or above this marks a finding as a likely example.
const EXAMPLE_SCORE: u8 = 70;

/// A rule with no value group is worth a diagnostic when a match of its scores under this.
const DILUTED_CONFIDENCE: u8 = 80;

/// The seed used when a request gives none.
const DEFAULT_SEED: u64 = 1;

/// The most documents one test run scans.
pub const MAX_TEST_DOCUMENTS: usize = 20;

pub fn version_router() -> Router<AppState> {
    Router::new().route("/{id}/test-data", post(create_test_data))
}

pub fn session_router() -> Router<AppState> {
    Router::new().route("/{scan_session_id}/test-runs", post(create_test_run))
}

/// What a case should get from a scan.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    utoipa::ToSchema,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Expect {
    /// A real secret: it should be reported, and not marked as an example.
    Secret,
    /// A placeholder or documentation example: not reported, or reported with a
    /// placeholderScore of at least 70.
    Example,
    /// Not a secret: it should not be reported.
    NotSecret,
}

impl From<Expectation> for Expect {
    fn from(expectation: Expectation) -> Self {
        match expectation {
            Expectation::Secret => Expect::Secret,
            Expectation::Example => Expect::Example,
            Expectation::NotSecret => Expect::NotSecret,
        }
    }
}

#[derive(Debug, Default, Deserialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerateTestData {
    /// Any whole number. The same version and seed always give the same data. Defaults to 1.
    pub seed: Option<u64>,
    /// Only these rules' cases. Omit for every enabled pattern rule in the version. The set's
    /// placeholder rules are always used to make placeholder copies.
    pub rule_ids: Option<Vec<i64>>,
}

/// Generated test data. Every value in it is made up, and none of it is stored.
#[derive(Serialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TestData {
    pub rule_set_version_id: i64,
    pub seed: u64,
    pub documents: Vec<GeneratedDocument>,
    /// Cases that couldn't be made, and why. Some reasons point at a rule problem, such as a
    /// pattern that doesn't require its prefix.
    pub skipped: Vec<SkippedCase>,
}

#[derive(Serialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedDocument {
    /// A file name whose extension says what the document holds: plain-text pattern cases,
    /// assignments in `.env`, YAML, or JSON, or ordinary lookalike settings.
    pub name: String,
    pub text: String,
    pub cases: Vec<GeneratedCase>,
}

#[derive(Serialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedCase {
    /// Stable for the same version and seed, such as `r4-assignment-env`.
    pub id: String,
    /// The rule the case was made for; null for lookalikes meant for no rule.
    pub rule_id: Option<i64>,
    pub rule_name: Option<String>,
    /// positive, assignment, broken_checksum, placeholder, wrong_prefix, one_short, low_entropy,
    /// neutral_key, or lookalike.
    pub kind: String,
    pub expect: Expect,
    /// The case's text in the document. Made up here; never a real secret.
    pub value: String,
    /// Byte range of the value in the document.
    pub start: usize,
    pub end: usize,
    /// 1-based line of the value's start.
    pub line: usize,
    pub note: String,
}

#[derive(Serialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SkippedCase {
    pub rule_id: i64,
    pub rule_name: Option<String>,
    pub kind: String,
    pub reason: String,
}

#[derive(Debug, Default, Deserialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunTestSuite {
    /// Regenerate the version's test data (as generate_test_data returns it for this seed and
    /// these rules) and scan it, without sending its text.
    pub generated: Option<GenerateTestData>,
    /// Documents of your own, such as realistic config files, READMEs, or code, with the cases
    /// in them labeled. At most 20 documents in a run, generated ones included.
    pub documents: Option<Vec<TestDocumentInput>>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestDocumentInput {
    /// A file name, such as `.env` or `README.md`, shown in the report.
    pub name: String,
    /// The document to scan, up to 1 MB. It is never stored or logged.
    pub text: String,
    /// The labeled values in it. Anything else a rule finds is reported as an unlabeled
    /// finding.
    #[serde(default)]
    pub cases: Vec<TestCaseInput>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestCaseInput {
    /// Shown in the report. Defaults to the document name and the case's number, such as
    /// `.env#2`. Must be unique within the run.
    pub id: Option<String>,
    /// The case's exact text in the document, usually the secret value alone, without its key
    /// or quotes. Findings that overlap it count for the case.
    pub value: String,
    /// Which occurrence of value in the document, from 1. Defaults to 1.
    pub occurrence: Option<usize>,
    pub expect: Expect,
    /// The rule that should catch a secret, or the one rule a not_secret is about. Omit to
    /// count every rule. Give ruleId or ruleName, not both.
    pub rule_id: Option<i64>,
    /// A rule's name in the session's version, ignoring case, in place of ruleId.
    pub rule_name: Option<String>,
    /// What the case is, shown in the report.
    pub note: Option<String>,
}

/// How a case's expectation compares with what the scan found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// A secret its rule reported as real.
    Caught,
    /// A secret its rule reported, but only as a likely example (placeholderScore 70 or more).
    CaughtAsExample,
    /// A secret its rule didn't report.
    Missed,
    /// An example every overlapping finding marked as one.
    FlaggedAsExample,
    /// An example some finding scored as real (placeholderScore under 70).
    ScoredAsReal,
    /// An example nothing reported.
    NotReported,
    /// A non-secret its rule (or no rule) reported.
    Ignored,
    /// A non-secret its rule (or, with no rule named, any rule) reported.
    FalseAlarm,
}

/// A test run's results. It never contains scanned text or matched values, only labels,
/// positions, and scores.
#[derive(Serialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TestRunReport {
    pub scan_session_id: i64,
    pub rule_set_version_id: i64,
    /// The seed the generated documents used, if any were generated.
    pub seed: Option<u64>,
    pub summary: TestSummary,
    /// Problems the run turned up, each tied to a rule and the cases that showed it.
    pub diagnostics: Vec<Diagnostic>,
    /// Each rule's cases and findings.
    pub rules: Vec<RuleResult>,
    /// One scan each, in the order scanned.
    pub documents: Vec<DocumentResult>,
    /// Generated cases that couldn't be made, and why.
    pub skipped: Vec<SkippedCase>,
}

#[derive(Default, Serialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TestSummary {
    pub cases: usize,
    pub caught: usize,
    pub caught_as_example: usize,
    pub missed: usize,
    pub flagged_as_example: usize,
    pub scored_as_real: usize,
    pub not_reported: usize,
    pub ignored: usize,
    pub false_alarms: usize,
    /// Findings that overlap no labeled case.
    pub unlabeled_findings: usize,
    /// Rules that couldn't run in at least one scan.
    pub rule_errors: usize,
}

#[derive(Serialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostic {
    /// parsed_pair_only, no_value_group, example_scored_as_real, classifier_only_lowered,
    /// model_unavailable, prefix_not_enforced, suppressed, or truncated.
    pub code: String,
    pub rule_id: Option<i64>,
    pub rule_name: Option<String>,
    pub case_ids: Vec<String>,
    pub message: String,
}

#[derive(Serialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleResult {
    pub rule_id: i64,
    pub rule_name: String,
    /// The rule's detectionType, if it has one.
    pub detection_type: Option<String>,
    pub enabled: bool,
    /// Cases labeled for this rule.
    pub cases: usize,
    pub caught: usize,
    pub missed: usize,
    /// Its findings on non-secrets: cases labeled not_secret for it or for no rule.
    pub false_alarms: usize,
    /// Its findings that overlap no labeled case.
    pub unlabeled_findings: usize,
    /// The lowest and highest confidence of its findings on secrets it caught.
    pub caught_confidence: Option<[u8; 2]>,
}

#[derive(Serialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DocumentResult {
    pub name: String,
    /// The scan saved for this document in the session; get_scan reads its findings.
    pub scan_id: i64,
    pub truncated: bool,
    pub partial: bool,
    pub suppressed_count: i64,
    pub cases: Vec<CaseResult>,
    /// Findings that overlap no labeled case.
    pub unlabeled: Vec<FindingBrief>,
    pub rule_errors: Vec<RuleErrorBrief>,
}

#[derive(Serialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CaseResult {
    pub id: String,
    /// The generated case's kind, or `custom` for a case of your own.
    pub kind: String,
    pub expect: Expect,
    pub rule_id: Option<i64>,
    pub rule_name: Option<String>,
    pub line: usize,
    pub outcome: Outcome,
    /// Every finding that overlaps the case, from any rule.
    pub findings: Vec<FindingBrief>,
    pub note: String,
}

#[derive(Clone, Serialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FindingBrief {
    pub finding_id: i64,
    pub rule_id: i64,
    pub rule_name: String,
    pub line: usize,
    pub column: usize,
    pub confidence: u8,
    /// 0–100, higher is more likely an example; null for unsafe handling.
    pub placeholder_score: Option<u8>,
    pub checksum_valid: Option<bool>,
    pub in_comment: bool,
    pub value_class: Option<ValueClassBrief>,
    /// True when the rule's pattern didn't match the value and only a parsed key/value pair
    /// under one of its key names found it.
    pub from_parsed_pair: bool,
}

#[derive(Clone, Deserialize, Serialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ValueClassBrief {
    pub label: String,
    pub credential: u8,
    pub non_secret: u8,
    pub placeholder: u8,
}

#[derive(Clone, Serialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleErrorBrief {
    pub rule_id: i64,
    pub rule_name: String,
    pub field: String,
    pub code: String,
    pub message: String,
}

#[utoipa::path(
    post,
    path = "/api/rule-set-versions/{id}/test-data",
    tag = "Testing",
    summary = "Generate test data for a rule set version",
    description = "Labeled cases for each enabled pattern rule, built from the rule's own pattern \
                   and checked against it: a positive (with a valid checksum when the rule has \
                   one), a broken-checksum copy, a copy with a placeholder from the set's \
                   placeholder rules inside it, lookalikes with a changed prefix, one character \
                   short, or too little randomness, and, for likely credentials with key names, \
                   assignments in `.env`, YAML, and JSON files. Plus a file of ordinary values \
                   that aren't secrets. The same version and seed always give the same data. \
                   Every value is made up, and nothing is stored.",
    params(("id" = i64, Path, description = "Rule set version id")),
    request_body = GenerateTestData,
    responses(
        (status = 200, description = "Generated documents and cases", body = TestData),
        (status = 404, description = "No such rule set version", body = ErrorResponse),
        (status = 422, description = "A listed rule isn't in the version", body = ErrorResponse)
    )
)]
pub async fn create_test_data(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(request): Json<GenerateTestData>,
) -> Result<Json<TestData>, ApiError> {
    Ok(Json(test_data(&state, id, request).await?))
}

#[utoipa::path(
    post,
    path = "/api/scan-sessions/{scan_session_id}/test-runs",
    tag = "Testing",
    summary = "Run a labeled test suite in a scan session",
    description = "Scans each document (the version's generated test data, documents of your \
                   own, or both) as a scan in the session, then compares each labeled case with \
                   the findings that overlap it: caught, missed, false alarm, or scored as \
                   example or real, with each finding's confidence and placeholderScore. \
                   Diagnostics point at rule problems the run showed. The text is never stored \
                   or logged: the scans and findings are saved as usual, and the labels exist \
                   only in this report. The session's suppressions apply.",
    params(("scan_session_id" = i64, Path, description = "The scan session to scan in")),
    request_body = RunTestSuite,
    responses(
        (status = 201, description = "Scans saved; the report", body = TestRunReport),
        (status = 400, description = "Nothing to scan, an empty document, or too many documents", body = ErrorResponse),
        (status = 404, description = "No such scan session", body = ErrorResponse),
        (status = 413, description = "A document is over 1 MB", body = ErrorResponse),
        (status = 422, description = "A case's value isn't in its document, an unknown rule, a repeated case id, or no enabled rules", body = ErrorResponse)
    )
)]
pub async fn create_test_run(
    State(state): State<AppState>,
    Path(scan_session_id): Path<i64>,
    Json(request): Json<RunTestSuite>,
) -> Result<(StatusCode, Json<TestRunReport>), ApiError> {
    let report = run_test_suite(&state, scan_session_id, request).await?;
    Ok((StatusCode::CREATED, Json(report)))
}

impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::NotFound(message) => ApiError::NotFound(message),
            StoreError::Invalid(message) => ApiError::Unprocessable(message),
            StoreError::RulesInvalid(_) => {
                ApiError::Unprocessable("The version's rules fail their checks.".into())
            }
            StoreError::Database(error) => ApiError::Internal(format!("Internal error: {error}")),
        }
    }
}

/// A version's rules as the engine reads them.
struct VersionRules {
    version_id: i64,
    rule_set: RuleSet,
}

impl VersionRules {
    async fn load(state: &AppState, version_id: i64) -> Result<Self, ApiError> {
        let version = state
            .db
            .call(move |connection| Ok(store::get_version(connection, version_id)))
            .await
            .map_err(StoreError::Database)??;
        let rules = version
            .rules
            .into_iter()
            .map(|rule| {
                let definition: RuleDefinition =
                    serde_json::from_value(rule.definition).map_err(|error| {
                        ApiError::Internal(format!(
                            "Internal error: rule {} in version {version_id}: {error}",
                            rule.rule_id
                        ))
                    })?;
                Ok(Rule {
                    id: rule.rule_id,
                    definition,
                })
            })
            .collect::<Result<_, ApiError>>()?;
        Ok(VersionRules {
            version_id,
            rule_set: RuleSet { rules },
        })
    }

    fn rule(&self, rule_id: i64) -> Option<&Rule> {
        self.rule_set.rules.iter().find(|rule| rule.id == rule_id)
    }

    fn name(&self, rule_id: i64) -> String {
        self.rule(rule_id)
            .and_then(|rule| rule.definition.name.as_deref())
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map_or_else(|| format!("Rule {rule_id}"), String::from)
    }

    /// Generates the version's test data off the async runtime.
    async fn generate(
        &self,
        request: GenerateTestData,
    ) -> Result<(u64, secrets_scanner_engine::TestSuite), ApiError> {
        if let Some(rule_ids) = &request.rule_ids
            && let Some(unknown) = rule_ids.iter().find(|&&id| self.rule(id).is_none())
        {
            return Err(ApiError::Unprocessable(format!(
                "Rule {unknown} isn't in rule set version {}.",
                self.version_id
            )));
        }
        let seed = request.seed.unwrap_or(DEFAULT_SEED);
        let rule_set = self.rule_set.clone();
        let suite = tokio::task::spawn_blocking(move || {
            generate_test_data(&rule_set, request.rule_ids.as_deref(), seed)
        })
        .await
        .map_err(|error| ApiError::Internal(format!("Internal error: {error}")))?;
        Ok((seed, suite))
    }

    fn skipped(&self, suite: &secrets_scanner_engine::TestSuite) -> Vec<SkippedCase> {
        suite
            .skipped
            .iter()
            .map(|skipped| SkippedCase {
                rule_id: skipped.rule_id,
                rule_name: Some(self.name(skipped.rule_id)),
                kind: kind_name(skipped.kind),
                reason: skipped.reason.clone(),
            })
            .collect()
    }
}

fn kind_name(kind: CaseKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|value| value.as_str().map(String::from))
        .unwrap_or_default()
}

fn line_of(text: &str, position: usize) -> usize {
    text[..position].matches('\n').count() + 1
}

/// Generates test data for a rule set version. Shared by the REST route and the MCP
/// `generate_test_data` tool.
pub async fn test_data(
    state: &AppState,
    version_id: i64,
    request: GenerateTestData,
) -> Result<TestData, ApiError> {
    let version = VersionRules::load(state, version_id).await?;
    let (seed, suite) = version.generate(request).await?;
    let skipped = version.skipped(&suite);
    let documents = suite
        .documents
        .into_iter()
        .map(|document| GeneratedDocument {
            cases: document
                .cases
                .into_iter()
                .map(|case| GeneratedCase {
                    rule_name: case.rule_id.map(|rule_id| version.name(rule_id)),
                    kind: kind_name(case.kind),
                    expect: case.expect.into(),
                    value: document.text[case.start..case.end].to_string(),
                    line: line_of(&document.text, case.start),
                    id: case.id,
                    rule_id: case.rule_id,
                    start: case.start,
                    end: case.end,
                    note: case.note,
                })
                .collect(),
            name: document.name,
            text: document.text,
        })
        .collect();
    Ok(TestData {
        rule_set_version_id: version_id,
        seed,
        documents,
        skipped,
    })
}

/// A document to scan with its cases located.
struct Document {
    name: String,
    text: String,
    cases: Vec<Case>,
}

struct Case {
    id: String,
    kind: String,
    expect: Expect,
    rule_id: Option<i64>,
    start: usize,
    end: usize,
    note: String,
}

/// Locates each case of a document of the caller's own, without echoing any of its text.
fn locate(
    document: TestDocumentInput,
    version: &VersionRules,
    ids: &mut HashSet<String>,
) -> Result<Document, ApiError> {
    let name = document.name.trim().to_string();
    if document.text.trim().is_empty() {
        return Err(ApiError::BadRequest(format!(
            "Document \"{name}\" has no text to scan."
        )));
    }
    if document.text.len() > MAX_INPUT_BYTES {
        return Err(ApiError::TooLarge(format!(
            "Document \"{name}\" is {} bytes; the limit is {MAX_INPUT_BYTES} bytes (1 MB).",
            document.text.len()
        )));
    }
    let mut cases = Vec::new();
    for (index, case) in document.cases.into_iter().enumerate() {
        let id = case
            .id
            .map(|id| id.trim().to_string())
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| format!("{name}#{}", index + 1));
        if !ids.insert(id.clone()) {
            return Err(ApiError::Unprocessable(format!(
                "Case id \"{id}\" is used more than once."
            )));
        }
        let occurrence = case.occurrence.unwrap_or(1);
        let start = (!case.value.is_empty() && occurrence > 0)
            .then(|| {
                document
                    .text
                    .match_indices(&case.value)
                    .nth(occurrence - 1)
                    .map(|(start, _)| start)
            })
            .flatten()
            .ok_or_else(|| {
                ApiError::Unprocessable(format!(
                    "Case \"{id}\": its value doesn't occur {} in document \"{name}\".",
                    if occurrence == 1 {
                        "at all".to_string()
                    } else {
                        format!("{occurrence} times")
                    }
                ))
            })?;
        let rule_id = match (case.rule_id, case.rule_name) {
            (Some(_), Some(_)) => {
                return Err(ApiError::Unprocessable(format!(
                    "Case \"{id}\": give ruleId or ruleName, not both."
                )));
            }
            (Some(rule_id), None) => {
                Some(version.rule(rule_id).map(|rule| rule.id).ok_or_else(|| {
                    ApiError::Unprocessable(format!(
                        "Case \"{id}\": rule {rule_id} isn't in rule set version {}.",
                        version.version_id
                    ))
                })?)
            }
            (None, Some(rule_name)) => {
                let wanted = rule_name.trim().to_lowercase();
                Some(
                    version
                        .rule_set
                        .rules
                        .iter()
                        .find(|rule| {
                            rule.definition
                                .name
                                .as_deref()
                                .is_some_and(|name| name.trim().to_lowercase() == wanted)
                        })
                        .map(|rule| rule.id)
                        .ok_or_else(|| {
                            ApiError::Unprocessable(format!(
                                "Case \"{id}\": no rule in rule set version {} is named \
                                 \"{}\".",
                                version.version_id,
                                rule_name.trim()
                            ))
                        })?,
                )
            }
            (None, None) => None,
        };
        cases.push(Case {
            id,
            kind: "custom".into(),
            expect: case.expect,
            rule_id,
            start,
            end: start + case.value.len(),
            note: case.note.unwrap_or_default(),
        });
    }
    Ok(Document {
        name,
        text: document.text,
        cases,
    })
}

/// Scans generated and given documents in a session and reports each case's outcome. Shared by
/// the REST route and the MCP `run_test_suite` tool. The text is never stored or logged.
pub async fn run_test_suite(
    state: &AppState,
    scan_session_id: i64,
    request: RunTestSuite,
) -> Result<TestRunReport, ApiError> {
    let session = state
        .db
        .call(move |connection| Ok(store::get_session(connection, scan_session_id)))
        .await
        .map_err(StoreError::Database)??;
    let version = VersionRules::load(state, session.summary.rule_set_version_id).await?;

    let given = request.documents.unwrap_or_default();
    if request.generated.is_none() && given.is_empty() {
        return Err(ApiError::BadRequest(
            "Nothing to scan: give generated, documents, or both.".into(),
        ));
    }
    let mut documents = Vec::new();
    let mut seed = None;
    let mut skipped = Vec::new();
    let mut ids = HashSet::new();
    if let Some(generate) = request.generated {
        let (used, suite) = version.generate(generate).await?;
        seed = Some(used);
        skipped = version.skipped(&suite);
        for document in suite.documents {
            documents.push(Document {
                name: document.name,
                cases: document
                    .cases
                    .into_iter()
                    .map(|case| {
                        ids.insert(case.id.clone());
                        Case {
                            id: case.id,
                            kind: kind_name(case.kind),
                            expect: case.expect.into(),
                            rule_id: case.rule_id,
                            start: case.start,
                            end: case.end,
                            note: case.note,
                        }
                    })
                    .collect(),
                text: document.text,
            });
        }
    }
    for document in given {
        documents.push(locate(document, &version, &mut ids)?);
    }
    if documents.len() > MAX_TEST_DOCUMENTS {
        return Err(ApiError::BadRequest(format!(
            "A test run scans at most {MAX_TEST_DOCUMENTS} documents; this one has {}.",
            documents.len()
        )));
    }

    let mut results = Vec::new();
    let mut evaluation = Evaluation::new(&version);
    for document in documents {
        let scan = scans::scan_in_session(state, scan_session_id, document.text.clone()).await?;
        results.push(evaluation.document(&document, scan));
    }
    let loaded = models::loaded_models(state);
    Ok(evaluation.report(scan_session_id, seed, results, skipped, &loaded))
}

/// What a saved match says, read back from its violation.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MatchFacts {
    confidence: u8,
    placeholder_score: Option<u8>,
    checksum_valid: Option<bool>,
    in_comment: bool,
    value_class: Option<ValueClassBrief>,
    location: LocationFacts,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LocationFacts {
    start_byte: usize,
    end_byte: usize,
    start_line: usize,
    start_column: usize,
}

#[derive(Deserialize)]
struct ErrorFacts {
    field: String,
    code: String,
    message: String,
}

struct Found {
    brief: FindingBrief,
    start: usize,
    end: usize,
    /// The whole matched text has spacing, quotes, or a `:`, so it holds more than a token.
    wide: bool,
}

impl Found {
    fn is_example(&self) -> bool {
        self.brief
            .placeholder_score
            .is_some_and(|score| score >= EXAMPLE_SCORE)
    }
}

/// One case's outcome, with the findings that counted for it.
struct Judged {
    expect: Expect,
    rule_id: Option<i64>,
    outcome: Outcome,
    case_id: String,
    counted: Vec<FindingBrief>,
}

/// Collects each document's results, then the per-rule tallies and diagnostics.
struct Evaluation<'v> {
    version: &'v VersionRules,
    outcomes: Vec<Judged>,
    /// Findings on no case, by rule.
    unlabeled: BTreeMap<i64, Vec<FindingBrief>>,
    /// Lowest confidence of a finding whose whole match holds more than a token, by rule.
    wide: BTreeMap<i64, u8>,
    /// Case ids each rule found only through parsed key/value pairs.
    parsed_pairs: BTreeMap<i64, (usize, Vec<String>)>,
    rule_errors: BTreeMap<i64, RuleErrorBrief>,
    suppressed: Vec<(String, i64)>,
    truncated: Vec<String>,
}

impl<'v> Evaluation<'v> {
    fn new(version: &'v VersionRules) -> Self {
        Evaluation {
            version,
            outcomes: Vec::new(),
            unlabeled: BTreeMap::new(),
            wide: BTreeMap::new(),
            parsed_pairs: BTreeMap::new(),
            rule_errors: BTreeMap::new(),
            suppressed: Vec::new(),
            truncated: Vec::new(),
        }
    }

    fn found(&self, text: &str, finding: &FindingResponse) -> Option<Found> {
        let facts: MatchFacts = serde_json::from_value(finding.violation.clone()).ok()?;
        let (start, end) = (facts.location.start_byte, facts.location.end_byte);
        let rule = self.version.rule(finding.rule_id);
        let from_parsed_pair = rule.is_some_and(|rule| {
            rule.definition.detection_type == Some(DetectionType::LikelyCredential)
                && !rule.definition.key_names.is_empty()
                && !pattern_matches_value(rule, text, start, end)
        });
        let has_value_group = rule
            .and_then(|rule| rule.definition.pattern.as_deref())
            .is_some_and(|pattern| pattern.contains("?P<value>") || pattern.contains("?<value>"));
        let wide = !has_value_group
            && !from_parsed_pair
            && text
                .get(start..end)
                .is_some_and(|matched| matched.contains([' ', '\n', '\t', '"', '\'', ':']));
        Some(Found {
            brief: FindingBrief {
                finding_id: finding.id,
                rule_id: finding.rule_id,
                rule_name: self.version.name(finding.rule_id),
                line: facts.location.start_line,
                column: facts.location.start_column,
                confidence: facts.confidence,
                placeholder_score: facts.placeholder_score,
                checksum_valid: facts.checksum_valid,
                in_comment: facts.in_comment,
                value_class: facts.value_class,
                from_parsed_pair,
            },
            start,
            end,
            wide,
        })
    }

    fn document(&mut self, document: &Document, scan: scans::ScanResponse) -> DocumentResult {
        let mut found = Vec::new();
        let mut rule_errors = Vec::new();
        for finding in &scan.findings {
            if finding.kind == "rule_error" {
                if let Ok(error) = serde_json::from_value::<ErrorFacts>(finding.violation.clone()) {
                    let brief = RuleErrorBrief {
                        rule_id: finding.rule_id,
                        rule_name: self.version.name(finding.rule_id),
                        field: error.field,
                        code: error.code,
                        message: error.message,
                    };
                    rule_errors.push(brief.clone());
                    self.rule_errors.entry(finding.rule_id).or_insert(brief);
                }
                continue;
            }
            if let Some(found_match) = self.found(&document.text, finding) {
                found.push(found_match);
            }
        }
        for found_match in &found {
            if found_match.wide && found_match.brief.confidence < DILUTED_CONFIDENCE {
                let lowest = self
                    .wide
                    .entry(found_match.brief.rule_id)
                    .or_insert(u8::MAX);
                *lowest = (*lowest).min(found_match.brief.confidence);
            }
        }

        let mut cases = Vec::new();
        for case in &document.cases {
            let overlapping: Vec<&Found> = found
                .iter()
                .filter(|found| found.start < case.end && case.start < found.end)
                .collect();
            let counted: Vec<&Found> = overlapping
                .iter()
                .copied()
                .filter(|found| {
                    case.expect == Expect::Example
                        || case
                            .rule_id
                            .is_none_or(|rule_id| found.brief.rule_id == rule_id)
                })
                .collect();
            let outcome = match case.expect {
                Expect::Secret if counted.is_empty() => Outcome::Missed,
                Expect::Secret if counted.iter().all(|found| found.is_example()) => {
                    Outcome::CaughtAsExample
                }
                Expect::Secret => Outcome::Caught,
                Expect::Example if counted.is_empty() => Outcome::NotReported,
                Expect::Example if counted.iter().all(|found| found.is_example()) => {
                    Outcome::FlaggedAsExample
                }
                Expect::Example => Outcome::ScoredAsReal,
                Expect::NotSecret if counted.is_empty() => Outcome::Ignored,
                Expect::NotSecret => Outcome::FalseAlarm,
            };
            for found in &overlapping {
                if found.brief.from_parsed_pair {
                    let entry = self
                        .parsed_pairs
                        .entry(found.brief.rule_id)
                        .or_insert((0, Vec::new()));
                    entry.0 += 1;
                    if !entry.1.contains(&case.id) {
                        entry.1.push(case.id.clone());
                    }
                }
            }
            let briefs: Vec<FindingBrief> = overlapping
                .iter()
                .map(|found| found.brief.clone())
                .collect();
            self.outcomes.push(Judged {
                expect: case.expect,
                rule_id: case.rule_id,
                outcome,
                case_id: case.id.clone(),
                counted: counted.iter().map(|found| found.brief.clone()).collect(),
            });
            cases.push(CaseResult {
                id: case.id.clone(),
                kind: case.kind.clone(),
                expect: case.expect,
                rule_id: case.rule_id,
                rule_name: case.rule_id.map(|rule_id| self.version.name(rule_id)),
                line: line_of(&document.text, case.start),
                outcome,
                findings: briefs,
                note: case.note.clone(),
            });
        }

        let unlabeled: Vec<FindingBrief> = found
            .iter()
            .filter(|found| {
                !document
                    .cases
                    .iter()
                    .any(|case| found.start < case.end && case.start < found.end)
            })
            .map(|found| found.brief.clone())
            .collect();
        for found in &unlabeled {
            if found.from_parsed_pair {
                self.parsed_pairs
                    .entry(found.rule_id)
                    .or_insert((0, Vec::new()))
                    .0 += 1;
            }
            self.unlabeled
                .entry(found.rule_id)
                .or_default()
                .push(found.clone());
        }
        if scan.suppressed_count > 0 {
            self.suppressed
                .push((document.name.clone(), scan.suppressed_count));
        }
        if scan.truncated {
            self.truncated.push(document.name.clone());
        }
        DocumentResult {
            name: document.name.clone(),
            scan_id: scan.scan_id,
            truncated: scan.truncated,
            partial: scan.partial,
            suppressed_count: scan.suppressed_count,
            cases,
            unlabeled,
            rule_errors,
        }
    }

    fn report(
        self,
        scan_session_id: i64,
        seed: Option<u64>,
        documents: Vec<DocumentResult>,
        skipped: Vec<SkippedCase>,
        loaded: &[ModelResponse],
    ) -> TestRunReport {
        let mut summary = TestSummary {
            cases: self.outcomes.len(),
            unlabeled_findings: self.unlabeled.values().map(Vec::len).sum(),
            rule_errors: self.rule_errors.len(),
            ..TestSummary::default()
        };
        for judged in &self.outcomes {
            let count = match judged.outcome {
                Outcome::Caught => &mut summary.caught,
                Outcome::CaughtAsExample => &mut summary.caught_as_example,
                Outcome::Missed => &mut summary.missed,
                Outcome::FlaggedAsExample => &mut summary.flagged_as_example,
                Outcome::ScoredAsReal => &mut summary.scored_as_real,
                Outcome::NotReported => &mut summary.not_reported,
                Outcome::Ignored => &mut summary.ignored,
                Outcome::FalseAlarm => &mut summary.false_alarms,
            };
            *count += 1;
        }

        let rules = self
            .version
            .rule_set
            .rules
            .iter()
            .filter(|rule| {
                rule.definition
                    .detection_type
                    .is_none_or(DetectionType::creates_findings)
            })
            .map(|rule| {
                let mine = |rule_id: &Option<i64>| *rule_id == Some(rule.id);
                let mut result = RuleResult {
                    rule_id: rule.id,
                    rule_name: self.version.name(rule.id),
                    detection_type: rule
                        .definition
                        .detection_type
                        .and_then(|detection_type| serde_json::to_value(detection_type).ok())
                        .and_then(|value| value.as_str().map(String::from)),
                    enabled: rule.definition.is_enabled(),
                    cases: self
                        .outcomes
                        .iter()
                        .filter(|judged| mine(&judged.rule_id))
                        .count(),
                    caught: 0,
                    missed: 0,
                    false_alarms: 0,
                    unlabeled_findings: self.unlabeled.get(&rule.id).map_or(0, Vec::len),
                    caught_confidence: None,
                };
                for Judged {
                    expect,
                    rule_id,
                    outcome,
                    counted,
                    ..
                } in &self.outcomes
                {
                    let by_rule: Vec<&FindingBrief> = counted
                        .iter()
                        .filter(|found| found.rule_id == rule.id)
                        .collect();
                    match (expect, outcome) {
                        (Expect::Secret, Outcome::Caught | Outcome::CaughtAsExample)
                            if mine(rule_id) =>
                        {
                            result.caught += 1;
                            for found in by_rule {
                                let [low, high] =
                                    result.caught_confidence.unwrap_or([u8::MAX, u8::MIN]);
                                result.caught_confidence =
                                    Some([low.min(found.confidence), high.max(found.confidence)]);
                            }
                        }
                        (Expect::Secret, Outcome::Missed) if mine(rule_id) => result.missed += 1,
                        (Expect::NotSecret, Outcome::FalseAlarm) if !by_rule.is_empty() => {
                            result.false_alarms += 1
                        }
                        _ => {}
                    }
                }
                result
            })
            .collect();

        let diagnostics = self.diagnostics(&skipped, loaded);
        TestRunReport {
            scan_session_id,
            rule_set_version_id: self.version.version_id,
            seed,
            summary,
            diagnostics,
            rules,
            documents,
            skipped,
        }
    }

    fn diagnostics(&self, skipped: &[SkippedCase], loaded: &[ModelResponse]) -> Vec<Diagnostic> {
        let version = self.version;
        let diagnostic =
            |code: &str, rule_id: Option<i64>, case_ids: Vec<String>, message| Diagnostic {
                code: code.into(),
                rule_id,
                rule_name: rule_id.map(|rule_id| version.name(rule_id)),
                case_ids,
                message,
            };
        let mut diagnostics = Vec::new();

        for (&rule_id, error) in &self.rule_errors {
            if error.code != "model_unavailable" {
                continue;
            }
            let fitting: Vec<String> = loaded
                .iter()
                .map(|model| format!("{} ({})", model.id, model.sha256))
                .collect();
            diagnostics.push(diagnostic(
                "model_unavailable",
                Some(rule_id),
                Vec::new(),
                format!(
                    "{} couldn't run: {} Rules name models by sha256, so a retrained model makes \
                     older versions' rules unavailable until a new version names its new hash. \
                     Loaded models: {}.",
                    error.rule_name,
                    error.message,
                    if fitting.is_empty() {
                        "none".to_string()
                    } else {
                        fitting.join(", ")
                    }
                ),
            ));
        }

        for (&rule_id, (count, case_ids)) in &self.parsed_pairs {
            diagnostics.push(diagnostic(
                "parsed_pair_only",
                Some(rule_id),
                case_ids.clone(),
                format!(
                    "{} reported {count} value(s) its pattern didn't match, through parsed \
                     key/value pairs: on a likely_credential rule, keyNames also checks every \
                     JSON, YAML, and .env pair whose key holds one of the names. If only the \
                     pattern's syntax should count, remove keyNames and put the names in the \
                     pattern, or make it a direct_credential rule.",
                    version.name(rule_id)
                ),
            ));
        }

        for (&rule_id, &lowest) in &self.wide {
            diagnostics.push(diagnostic(
                "no_value_group",
                Some(rule_id),
                Vec::new(),
                format!(
                    "{} has no value group, so its whole match, including the syntax around the \
                     secret, is the value: randomness, the placeholder check, and the checksum \
                     all read that span, which dilutes them (its lowest confidence here was \
                     {lowest}). Put the secret alone in a (?P<value>...) group, and keep the \
                     syntax outside it.",
                    version.name(rule_id)
                ),
            ));
        }

        // Examples some finding scored as real, by the rule that did.
        let mut scored_real: BTreeMap<i64, (Vec<String>, u8, u8, bool)> = BTreeMap::new();
        for Judged {
            expect,
            rule_id: case_rule,
            outcome,
            case_id,
            counted,
        } in &self.outcomes
        {
            if *expect != Expect::Example || *outcome != Outcome::ScoredAsReal {
                continue;
            }
            for found in counted.iter().filter(|found| {
                found
                    .placeholder_score
                    .is_none_or(|score| score < EXAMPLE_SCORE)
            }) {
                let entry = scored_real.entry(found.rule_id).or_insert((
                    Vec::new(),
                    u8::MAX,
                    u8::MIN,
                    false,
                ));
                if !entry.0.contains(case_id) {
                    entry.0.push(case_id.clone());
                }
                entry.1 = entry.1.min(found.confidence);
                entry.2 = entry.2.max(found.confidence);
                entry.3 |= case_rule.is_some_and(|rule_id| rule_id != found.rule_id);
            }
        }
        for (rule_id, (case_ids, low, high, other)) in scored_real {
            let range = if low == high {
                format!("{low}")
            } else {
                format!("{low}–{high}")
            };
            let overlap = if other {
                " Some of them were made for another rule: a failed checksum or a placeholder \
                 only marks the findings of a rule that checks it, so an overlapping rule \
                 matching the same value scores it on its own evidence."
            } else {
                ""
            };
            diagnostics.push(diagnostic(
                "example_scored_as_real",
                Some(rule_id),
                case_ids.clone(),
                format!(
                    "{} scored {} example case(s) as real (confidence {range}, placeholderScore \
                     under {EXAMPLE_SCORE}).{overlap} A placeholder rule matching inside the \
                     value, or a narrower overlapping rule, marks them as examples.",
                    version.name(rule_id),
                    case_ids.len()
                ),
            ));
        }

        // False alarms a value classifier only lowered.
        let mut lowered: BTreeMap<i64, Vec<String>> = BTreeMap::new();
        let not_credential = |found: &FindingBrief| {
            found
                .value_class
                .as_ref()
                .is_some_and(|class| class.label != "credential")
        };
        for Judged {
            expect,
            outcome,
            case_id,
            counted,
            ..
        } in &self.outcomes
        {
            if *expect == Expect::NotSecret && *outcome == Outcome::FalseAlarm {
                for found in counted.iter().filter(|found| not_credential(found)) {
                    lowered
                        .entry(found.rule_id)
                        .or_default()
                        .push(case_id.clone());
                }
            }
        }
        for found in self.unlabeled.values().flatten() {
            if not_credential(found) {
                lowered.entry(found.rule_id).or_default();
            }
        }
        for (rule_id, case_ids) in lowered {
            diagnostics.push(diagnostic(
                "classifier_only_lowered",
                Some(rule_id),
                case_ids,
                format!(
                    "{}'s value classifier rated some reported values as not credentials and \
                     lowered their confidence to 30, but a value classifier never drops a \
                     finding, so they are still reported. Treat confidence 30 as a likely false \
                     alarm, or narrow the rule's pattern or key names.",
                    version.name(rule_id)
                ),
            ));
        }

        for skipped in skipped
            .iter()
            .filter(|skipped| skipped.kind == "wrong_prefix")
        {
            diagnostics.push(diagnostic(
                "prefix_not_enforced",
                Some(skipped.rule_id),
                Vec::new(),
                skipped.reason.clone(),
            ));
        }
        for (name, count) in &self.suppressed {
            diagnostics.push(diagnostic(
                "suppressed",
                None,
                Vec::new(),
                format!(
                    "{count} match(es) in \"{name}\" were left out by the session's \
                     suppressions, so cases they cover read as missed or not reported. Run the \
                     suite in a new session to see every match."
                ),
            ));
        }
        for name in &self.truncated {
            diagnostics.push(diagnostic(
                "truncated",
                None,
                Vec::new(),
                format!(
                    "\"{name}\" had more findings than the cap of 200, so later cases may read \
                     as missed. A rule that hits the cap is usually too broad."
                ),
            ));
        }
        diagnostics
    }
}
