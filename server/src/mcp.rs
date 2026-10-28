//! An MCP server, mounted on the API at `/mcp`, for reading and writing rules, rule sets and
//! their versions, scan sessions, and scans. It goes through the same storage rules as the rest of the
//! API (see `store`), and `run_scan` uses the same path as the scan endpoint, so scan text is
//! never stored or logged here either.

use crate::routes::AppState;
use crate::routes::scans::{self, ApiError, ScanResponse};
use crate::store::{
    self, RuleRecord, RuleSetRecord, RuleSetSummary, RuleSetVersionRecord, RuleSetVersionSummary,
    ScanSessionRecord, ScanSessionSummary, StoreError,
};
use rmcp::{
    ErrorData, Json, ServerHandler,
    handler::server::{router::tool::ToolRouter, tool::IntoCallToolResult, wrapper::Parameters},
    model::{
        CallToolResponse, CallToolResult, ContentBlock, Implementation, ServerCapabilities,
        ServerConfig,
    },
    tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use rusqlite::Connection;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

const INSTRUCTIONS: &str = "Manages the secrets scanner's rules, rule sets and their versions, scan \
sessions, and scans. Rules exist on their own and start as drafts, which are not validated. A rule \
set is a named line of versions (names are unique, ignoring case); a new set starts empty or with \
an exact copy of any version. A version is added to a set from a list of rule ids: the rules are \
checked as a set, and each one's current definition is snapshotted into the version, so later rule \
edits never change a saved version. Versions are numbered within their set. Saved versions can only \
be archived or restored. A scan session uses one version; each scan in it \
runs that version's snapshots. Scan text is never stored, and findings never contain matched \
values. Before writing or changing a rule, read rule_authoring_guide: it explains every mechanism a \
rule is built from (patterns and their value and key groups, detection types, key names, entropy, \
checksums, password shape, placeholders, model rules), when to use each and why, and how each \
built-in rule is assembled from them.";

const DEFINITION_HELP: &str = "The rule's definition as canonical JSON. Every field is optional \
while drafting, and unknown fields are rejected. Fields: name (string); enabled (boolean, default \
true); detectionType (direct_credential, likely_credential, unsafe_handling, or \
placeholder_vs_real); severity (high, medium, or low; not used by placeholder_vs_real); pattern \
(a Rust regex: a named group `value` narrows the finding to the secret, a named group `key` is \
checked against keyNames); prefix (the public prefix shown as the redacted preview); keyNames \
(string array); minEntropy (0 to 8 bits per character); checksum ({\"algorithm\": \"luhn\"}, \
{\"algorithm\": \"base58check\"}, or {\"algorithm\": \"crc32\", \"encoding\": \
\"base62\"|\"base36\"|\"hex\", \"prefixLength\": n, \"length\": n}); passwordShape \
({\"minScore\": 1 to 10}, built for likely_credential); remediation (string); model ({\"id\": string, \
\"sha256\": 64 hex characters}) and threshold (0 to 100), for model_assessment and model_detection \
only. rule_authoring_guide explains what each field does, when to use it, and why.";

/// The MCP service, ready to mount on the API router.
pub fn service(state: AppState) -> StreamableHttpService<ScannerMcp, LocalSessionManager> {
    let config = StreamableHttpServerConfig::default()
        // Every tool is a single request and response, so no session state is kept.
        .with_legacy_session_mode(false)
        .with_json_response(true)
        // Room for a full 1 MB scan once escaped as JSON, matching the API's own body limit.
        .with_max_request_body_bytes(16 * 1024 * 1024)
        // Loopback hosts only (the default), and no browser origins: these tools write, so a web
        // page must not be able to call them through the user's browser.
        .enforce_origin_validation();
    StreamableHttpService::new(
        move || Ok(ScannerMcp::new(state.clone())),
        Default::default(),
        config,
    )
}

/// A tool failure the caller can act on, returned as a tool error rather than a protocol error
/// so the model sees the message.
pub struct ToolError(String);

impl From<StoreError> for ToolError {
    fn from(error: StoreError) -> Self {
        ToolError(match error {
            StoreError::NotFound(message) | StoreError::Invalid(message) => message,
            StoreError::RulesInvalid(check) => format!(
                "The rules failed their checks, so nothing was saved. Fix these and try \
                 again:\n{}",
                serde_json::to_string_pretty(&check).expect("a rule check always serializes")
            ),
            StoreError::Database(error) => format!("Internal error: {error}"),
        })
    }
}

impl From<ApiError> for ToolError {
    fn from(error: ApiError) -> Self {
        ToolError(error.message().to_string())
    }
}

impl IntoCallToolResult for ToolError {
    fn into_call_tool_result(self) -> Result<CallToolResponse, ErrorData> {
        Ok(CallToolResult::error(vec![ContentBlock::text(self.0)]).into())
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListRulesParams {
    /// Only drafts (true) or only rules that have been added into a version (false). Omit for
    /// all rules.
    drafting: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleIdParams {
    rule_id: i64,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateRuleParams {
    #[schemars(description = DEFINITION_HELP)]
    definition: Option<Map<String, Value>>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateRuleParams {
    rule_id: i64,
    /// Replaces the whole definition; fields left out are cleared.
    #[schemars(description = DEFINITION_HELP)]
    definition: Map<String, Value>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleIdsParams {
    /// The rules to check together, as they would be checked when saved into one version.
    rule_ids: Vec<i64>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListVersionsParams {
    /// Only this rule set's versions. Omit for every set's.
    rule_set_id: Option<i64>,
    /// Include archived versions. Defaults to false, matching the timeline.
    include_archived: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListRuleSetsParams {
    /// Include archived rule sets. Defaults to false.
    include_archived: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleSetIdParams {
    rule_set_id: i64,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateRuleSetParams {
    /// Required, unique among rule sets ignoring case, at most 80 characters.
    name: String,
    description: Option<String>,
    /// Start the set with an exact copy of this version, from any rule set. Omit to start empty.
    from_version_id: Option<i64>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateRuleSetParams {
    rule_set_id: i64,
    name: Option<String>,
    description: Option<String>,
    /// Archived sets are hidden, can't get new versions, and can't start new scan sessions.
    archived: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VersionIdParams {
    version_id: i64,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateVersionParams {
    /// The rule set the version is added to.
    rule_set_id: i64,
    /// The version this one is based on, from the same rule set, recorded for the timeline. Its rules are not copied:
    /// list every rule the new version should hold in ruleIds.
    parent_id: Option<i64>,
    /// Every rule the new version holds. Each is snapshotted from its current definition.
    rule_ids: Vec<i64>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetArchivedParams {
    version_id: i64,
    archived: bool,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionIdParams {
    session_id: i64,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateSessionParams {
    rule_set_version_id: i64,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanIdParams {
    scan_id: i64,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunScanParams {
    session_id: i64,
    /// The text to scan, up to 1 MB. It is never stored or logged.
    text: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuideParams {
    /// One section of the guide, by id (see the tool description). Omit for the whole guide.
    topic: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub struct RuleGuide {
    /// Every section id, in reading order.
    topics: Vec<String>,
    /// The section returned, or none for the whole guide.
    topic: Option<String>,
    /// The guide text, as Markdown.
    text: String,
}

/// How to build rules from the engine's mechanisms, served by `rule_authoring_guide`.
const RULE_GUIDE: &str = include_str!("rule_guide.md");

/// The guide's sections as (id, text), split at its `## ` headings. The id is the heading in
/// lowercase with spaces as dashes, e.g. "Detection types" is `detection-types`.
fn guide_sections() -> Vec<(String, &'static str)> {
    RULE_GUIDE
        .split("\n## ")
        .skip(1)
        .map(|section| {
            let heading = section.lines().next().unwrap_or_default();
            let id = heading.trim().to_lowercase().replace(' ', "-");
            (id, section)
        })
        .collect()
}

#[derive(Serialize, JsonSchema)]
pub struct RuleList {
    rules: Vec<RuleRecord>,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleDetail {
    #[serde(flatten)]
    rule: RuleRecord,
    /// The versions that hold a snapshot of this rule.
    rule_set_version_ids: Vec<i64>,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Deleted {
    deleted_rule_id: i64,
}

#[derive(Serialize, JsonSchema)]
pub struct RuleCheckResult {
    valid: bool,
    /// Problems that stop a rule from being saved into a version, each keyed by rule id and
    /// field.
    errors: Value,
    /// Worth fixing, but they don't block saving.
    warnings: Value,
}

#[derive(Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetList {
    rule_sets: Vec<RuleSetSummary>,
}

#[derive(Serialize, JsonSchema)]
pub struct VersionList {
    versions: Vec<RuleSetVersionSummary>,
}

#[derive(Serialize, JsonSchema)]
pub struct CreatedVersion {
    version: RuleSetVersionRecord,
    /// Warnings from the check. They didn't block saving.
    warnings: Value,
}

#[derive(Serialize, JsonSchema)]
pub struct SessionList {
    sessions: Vec<ScanSessionSummary>,
}

#[derive(Clone)]
pub struct ScannerMcp {
    state: AppState,
    tool_router: ToolRouter<Self>,
}

impl ScannerMcp {
    pub fn new(state: AppState) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
        }
    }

    /// Runs `work` against the database off the async runtime.
    async fn with_db<T, F>(&self, work: F) -> Result<T, ToolError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> store::StoreResult<T> + Send + 'static,
    {
        self.state
            .db
            .call(move |connection| Ok(work(connection)))
            .await
            .map_err(StoreError::Database)?
            .map_err(ToolError::from)
    }
}

#[tool_router]
impl ScannerMcp {
    #[tool(
        description = "How to build rules: every mechanism a rule definition can use, when to use \
                       it, and why, with recipes for each kind of built-in rule. Read it before \
                       creating or changing rules. Sections: overview, workflow, detection-types, \
                       patterns, key-names, entropy, checksums, password-shape, placeholders, \
                       models, scoring, parsing, validation, recipes, pitfalls. Omit topic for \
                       the whole guide.",
        annotations(read_only_hint = true)
    )]
    async fn rule_authoring_guide(
        &self,
        Parameters(params): Parameters<GuideParams>,
    ) -> Result<Json<RuleGuide>, ToolError> {
        let sections = guide_sections();
        let topics: Vec<String> = sections.iter().map(|(id, _)| id.clone()).collect();
        let text = match &params.topic {
            None => RULE_GUIDE.to_string(),
            Some(topic) => match sections.iter().find(|(id, _)| id == topic) {
                Some((_, section)) => format!("## {}", section.trim_end()),
                None => {
                    return Err(ToolError(format!(
                        "There is no guide section \"{topic}\". Sections: {}.",
                        topics.join(", ")
                    )));
                }
            },
        };
        Ok(Json(RuleGuide {
            topics,
            topic: params.topic,
            text,
        }))
    }

    #[tool(
        description = "List rules with their current definitions.",
        annotations(read_only_hint = true)
    )]
    async fn list_rules(
        &self,
        Parameters(params): Parameters<ListRulesParams>,
    ) -> Result<Json<RuleList>, ToolError> {
        let rules = self
            .with_db(move |connection| store::list_rules(connection, params.drafting))
            .await?;
        Ok(Json(RuleList { rules }))
    }

    #[tool(
        description = "Get one rule's current definition and the versions it is in.",
        annotations(read_only_hint = true)
    )]
    async fn get_rule(
        &self,
        Parameters(params): Parameters<RuleIdParams>,
    ) -> Result<Json<RuleDetail>, ToolError> {
        self.with_db(move |connection| {
            Ok(RuleDetail {
                rule: store::get_rule(connection, params.rule_id)?,
                rule_set_version_ids: store::rule_version_ids(connection, params.rule_id)?,
            })
        })
        .await
        .map(Json)
    }

    #[tool(
        description = "Create a draft rule. Drafts are stored right away but not validated; \
                       they are checked when added into a rule set version. Omit the definition \
                       to start an empty draft.",
        annotations(destructive_hint = false)
    )]
    async fn create_rule(
        &self,
        Parameters(params): Parameters<CreateRuleParams>,
    ) -> Result<Json<RuleRecord>, ToolError> {
        let definition =
            store::parse_definition(Value::Object(params.definition.unwrap_or_default()))?;
        self.with_db(move |connection| store::create_rule(connection, &definition))
            .await
            .map(Json)
    }

    #[tool(
        description = "Replace a rule's definition. A draft saves as-is; a rule that is already \
                       in a rule set version must pass the same checks as saving a version, or \
                       nothing is saved and the errors are returned. Saved rule set versions \
                       keep their own snapshots, so this only affects versions created \
                       afterwards.",
        annotations(idempotent_hint = true)
    )]
    async fn update_rule(
        &self,
        Parameters(params): Parameters<UpdateRuleParams>,
    ) -> Result<Json<RuleRecord>, ToolError> {
        let definition = store::parse_definition(Value::Object(params.definition))?;
        self.with_db(move |connection| store::update_rule(connection, params.rule_id, &definition))
            .await
            .map(Json)
    }

    #[tool(
        description = "Delete a draft rule. Rules already in a rule set version can't be \
                       deleted; leave them out of the next version or disable them instead.",
        annotations(destructive_hint = true)
    )]
    async fn delete_rule(
        &self,
        Parameters(params): Parameters<RuleIdParams>,
    ) -> Result<Json<Deleted>, ToolError> {
        self.with_db(move |connection| store::delete_draft_rule(connection, params.rule_id))
            .await?;
        Ok(Json(Deleted {
            deleted_rule_id: params.rule_id,
        }))
    }

    #[tool(
        description = "Check rules as one set, with the same checks saving a rule set version \
                       runs: required fields, ranges, pattern compilation, and duplicate names. \
                       Saves nothing.",
        annotations(read_only_hint = true)
    )]
    async fn check_rules(
        &self,
        Parameters(params): Parameters<RuleIdsParams>,
    ) -> Result<Json<RuleCheckResult>, ToolError> {
        let check = self
            .with_db(move |connection| store::check_rules(connection, &params.rule_ids))
            .await?;
        Ok(Json(RuleCheckResult {
            valid: check.is_valid(),
            errors: to_value(&check.errors),
            warnings: to_value(&check.warnings),
        }))
    }

    #[tool(
        description = "List rule sets in creation order, with each one's version count and \
                       latest version.",
        annotations(read_only_hint = true)
    )]
    async fn list_rule_sets(
        &self,
        Parameters(params): Parameters<ListRuleSetsParams>,
    ) -> Result<Json<RuleSetList>, ToolError> {
        let include_archived = params.include_archived.unwrap_or(false);
        let rule_sets = self
            .with_db(move |connection| store::list_rule_sets(connection, include_archived))
            .await?;
        Ok(Json(RuleSetList { rule_sets }))
    }

    #[tool(
        description = "Get a rule set with every one of its versions, oldest first.",
        annotations(read_only_hint = true)
    )]
    async fn get_rule_set(
        &self,
        Parameters(params): Parameters<RuleSetIdParams>,
    ) -> Result<Json<RuleSetRecord>, ToolError> {
        self.with_db(move |connection| store::get_rule_set(connection, params.rule_set_id))
            .await
            .map(Json)
    }

    #[tool(
        description = "Create a named rule set. It starts empty, or with an exact copy of \
                       fromVersionId (a version from any set) as its first version.",
        annotations(destructive_hint = false)
    )]
    async fn create_rule_set(
        &self,
        Parameters(params): Parameters<CreateRuleSetParams>,
    ) -> Result<Json<RuleSetRecord>, ToolError> {
        self.with_db(move |connection| {
            store::create_rule_set(
                connection,
                &params.name,
                params.description.as_deref().unwrap_or(""),
                params.from_version_id,
            )
        })
        .await
        .map(Json)
    }

    #[tool(
        description = "Rename, redescribe, archive, or restore a rule set. Only the fields given \
                       change, and its versions never do.",
        annotations(destructive_hint = false, idempotent_hint = true)
    )]
    async fn update_rule_set(
        &self,
        Parameters(params): Parameters<UpdateRuleSetParams>,
    ) -> Result<Json<RuleSetSummary>, ToolError> {
        self.with_db(move |connection| {
            store::update_rule_set(
                connection,
                params.rule_set_id,
                params.name.as_deref(),
                params.description.as_deref(),
                params.archived,
            )
        })
        .await
        .map(Json)
    }

    #[tool(
        description = "List rule set versions, oldest first: every set's, or one set's.",
        annotations(read_only_hint = true)
    )]
    async fn list_rule_set_versions(
        &self,
        Parameters(params): Parameters<ListVersionsParams>,
    ) -> Result<Json<VersionList>, ToolError> {
        let include_archived = params.include_archived.unwrap_or(false);
        let versions = self
            .with_db(move |connection| {
                store::list_versions(connection, params.rule_set_id, include_archived)
            })
            .await?;
        Ok(Json(VersionList { versions }))
    }

    #[tool(
        description = "Get a rule set version with the rule definitions it saved. These \
                       snapshots are what scans in its sessions run.",
        annotations(read_only_hint = true)
    )]
    async fn get_rule_set_version(
        &self,
        Parameters(params): Parameters<VersionIdParams>,
    ) -> Result<Json<RuleSetVersionRecord>, ToolError> {
        self.with_db(move |connection| store::get_version(connection, params.version_id))
            .await
            .map(Json)
    }

    #[tool(
        description = "Save a new version of a rule set holding exactly the listed rules, each \
                          snapshotted from its current definition. The rules are checked as a \
                          set first; if any check fails nothing is saved and the errors are \
                          returned. Draft rules stop being drafts once saved into a version.",
        annotations(destructive_hint = false)
    )]
    async fn create_rule_set_version(
        &self,
        Parameters(params): Parameters<CreateVersionParams>,
    ) -> Result<Json<CreatedVersion>, ToolError> {
        let (version, check) = self
            .with_db(move |connection| {
                store::create_version(
                    connection,
                    params.rule_set_id,
                    params.parent_id,
                    &params.rule_ids,
                )
            })
            .await?;
        Ok(Json(CreatedVersion {
            version,
            warnings: to_value(&check.warnings),
        }))
    }

    #[tool(
        description = "Archive or restore a rule set version. Archived versions are hidden from \
                       the timeline and can't start new scan sessions; nothing is deleted. This \
                       is the only change a saved version allows.",
        annotations(destructive_hint = false, idempotent_hint = true)
    )]
    async fn set_rule_set_version_archived(
        &self,
        Parameters(params): Parameters<SetArchivedParams>,
    ) -> Result<Json<RuleSetVersionSummary>, ToolError> {
        self.with_db(move |connection| {
            store::set_version_archived(connection, params.version_id, params.archived)
        })
        .await
        .map(Json)
    }

    #[tool(
        description = "List scan sessions, newest first.",
        annotations(read_only_hint = true)
    )]
    async fn list_scan_sessions(&self) -> Result<Json<SessionList>, ToolError> {
        let sessions = self
            .with_db(|connection| store::list_sessions(connection))
            .await?;
        Ok(Json(SessionList { sessions }))
    }

    #[tool(
        description = "Get a scan session and a summary of each of its scans.",
        annotations(read_only_hint = true)
    )]
    async fn get_scan_session(
        &self,
        Parameters(params): Parameters<SessionIdParams>,
    ) -> Result<Json<ScanSessionRecord>, ToolError> {
        self.with_db(move |connection| store::get_session(connection, params.session_id))
            .await
            .map(Json)
    }

    #[tool(
        description = "Start a scan session on a rule set version. Archived versions can't \
                          be used.",
        annotations(destructive_hint = false)
    )]
    async fn create_scan_session(
        &self,
        Parameters(params): Parameters<CreateSessionParams>,
    ) -> Result<Json<ScanSessionSummary>, ToolError> {
        self.with_db(move |connection| {
            store::create_session(connection, params.rule_set_version_id)
        })
        .await
        .map(Json)
    }

    #[tool(
        description = "Get a saved scan and its findings. Findings hold rule, location, scores, \
                       and a redacted preview, never the matched text.",
        annotations(read_only_hint = true)
    )]
    async fn get_scan(
        &self,
        Parameters(params): Parameters<ScanIdParams>,
    ) -> Result<Json<ScanResponse>, ToolError> {
        let scan_id = params.scan_id;
        self.with_db(move |connection| Ok(scans::load_scan(connection, scan_id)?))
            .await?
            .map(Json)
            .ok_or_else(|| ToolError(format!("Scan {scan_id} not found.")))
    }

    #[tool(
        description = "Scan text with the session's rule set version and save the scan and \
                          its findings to the session. The text is never stored or logged. \
                          Findings are capped at 200.",
        annotations(destructive_hint = false)
    )]
    async fn run_scan(
        &self,
        Parameters(params): Parameters<RunScanParams>,
    ) -> Result<Json<ScanResponse>, ToolError> {
        Ok(Json(
            scans::scan_in_session(&self.state, params.session_id, params.text).await?,
        ))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for ScannerMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "secrets-scanner",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(INSTRUCTIONS)
    }
}

fn to_value(value: &impl Serialize) -> Value {
    serde_json::to_value(value).expect("rule check results always serialize")
}
