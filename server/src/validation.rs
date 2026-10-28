//! Checks rule definitions with the engine before they can join a rule set version.
//!
//! A definition is stored as JSON, so it is first parsed into the engine's `RuleDefinition`
//! (which rejects unknown fields and wrong types), then run through the engine's own
//! `check_rule` / `check_rule_set`. Every saved version therefore parses and compiles exactly
//! as the scan endpoint will load it.

use secrets_scanner_engine::{self as engine, Rule, RuleDefinition};
use serde::Serialize;
use serde_json::Value;

/// A problem that stops a rule from being added to a rule set version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleError {
    pub rule_id: i64,
    /// The definition field at fault, in snake_case (e.g. `pattern`, `min_entropy`), or
    /// `definition` when the JSON itself doesn't fit the rule shape.
    pub field: String,
    /// The engine's error code (`required`, `invalid_regex`, `too_large`, `out_of_range`,
    /// `duplicate_name`), or `invalid_definition`.
    pub code: String,
    pub message: String,
    /// Byte range within the field's value, when known.
    pub span: Option<(usize, usize)>,
}

/// Worth showing, but does not stop the rule from being saved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuleWarning {
    pub rule_id: i64,
    pub field: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Default, Serialize, utoipa::ToSchema)]
pub struct RuleCheck {
    pub errors: Vec<RuleError>,
    pub warnings: Vec<RuleWarning>,
}

/// Checks one rule's definition on its own.
pub fn check_rule(rule_id: i64, definition: &Value) -> RuleCheck {
    check_rule_set(&[(rule_id, definition.clone())])
}

/// Checks every rule, plus the checks that span rules (no two rules share a name).
pub fn check_rule_set(rules: &[(i64, Value)]) -> RuleCheck {
    let mut check = RuleCheck::default();
    let mut parsed = Vec::with_capacity(rules.len());
    for (rule_id, definition) in rules {
        match serde_json::from_value::<RuleDefinition>(definition.clone()) {
            Ok(definition) => parsed.push(Rule {
                id: *rule_id,
                definition,
            }),
            Err(error) => check.errors.push(RuleError {
                rule_id: *rule_id,
                field: "definition".to_owned(),
                code: "invalid_definition".to_owned(),
                message: format!("This rule's settings don't fit the rule shape: {error}."),
                span: None,
            }),
        }
    }

    let engine_check = engine::check_rule_set(&parsed);
    check
        .errors
        .extend(engine_check.errors.into_iter().map(|error| RuleError {
            rule_id: error.rule_id,
            field: name_of(&error.field),
            code: name_of(&error.code),
            message: error.message,
            span: error.span,
        }));
    check.warnings.extend(
        engine_check
            .warnings
            .into_iter()
            .map(|warning| RuleWarning {
                rule_id: warning.rule_id,
                field: name_of(&warning.field),
                code: name_of(&warning.code),
                message: warning.message,
            }),
    );
    check
}

/// The snake_case name the engine serializes a field or code enum as.
fn name_of(value: &impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}
