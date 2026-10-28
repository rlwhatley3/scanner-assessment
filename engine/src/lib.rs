//! The detection engine: a pure library that scans text against a rule set.
//!
//! It does no I/O of its own. Callers (the API today, a CLI later) hand it the text and the
//! rules, and get back findings plus log events to write wherever they like. Nothing it returns
//! contains the scanned text or a matched value.

mod defaults;
mod location;
mod rules;
mod scan;

pub use defaults::default_rule_set;
pub use location::Location;
pub use rules::{
    DetectionType, ErrorCode, Rule, RuleCheck, RuleDefinition, RuleError, RuleField, RuleSet,
    RuleWarning, Severity, WarningCode, check_rule, check_rule_set,
};
pub use scan::{
    Finding, FindingKind, LogEvent, MAX_FINDINGS, MAX_INPUT_BYTES, MatchDetails, ScanError,
    ScanResult, Violation, scan,
};
