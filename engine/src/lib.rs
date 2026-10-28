//! The detection engine: a pure library that scans text against a rule set.
//!
//! It does no I/O of its own. Callers (the API today, a CLI later) hand it the text and the
//! rules, and get back findings plus log events to write wherever they like. Nothing it returns
//! contains the scanned text or a matched value.

mod checksum;
mod defaults;
mod format;
mod location;
mod models;
mod password_shape;
mod rules;
mod scan;

pub use checksum::{Checksum, ChecksumEncoding, Crc32Checksum};
pub use defaults::default_rule_set;
pub use format::Format;
pub use location::Location;
pub use models::{ModelLoadError, Models};
pub use password_shape::PasswordShape;
pub use rules::{
    DetectionType, ErrorCode, ModelRef, Rule, RuleCheck, RuleDefinition, RuleError, RuleField,
    RuleSet, RuleWarning, Severity, WarningCode, check_rule, check_rule_set,
};
pub use scan::{
    Finding, FindingKind, LogEvent, MAX_FINDINGS, MAX_INPUT_BYTES, MIN_DETECTION_BYTES,
    MatchDetails, ModelAssessment, ModelVerdict, ScanError, ScanResult, Violation, scan,
    scan_with_models,
};
