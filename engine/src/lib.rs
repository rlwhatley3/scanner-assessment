//! The detection engine: a pure library that scans text against a rule set.
//!
//! It does no I/O of its own. Callers (the API today, a CLI later) hand it the text and the
//! rules, and get back findings plus log events to write wherever they like. Nothing it returns
//! contains the scanned text or a matched value.

mod checksum;
mod defaults;
mod fingerprint;
mod format;
mod location;
mod models;
mod password_shape;
mod rules;
mod scan;
mod test_data;

pub use checksum::{Checksum, ChecksumEncoding, Crc32Checksum};
pub use defaults::{
    SECRET_DETECTOR_ONNX, SECRET_DETECTOR_SHA256, VALUE_CLASSIFIER_ONNX, VALUE_CLASSIFIER_SHA256,
    default_rule_set, secret_detector_rule, value_classifier_setting,
};
pub use fingerprint::{FINGERPRINT_KEY_BYTES, FingerprintKey};
pub use format::Format;
pub use location::Location;
pub use models::{ModelInfo, ModelLoadError, ModelUse, Models};
pub use password_shape::PasswordShape;
pub use rules::{
    DetectionType, ErrorCode, ModelRef, Rule, RuleCheck, RuleDefinition, RuleError, RuleField,
    RuleSet, RuleWarning, Severity, ValueClassifierSetting, WarningCode, check_rule,
    check_rule_set,
};
pub use scan::{
    Finding, FindingKind, LogEvent, MAX_FINDINGS, MAX_INPUT_BYTES, MIN_DETECTION_BYTES,
    MatchDetails, ModelAssessment, ModelVerdict, ScanError, ScanOptions, ScanResult, ValueClass,
    ValueLabel, Violation, pattern_matches_value, scan, scan_with_models, scan_with_options,
};
pub use test_data::{
    CaseKind, Expectation, SkippedCase, TestCase, TestDocument, TestSuite, generate_test_data,
};
