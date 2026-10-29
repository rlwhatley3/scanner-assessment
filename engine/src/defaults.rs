//! The built-in rule set, seeded as the first rule set version. It lives in
//! `rule_sets/default.json` in the same shape the API sends for a scan, so loading it exercises
//! that contract. Every rule is ordinary data: users can edit, disable, or remove any of them.
//! See `engine/README.md` for what each rule catches, what it misses, and why.

use crate::rules::{DetectionType, ModelRef, RuleDefinition, RuleSet, Severity};

const DEFAULT_RULE_SET: &str = include_str!("../rule_sets/default.json");

pub fn default_rule_set() -> RuleSet {
    serde_json::from_str(DEFAULT_RULE_SET)
        .expect("rule_sets/default.json matches the rule set contract")
}

/// The trained value classifier in `models/`, a model for a model assessment rule. `ml/` has the
/// code that trains it.
pub const VALUE_CLASSIFIER_ONNX: &[u8] = include_bytes!("../models/value-classifier.onnx");

/// The SHA-256 of [`VALUE_CLASSIFIER_ONNX`], which is how a rule names it.
pub const VALUE_CLASSIFIER_SHA256: &str =
    "b72bdda9ee94f1b0820a9c6b9b592233d757186743a78c09ac2677b1a55a8528";

/// A model assessment rule that runs the value classifier. It is kept out of the built-in rule
/// set, which runs without models; callers that load the classifier add it themselves.
pub fn value_classifier_rule() -> RuleDefinition {
    RuleDefinition {
        name: Some("Value classifier".into()),
        detection_type: Some(DetectionType::ModelAssessment),
        model: Some(ModelRef {
            id: Some("value-classifier".into()),
            sha256: Some(VALUE_CLASSIFIER_SHA256.into()),
        }),
        threshold: Some(50),
        ..RuleDefinition::default()
    }
}

/// The trained secret detector in `models/`, a model for a model detection rule: it reads raw
/// text and scores each byte, so it can flag secrets no pattern describes. `ml/` has the code
/// that trains it.
pub const SECRET_DETECTOR_ONNX: &[u8] = include_bytes!("../models/secret-detector.onnx");

/// The SHA-256 of [`SECRET_DETECTOR_ONNX`], which is how a rule names it.
pub const SECRET_DETECTOR_SHA256: &str =
    "cb18c8a0bd783893361a1ef4ff3440c4fe0e50c0a805d8437e612af2261d21c8";

/// A model detection rule that runs the secret detector. Like the value classifier's rule, it is
/// kept out of the built-in rule set; callers that load the detector add it themselves.
pub fn secret_detector_rule() -> RuleDefinition {
    RuleDefinition {
        name: Some("Secret detector".into()),
        detection_type: Some(DetectionType::ModelDetection),
        severity: Some(Severity::Medium),
        model: Some(ModelRef {
            id: Some("secret-detector".into()),
            sha256: Some(SECRET_DETECTOR_SHA256.into()),
        }),
        threshold: Some(50),
        ..RuleDefinition::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn the_value_classifier_hash_matches_its_file() {
        let sha256: String = Sha256::digest(VALUE_CLASSIFIER_ONNX)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(sha256, VALUE_CLASSIFIER_SHA256);
    }

    #[test]
    fn the_secret_detector_hash_matches_its_file() {
        let sha256: String = Sha256::digest(SECRET_DETECTOR_ONNX)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(sha256, SECRET_DETECTOR_SHA256);
    }

    #[test]
    fn the_secret_detector_rule_is_valid() {
        let rule = crate::Rule {
            id: 1,
            definition: secret_detector_rule(),
        };
        assert!(crate::check_rule(&rule).is_valid());
    }

    #[test]
    fn the_value_classifier_rule_is_valid() {
        let rule = crate::Rule {
            id: 1,
            definition: value_classifier_rule(),
        };
        assert!(crate::check_rule(&rule).is_valid());
    }
}
