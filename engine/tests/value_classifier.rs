//! The trained value classifier in `models/`, run as the value classifier setting on the two
//! high-entropy built-in rules (4, secret-looking assignment, and 12, password-shaped value).
//! The texts here are written by hand, not taken from the training generator.
#![cfg(feature = "ml")]

use secrets_scanner_engine::{
    ErrorCode, MatchDetails, Models, RuleField, VALUE_CLASSIFIER_ONNX, VALUE_CLASSIFIER_SHA256,
    ValueLabel, Violation, default_rule_set, scan_with_models, value_classifier_setting,
};

/// The one finding a text produces, with the classifier on rules 4 and 12.
fn finding(text: &str) -> MatchDetails {
    let mut models = Models::new();
    models
        .load(VALUE_CLASSIFIER_ONNX)
        .expect("the trained model should load");
    let mut rule_set = default_rule_set();
    for rule in &mut rule_set.rules {
        if rule.id == 4 || rule.id == 12 {
            rule.definition.value_classifier = Some(value_classifier_setting());
        }
    }
    let result = scan_with_models(1, text, &rule_set, &models).expect("scan should run");
    let [found] = result.findings.as_slice() else {
        panic!(
            "expected one finding in {text:?}, got {:?}",
            result.findings
        );
    };
    match &found.violation {
        Violation::Match(details) => details.clone(),
        Violation::RuleError(error) => panic!("unexpected rule error: {error:?}"),
    }
}

fn label(details: &MatchDetails) -> ValueLabel {
    details
        .value_class
        .expect("the rule has a classifier")
        .label
}

#[test]
fn the_model_loads_under_the_hash_its_setting_names() {
    let mut models = Models::new();
    assert_eq!(
        models.load(VALUE_CLASSIFIER_ONNX).unwrap(),
        VALUE_CLASSIFIER_SHA256
    );
}

#[test]
fn credentials_are_rated_credentials_and_keep_their_confidence() {
    for text in [
        "database:\n  password: q8Z!fP2xL7mR\n",
        "SECRET_KEY=Kq3vT8wZ1pLm6Ns9Rx2Bf5Hj\n",
        "admin_password: Summer2024!\n",
    ] {
        let details = finding(text);
        assert_eq!(label(&details), ValueLabel::Credential, "{text:?}");
        assert!(details.confidence > 30, "{text:?}: {}", details.confidence);
        assert!(details.why_flagged.contains("rates it a credential"));
        assert!(details.confidence <= 95, "{text:?}: {}", details.confidence);
    }
}

#[test]
fn hashes_and_ids_under_secret_sounding_names_are_non_secret_with_low_confidence() {
    for text in [
        "api_key_id: 6f1c2a3e-9b4d-4e8f-a1c2-3d4e5f6a7b8c\n",
        "password_hash: sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n",
        "secret_checksum = \"3f786850e387550fdab836ed7e6dc881de23001b\"\n",
    ] {
        let details = finding(text);
        assert_eq!(label(&details), ValueLabel::NonSecret, "{text:?}");
        assert_eq!(details.confidence, 30, "{text:?}");
        assert!(details.why_flagged.contains("non-secret string"));
    }
}

#[test]
fn urls_and_paths_are_not_rated_credentials() {
    for text in [
        "token_url: https://auth.example.com/oauth2/token\n",
        "secret_version: projects/acme/secrets/db-password/versions/3\n",
    ] {
        let details = finding(text);
        assert_ne!(label(&details), ValueLabel::Credential, "{text:?}");
        assert_eq!(details.confidence, 30, "{text:?}");
    }
}

#[test]
fn placeholders_are_rated_placeholders_and_count_as_examples() {
    for text in [
        "smtp:\n  password: \"P@ssw0rd-CHANGE-ME\"\n",
        "api_key: \"your_api_key_here_123\"\n",
    ] {
        let details = finding(text);
        assert_eq!(label(&details), ValueLabel::Placeholder, "{text:?}");
        assert_eq!(details.confidence, 30, "{text:?}");
        assert!(details.placeholder_score >= Some(70), "{text:?}");
        assert!(details.why_flagged.contains("rates it a placeholder"));
    }
}

#[test]
fn rules_without_the_setting_are_not_classified() {
    let details = finding("aws_access_key_id = AKIAZ7Q3LMN4XWY2PRT6\n");
    assert_eq!(details.value_class, None);
    assert_eq!(details.confidence, 97);
}

#[test]
fn a_classifier_that_was_not_loaded_is_a_rule_error_for_its_rule() {
    let mut rule_set = default_rule_set();
    rule_set.rules[3].definition.value_classifier = Some(value_classifier_setting());
    let result = scan_with_models(1, "password: q8Z!fP2xL7mR\n", &rule_set, &Models::new())
        .expect("scan should run");
    let errors: Vec<_> = result
        .findings
        .iter()
        .filter_map(|finding| match &finding.violation {
            Violation::RuleError(error) => Some((error.rule_id, error.field, error.code)),
            Violation::Match(_) => None,
        })
        .collect();
    assert_eq!(
        errors,
        [(4, RuleField::ValueClassifier, ErrorCode::ModelUnavailable)]
    );
}

#[test]
fn other_lines_do_not_change_a_value_s_class() {
    let alone = finding("api_key: \"your_api_key_here_123\"\n");
    let mut models = Models::new();
    models.load(VALUE_CLASSIFIER_ONNX).unwrap();
    let mut rule_set = default_rule_set();
    rule_set.rules[3].definition.value_classifier = Some(value_classifier_setting());
    let text = "database:\n  password_hash: sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\napi_key: \"your_api_key_here_123\"\nAWS_ACCESS_KEY_ID=AKIAZ7Q3LMN4XWY2PRT6\n";
    let result = scan_with_models(1, text, &rule_set, &models).unwrap();
    let placeholder = result
        .findings
        .iter()
        .find_map(|finding| match &finding.violation {
            Violation::Match(details) if details.location.start_line == 3 => Some(details),
            _ => None,
        })
        .expect("the placeholder line should be a finding");
    assert_eq!(placeholder.value_class, alone.value_class);
}

#[test]
fn a_credential_score_above_the_rule_s_confidence_raises_it_halfway() {
    let details = finding("database:\n  password: q8Z!fP2xL7mR\n");
    let class = details.value_class.unwrap();
    assert!(class.credential > 92, "{class:?}");
    assert_eq!(details.confidence, 92 + (class.credential - 92) / 2);
    assert!(details.why_flagged.contains(&format!(
        "raising confidence from 92 to {}",
        details.confidence
    )));
}
