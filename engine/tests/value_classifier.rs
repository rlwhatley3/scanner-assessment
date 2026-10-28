//! The trained value classifier in `models/`, run through the engine by its model assessment rule.
//! The texts here are written by hand, not taken from the training generator.
#![cfg(feature = "ml")]

use secrets_scanner_engine::{
    ModelVerdict, Models, Rule, ScanResult, VALUE_CLASSIFIER_ONNX, VALUE_CLASSIFIER_SHA256,
    Violation, default_rule_set, scan_with_models, value_classifier_rule,
};

fn assess(text: &str) -> ScanResult {
    let mut models = Models::new();
    models
        .load(VALUE_CLASSIFIER_ONNX)
        .expect("the trained model should load");
    let mut rule_set = default_rule_set();
    rule_set.rules.push(Rule {
        id: 100,
        definition: value_classifier_rule(),
    });
    scan_with_models(1, text, &rule_set, &models).expect("scan should run")
}

/// Every model verdict in the result, with its score, so a failure shows what the model said.
fn verdicts(result: &ScanResult) -> Vec<(ModelVerdict, u8)> {
    result
        .findings
        .iter()
        .map(|finding| match &finding.violation {
            Violation::Match(details) => details,
            Violation::RuleError(error) => panic!("unexpected rule error: {error:?}"),
        })
        .flat_map(|details| &details.model_assessments)
        .map(|assessment| (assessment.verdict, assessment.score))
        .collect()
}

fn assert_all(text: &str, expected: ModelVerdict) {
    let found = verdicts(&assess(text));
    assert!(!found.is_empty(), "nothing was assessed in {text:?}");
    assert!(
        found.iter().all(|&(verdict, _)| verdict == expected),
        "expected {expected:?} for {text:?}, got {found:?}"
    );
}

// Built from pieces so no token-shaped string sits in the source for secret scanners.
fn github_token() -> String {
    ["ghp", "_Q7wErT5yUi9oP3aSd1fGh8jK2lZx6cVb4nM0"].concat()
}

#[test]
fn the_model_loads_under_the_hash_its_rule_names() {
    let mut models = Models::new();
    assert_eq!(
        models.load(VALUE_CLASSIFIER_ONNX).unwrap(),
        VALUE_CLASSIFIER_SHA256
    );
}

#[test]
fn a_key_in_an_env_file_is_likely_real() {
    assert_all(
        "AWS_REGION=us-west-2\nAWS_ACCESS_KEY_ID=AKIAZ7Q3LMN4XWY2PRT6\n",
        ModelVerdict::LikelyReal,
    );
}

#[test]
fn a_token_in_ci_settings_is_likely_real() {
    assert_all(
        &format!(
            "jobs:\n  release:\n    env:\n      GH_TOKEN: {}\n",
            github_token()
        ),
        ModelVerdict::LikelyReal,
    );
}

#[test]
fn a_password_in_yaml_config_is_likely_real() {
    assert_all(
        "database:\n  host: pg.prod\n  password: q8Z!fP2xL7mR\n",
        ModelVerdict::LikelyReal,
    );
}

#[test]
fn the_aws_documentation_key_is_likely_an_example() {
    assert_all(
        "To configure the CLI, for example:\n\n    aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
        ModelVerdict::LikelyExample,
    );
}

#[test]
fn a_token_in_a_unit_test_is_likely_an_example() {
    assert_all(
        &format!(
            "def test_hides_token_in_logs():\n    token = \"{}\"\n    assert scrub(token) == \"***\"\n",
            github_token()
        ),
        ModelVerdict::LikelyExample,
    );
}

#[test]
fn a_placeholder_under_a_secret_name_is_likely_an_example() {
    assert_all(
        "settings:\n  api_key: \"your_api_key_here_123\"\n",
        ModelVerdict::LikelyExample,
    );
}

#[test]
fn a_password_marked_change_me_is_likely_an_example() {
    assert_all(
        "smtp:\n  password: \"P@ssw0rd-CHANGE-ME\"\n",
        ModelVerdict::LikelyExample,
    );
}

#[test]
fn an_example_comment_on_other_lines_does_not_make_a_real_key_an_example() {
    assert_all(
        "AWS_REGION=us-west-2\nAWS_ACCESS_KEY_ID=AKIAZ7Q3LMN4XWY2PRT6\n\n# Example from the docs:\n",
        ModelVerdict::LikelyReal,
    );
}
