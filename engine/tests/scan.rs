use secrets_scanner_engine::{
    ErrorCode, FindingKind, Format, MAX_FINDINGS, MAX_INPUT_BYTES, MatchDetails, Rule,
    RuleDefinition, RuleField, ScanError, ScanResult, Violation, default_rule_set, github_checksum,
    scan,
};

const AWS_KEY: &str = "AKIAZ7Q3LMN4XWY2PRT6";
const GITHUB_TOKEN: &str = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
const RANDOM_PASSWORD: &str = "q8Z!fP2xL7mR";

/// Scans with the built-in rule set: ids 1–6 are the AWS key, GitHub token, private key,
/// assignment, logging, and known placeholder values rules.
fn run(text: &str) -> ScanResult {
    scan(42, text, &default_rule_set()).expect("scan should run")
}

fn matches(result: &ScanResult) -> Vec<&MatchDetails> {
    result
        .findings
        .iter()
        .filter_map(|finding| match &finding.violation {
            Violation::Match(details) => Some(details),
            Violation::RuleError(_) => None,
        })
        .collect()
}

#[test]
fn finds_an_aws_key_with_its_location_and_a_prefix_only_preview() {
    let result = run(&format!(
        "aws_region = us-east-1\naws_access_key_id = {AWS_KEY}\n"
    ));
    let found = matches(&result);
    assert_eq!(found.len(), 1);
    let aws = found[0];
    assert_eq!(result.findings[0].rule_id, 1);
    assert_eq!(result.findings[0].kind, FindingKind::Match);
    assert_eq!(
        (aws.location.start_line, aws.location.start_column),
        (2, 21)
    );
    assert_eq!(
        aws.location.end_byte - aws.location.start_byte,
        AWS_KEY.len()
    );
    assert_eq!(aws.redacted_preview.as_deref(), Some("AKIA…"));
    assert_eq!(aws.confidence, 95);
    assert_eq!(aws.placeholder_score, Some(5));
    assert_eq!(
        result.findings[0].violation_pretty,
        "AWS access key (high) at line 2, column 21"
    );
    assert!(!result.truncated);
}

#[test]
fn the_aws_documentation_example_key_scores_as_a_placeholder() {
    let result = run("key: AKIAIOSFODNN7EXAMPLE");
    let found = matches(&result);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].placeholder_score, Some(95));
    assert!(found[0].why_flagged.contains("known placeholder"));
}

#[test]
fn a_token_assigned_to_a_secret_name_is_two_findings_in_one_overlap_group() {
    let result = run(&format!("token = \"{GITHUB_TOKEN}\""));
    let found = matches(&result);
    let rules: Vec<i64> = result
        .findings
        .iter()
        .map(|finding| finding.rule_id)
        .collect();
    assert_eq!(rules, [2, 4]);
    assert_eq!(found[0].location, found[1].location);
    assert_eq!(found[0].overlap_group, Some(1));
    assert_eq!(found[1].overlap_group, Some(1));
}

#[test]
fn separate_findings_get_no_overlap_group() {
    let result = run(&format!("a = {AWS_KEY}\nb = {GITHUB_TOKEN}"));
    assert!(
        matches(&result)
            .iter()
            .all(|found| found.overlap_group.is_none())
    );
}

#[test]
fn a_private_key_block_is_one_finding_across_its_lines() {
    let result =
        run("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n");
    let found = matches(&result);
    assert_eq!(found.len(), 1);
    assert_eq!(
        (found[0].location.start_line, found[0].location.end_line),
        (1, 3)
    );
    assert_eq!(found[0].redacted_preview.as_deref(), Some("-----BEGIN…"));
}

#[test]
fn a_private_key_header_without_its_end_line_is_still_caught() {
    let result = run("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk");
    assert_eq!(matches(&result).len(), 1);
}

#[test]
fn a_likely_credential_needs_a_secret_sounding_name_and_enough_randomness() {
    let found = run(&format!("db_password: {RANDOM_PASSWORD}"));
    let found = matches(&found);
    assert_eq!(found.len(), 1);
    assert!(found[0].why_flagged.contains("bits per character"));
    assert!(found[0].confidence >= 50);

    assert!(matches(&run(&format!("description: {RANDOM_PASSWORD}"))).is_empty());
    assert!(matches(&run("password: aaaaaaaaaaaa")).is_empty());
}

#[test]
fn references_to_a_secret_are_not_secrets() {
    let result = run("password = ${DB_PASSWORD}\napi_key: {{ vault.api_key }}");
    assert!(matches(&result).is_empty());
}

#[test]
fn logging_a_secret_is_unsafe_handling_with_no_value_to_score() {
    let result = run("console.log(\"connecting with\", apiKey);");
    let found = matches(&result);
    assert_eq!(found.len(), 1);
    assert_eq!(result.findings[0].rule_id, 5);
    assert_eq!(found[0].placeholder_score, None);
    assert_eq!(found[0].redacted_preview, None);
    assert!(matches(&run("logger.info(\"user signed in\")")).is_empty());
}

#[test]
fn clean_text_has_no_findings() {
    let result = run("name: demo\nport: 8080\n");
    assert!(result.findings.is_empty());
    assert!(!result.truncated);
}

#[test]
fn nothing_returned_contains_a_matched_secret() {
    let result = run(&format!(
        "aws = {AWS_KEY}\ntoken = {GITHUB_TOKEN}\npassword: {RANDOM_PASSWORD}\n"
    ));
    assert_eq!(matches(&result).len(), 4);
    let output = serde_json::to_string(&result).expect("result should serialize");
    for secret in [AWS_KEY, GITHUB_TOKEN, RANDOM_PASSWORD] {
        assert!(!output.contains(secret), "output leaked {secret}");
    }
}

#[test]
fn log_events_carry_the_scan_id() {
    let result = run(&format!("aws = {AWS_KEY}"));
    assert!(!result.log.is_empty());
    assert!(result.log.iter().all(|event| event.scan_id == 42));
}

#[test]
fn a_broken_rule_becomes_a_rule_error_finding_and_the_others_still_run() {
    let mut rule_set = default_rule_set();
    rule_set.rules.push(Rule {
        id: 99,
        definition: RuleDefinition {
            name: Some("Broken".into()),
            pattern: Some("AKIA(".into()),
            ..rule_set.rules[0].definition.clone()
        },
    });
    let result = scan(1, &format!("k = {AWS_KEY}"), &rule_set).expect("scan should run");
    assert_eq!(matches(&result).len(), 1);
    let error = result
        .findings
        .iter()
        .find(|finding| finding.kind == FindingKind::RuleError)
        .expect("the broken rule should be reported");
    assert_eq!(error.rule_id, 99);
    let Violation::RuleError(details) = &error.violation else {
        panic!("a rule error finding should carry a rule error");
    };
    assert_eq!(
        (details.field, details.code),
        (RuleField::Pattern, ErrorCode::InvalidRegex)
    );
    assert!(details.span.is_some());
    assert!(error.violation_pretty.starts_with("Broken: "));
}

#[test]
fn a_repeated_rule_name_is_a_rule_error_and_the_first_rule_still_runs() {
    let mut rule_set = default_rule_set();
    rule_set.rules.push(Rule {
        id: 6,
        definition: rule_set.rules[0].definition.clone(),
    });
    let result = scan(1, &format!("k = {AWS_KEY}"), &rule_set).expect("scan should run");
    assert_eq!(matches(&result).len(), 1);
    assert_eq!(result.findings[0].rule_id, 1);
    let errors: Vec<i64> = result
        .findings
        .iter()
        .filter(|finding| finding.kind == FindingKind::RuleError)
        .map(|finding| finding.rule_id)
        .collect();
    assert_eq!(errors, [6]);
}

#[test]
fn placeholder_values_on_their_own_are_not_findings() {
    let result = run("# example config; replace changeme before use
mode: test
");
    assert!(result.findings.is_empty());
}

#[test]
fn turning_off_the_placeholder_rule_stops_examples_scoring_as_examples() {
    let mut rule_set = default_rule_set();
    rule_set.rules[5].definition.enabled = Some(false);
    let result = scan(1, "key: AKIAIOSFODNN7EXAMPLE", &rule_set).expect("scan should run");
    assert_eq!(matches(&result)[0].placeholder_score, Some(5));
}

#[test]
fn a_placeholder_only_counts_when_it_falls_inside_the_finding() {
    let result = run(&format!("example key: {AWS_KEY}"));
    assert_eq!(matches(&result)[0].placeholder_score, Some(5));
}

#[test]
fn a_rule_set_with_only_placeholder_rules_enabled_has_nothing_to_find() {
    let mut rule_set = default_rule_set();
    for rule in &mut rule_set.rules {
        rule.definition.enabled = Some(rule.id == 6);
    }
    assert_eq!(scan(1, "text", &rule_set), Err(ScanError::NoRulesEnabled));
}

#[test]
fn disabled_rules_do_not_run_and_none_enabled_is_an_error() {
    let mut rule_set = default_rule_set();
    for rule in &mut rule_set.rules {
        rule.definition.enabled = Some(rule.id != 2);
    }
    let result = scan(1, &format!("token = {GITHUB_TOKEN}"), &rule_set).expect("scan should run");
    assert!(result.findings.iter().all(|finding| finding.rule_id != 2));

    for rule in &mut rule_set.rules {
        rule.definition.enabled = Some(false);
    }
    assert_eq!(scan(1, "text", &rule_set), Err(ScanError::NoRulesEnabled));
}

#[test]
fn empty_and_oversized_input_are_rejected() {
    let rule_set = default_rule_set();
    assert_eq!(scan(1, "  \n\t ", &rule_set), Err(ScanError::Empty));
    let big = "a".repeat(MAX_INPUT_BYTES + 1);
    assert_eq!(
        scan(1, &big, &rule_set),
        Err(ScanError::TooLarge { bytes: big.len() })
    );
}

#[test]
fn more_than_the_cap_keeps_the_first_findings_in_text_order_and_says_so() {
    let text = format!("k = {AWS_KEY}\n").repeat(MAX_FINDINGS + 50);
    let result = run(&text);
    assert!(result.truncated);
    let found = matches(&result);
    assert_eq!(found.len(), MAX_FINDINGS);
    assert_eq!(found[0].location.start_line, 1);
    assert_eq!(found[MAX_FINDINGS - 1].location.start_line, MAX_FINDINGS);
}

#[test]
fn locations_survive_unicode_and_mixed_line_endings() {
    let result = run(&format!("café = 1\r\nnote = \"🙂\"\rk = {AWS_KEY}"));
    let found = matches(&result);
    assert_eq!(found.len(), 1);
    assert_eq!(
        (found[0].location.start_line, found[0].location.start_column),
        (3, 5)
    );
}

/// A GitHub token whose checksum is valid, built at run time so no real-looking token is
/// committed.
fn valid_github_token() -> String {
    let random = "Zq7Lm2Xc9Vb4Nn6Tt1Rr8Pp3Kk5Hh0";
    format!("ghp_{random}{}", github_checksum(random))
}

#[test]
fn a_token_with_a_valid_checksum_is_high_confidence() {
    let result = run(&format!("gh = {}", valid_github_token()));
    let found = matches(&result);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].checksum_valid, Some(true));
    assert_eq!(found[0].confidence, 99);
    assert_eq!(found[0].placeholder_score, Some(5));
    assert!(found[0].why_flagged.contains("checksum is valid"));
}

#[test]
fn a_token_whose_checksum_fails_is_likely_made_up() {
    let result = run(&format!("gh = {GITHUB_TOKEN}"));
    let found = matches(&result);
    assert_eq!(found[0].checksum_valid, Some(false));
    assert_eq!(found[0].confidence, 50);
    assert_eq!(found[0].placeholder_score, Some(70));
    assert!(found[0].why_flagged.contains("checksum doesn't match"));
}

#[test]
fn rules_without_a_checksum_report_none() {
    let result = run(&format!("k = {AWS_KEY}"));
    assert_eq!(matches(&result)[0].checksum_valid, None);
}

#[test]
fn parsing_json_catches_a_quoted_secret_the_pattern_alone_misses() {
    let secret = "Xk9$mQ2;vL7#pR4w";
    let text = format!("{{\n  \"db\": {{\n    \"password\":\n      \"{secret}\"\n  }}\n}}");
    let result = run(&text);
    assert_eq!(result.format, Format::Json);
    let found = matches(&result);
    assert_eq!(found.len(), 1);
    assert_eq!(result.findings[0].rule_id, 4);
    let location = found[0].location;
    assert_eq!(&text[location.start_byte..location.end_byte], secret);
    assert_eq!(location.start_line, 4);
}

#[test]
fn a_yaml_value_stops_before_its_trailing_comment() {
    let text = format!("db:\n  password: \"{RANDOM_PASSWORD}\"  # rotate monthly\n");
    let result = run(&text);
    assert_eq!(result.format, Format::Yaml);
    let found = matches(&result);
    assert_eq!(found.len(), 1);
    let location = found[0].location;
    assert_eq!(
        &text[location.start_byte..location.end_byte],
        RANDOM_PASSWORD
    );
    assert!(!found[0].in_comment);
}

#[test]
fn a_secret_in_a_comment_still_counts_but_looks_like_an_example() {
    let result = run(&format!(
        "# old key, do not use: {AWS_KEY}\nREGION=us-east-1\n"
    ));
    let found = matches(&result);
    assert_eq!(found.len(), 1);
    assert!(found[0].in_comment);
    assert_eq!(found[0].placeholder_score, Some(70));
    assert!(found[0].why_flagged.contains("in a comment"));
}

#[test]
fn commented_out_logging_is_low_confidence() {
    let result = run("// console.log(\"debug\", token)\nrun();\n");
    let found = matches(&result);
    assert_eq!(found.len(), 1);
    assert!(found[0].in_comment);
    assert_eq!(found[0].confidence, 30);
}

#[test]
fn the_result_says_which_format_the_text_was_read_as() {
    assert_eq!(run("A=1\nB=2\n").format, Format::Dotenv);
    assert_eq!(run("a: 1\nb: 2\n").format, Format::Yaml);
    assert_eq!(run("[1, 2]").format, Format::Json);
    assert_eq!(run("hello there").format, Format::Text);
}
