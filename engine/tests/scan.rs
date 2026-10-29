use secrets_scanner_engine::DetectionType;
use secrets_scanner_engine::{
    Checksum, ChecksumEncoding, Crc32Checksum, ErrorCode, FindingKind, Format, MAX_FINDINGS,
    MAX_INPUT_BYTES, MatchDetails, Rule, RuleDefinition, RuleField, RuleSet, ScanError, ScanResult,
    Severity, Violation, default_rule_set, scan,
};

const AWS_KEY: &str = "AKIAZ7Q3LMN4XWY2PRT6";
const GITHUB_TOKEN: &str = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
const RANDOM_PASSWORD: &str = "q8Z!fP2xL7mR";

/// Scans with the built-in rule set: ids 1–12 are the AWS key, GitHub token, private key,
/// assignment, logging, known placeholder values, npm token, GitLab token, legacy GitLab
/// token, payment card number, Bitcoin private key, and password-shaped value rules. Ids 13
/// and up are provider formats and credentials in a known syntax, looked up by name below.
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
    assert_eq!(aws.confidence, 97);
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

    // Without a secret-sounding name the assignment rule skips it; only the password shape
    // fallback reports it, at low severity.
    let result = run(&format!("description: {RANDOM_PASSWORD}"));
    let rule_ids: Vec<i64> = result
        .findings
        .iter()
        .map(|finding| finding.rule_id)
        .collect();
    assert_eq!(rule_ids, [12]);
    assert_eq!(matches(&result)[0].severity.to_string(), "low");
    assert!(matches(&run("password: aaaaaaaaaaaa")).is_empty());
}

#[test]
fn a_made_up_password_under_any_name_is_a_low_severity_finding() {
    for text in [
        "safe_bet: \"myUnencryptedPWHERE\"",
        "safe_bet: myUnencryptedPWHERE",
        "{\"safe_bet\": \"myUnencryptedPWHERE\"}",
    ] {
        let result = run(text);
        let found = matches(&result);
        assert_eq!(found.len(), 1, "{text}");
        assert_eq!(result.findings[0].rule_id, 12, "{text}");
        assert_eq!(found[0].rule_name, "Password-shaped value");
        assert_eq!(found[0].severity.to_string(), "low");
        assert!(
            found[0]
                .why_flagged
                .contains("contains a word common in passwords")
        );
        assert!(
            found[0]
                .why_flagged
                .contains("name doesn't suggest a secret")
        );
        assert!(!found[0].why_flagged.contains("PWHERE"));
        let location = found[0].location;
        assert_eq!(
            &text[location.start_byte..location.end_byte],
            "myUnencryptedPWHERE"
        );
    }
}

#[test]
fn the_password_shape_rule_does_not_repeat_what_another_rule_found() {
    let result = run("password: \"Summer2024!\"");
    let rule_ids: Vec<i64> = result
        .findings
        .iter()
        .map(|finding| finding.rule_id)
        .collect();
    assert_eq!(rule_ids, [4]);
}

#[test]
fn ordinary_config_values_are_not_password_shaped() {
    let text = "name: catalog-service\nregion: us-east-1\nimage: ghcr.io/acme/catalog:1.24.3\n\
                handler: myUnencryptedFileHandler\nurl: \"https://example.com/a/b\"\n\
                level: \"LOG_LEVEL_DEBUG\"\nid: \"1f3a7c2e-8b4d-4e6f-9a1b-2c3d4e5f6a7b\"\n";
    assert!(matches(&run(text)).is_empty());
}

#[test]
fn the_expected_clean_sample_has_no_password_shaped_findings() {
    let text = include_str!("../../tests/clean-lookalikes.yaml");
    let result = run(text);
    assert!(result.findings.iter().all(|finding| finding.rule_id != 12));
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
    format!("ghp_{random}{}", Crc32Checksum::GITHUB.compute(random))
}

#[test]
fn every_github_token_prefix_is_checked_with_the_same_checksum() {
    let random = "Ab3De6Gh9Jk2Mn5Pq8St1Vw4Yz7Bc0";
    let token = format!("gho_{random}{}", Crc32Checksum::GITHUB.compute(random));
    let result = run(&format!("oauth = {token}"));
    let found = matches(&result);
    assert_eq!(result.findings[0].rule_id, 2);
    assert_eq!(found[0].checksum_valid, Some(true));
    assert_eq!(found[0].redacted_preview.as_deref(), Some("gh…"));
}

#[test]
fn npm_tokens_are_found_and_checked_like_github_tokens() {
    let random = "Kx4Mv7Pz1Qr3St6Uw9Yb2Dc5Fg8Hj0";
    let valid = format!("npm_{random}{}", Crc32Checksum::GITHUB.compute(random));
    let result = run(&format!("//registry.npmjs.org/:_authToken={valid}"));
    let found = matches(&result);
    let npm = result
        .findings
        .iter()
        .position(|finding| finding.rule_id == 7)
        .expect("the npm rule should match");
    assert_eq!(found[npm].checksum_valid, Some(true));
    assert_eq!(found[npm].confidence, 99);

    let made_up = format!("npm_{}", "a".repeat(36));
    let result = run(&format!("token: {made_up}"));
    let npm = matches(&result)
        .into_iter()
        .zip(&result.findings)
        .find(|(_, finding)| finding.rule_id == 7)
        .map(|(details, _)| details.clone())
        .expect("the npm rule should match");
    assert_eq!(npm.checksum_valid, Some(false));
}

#[test]
fn a_rule_author_can_describe_their_own_checksum() {
    // An in-house token: "acme_", the covered part, then an 8-digit hex CRC32.
    let setup = Crc32Checksum {
        encoding: ChecksumEncoding::Hex,
        prefix_length: 5,
        length: 8,
    };
    let mut rule_set = default_rule_set();
    rule_set.rules.push(Rule {
        id: 100,
        definition: RuleDefinition {
            name: Some("Acme service key".into()),
            pattern: Some(r"\bacme_[0-9a-f]{20}\b".into()),
            prefix: Some("acme_".into()),
            checksum: Some(Checksum::Crc32(setup)),
            ..rule_set.rules[0].definition.clone()
        },
    });
    let covered = "0123456789ab";
    let valid = format!("acme_{covered}{}", setup.compute(covered));
    let invalid = format!("acme_{covered}00000000");
    let result =
        scan(1, &format!("a = {valid}\nb = {invalid}"), &rule_set).expect("scan should run");
    let found: Vec<Option<bool>> = result
        .findings
        .iter()
        .zip(matches(&result))
        .filter(|(finding, _)| finding.rule_id == 100)
        .map(|(_, details)| details.checksum_valid)
        .collect();
    assert_eq!(found, [Some(true), Some(false)]);
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
    assert_eq!(found[0].confidence, 43);
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
fn a_short_value_is_only_an_example_when_it_repeats_itself() {
    let placeholder_score = |password: &str| {
        let result = run(&format!("ALTER ROLE app WITH PASSWORD '{password}';\n"));
        matches(&result)
            .into_iter()
            .find(|details| details.rule_name == "Password in a SQL statement")
            .expect("the password is reported")
            .placeholder_score
    };
    // Every character differs: as random as a value this short can be.
    assert_eq!(placeholder_score("k7q"), Some(5));
    assert_eq!(placeholder_score("k7qk"), Some(5));
    // Mostly one character.
    assert_eq!(placeholder_score("000"), Some(70));
    assert_eq!(placeholder_score("kkq"), Some(70));
    // From 8 characters on, under 2 bits per character is an example whatever the length.
    assert_eq!(placeholder_score("kkk777qq"), Some(70));
}

#[test]
fn commented_out_logging_is_low_confidence() {
    let result = run("// console.log(\"debug\", token)\nrun();\n");
    let found = matches(&result);
    assert_eq!(found.len(), 1);
    assert!(found[0].in_comment);
    assert_eq!(found[0].confidence, 27);
    assert!(found[0].why_flagged.contains("commented out"));
}

#[test]
fn the_result_says_which_format_the_text_was_read_as() {
    assert_eq!(run("A=1\nB=2\n").format, Format::Dotenv);
    assert_eq!(run("a: 1\nb: 2\n").format, Format::Yaml);
    assert_eq!(run("[1, 2]").format, Format::Json);
    assert_eq!(run("hello there").format, Format::Text);
}

/// The findings from one rule, by rule id.
fn from_rule(result: &ScanResult, rule_id: i64) -> Vec<MatchDetails> {
    result
        .findings
        .iter()
        .zip(matches(result))
        .filter(|(finding, _)| finding.rule_id == rule_id)
        .map(|(_, details)| details.clone())
        .collect()
}

#[test]
fn a_routable_gitlab_token_is_checked_and_not_mistaken_for_the_legacy_format() {
    // Built from pieces so no token-shaped string sits in the source for secret scanners.
    let body = ["glpat", "-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789.01.0w"].concat();
    let token = format!("{body}{}", Crc32Checksum::GITLAB.compute(&body));
    let result = run(&format!("GITLAB_TOKEN={token}\n"));
    let routable = from_rule(&result, 8);
    assert_eq!(routable.len(), 1);
    assert_eq!(routable[0].checksum_valid, Some(true));
    assert_eq!(routable[0].confidence, 99);
    assert!(from_rule(&result, 9).is_empty());
}

#[test]
fn a_legacy_gitlab_token_is_found_without_a_checksum() {
    // Built from pieces so no token-shaped string sits in the source for secret scanners.
    let token = ["glpat", "-Ab1Cd2Ef3Gh4Ij5Kl6Mn"].concat();
    let result = run(&format!("token: {token}\n"));
    let legacy = from_rule(&result, 9);
    assert_eq!(legacy.len(), 1);
    assert_eq!(legacy[0].checksum_valid, None);
    assert!(from_rule(&result, 8).is_empty());
}

#[test]
fn a_card_number_that_passes_luhn_is_high_confidence_and_one_that_fails_is_not() {
    let result = run("card: 4111 1111 1111 1111\nother: 4111 1111 1111 1112\n");
    let cards: Vec<(Option<bool>, u8)> = from_rule(&result, 10)
        .iter()
        .map(|card| (card.checksum_valid, card.confidence))
        .collect();
    assert_eq!(cards, [(Some(true), 93), (Some(false), 2)]);
}

#[test]
fn card_numbers_outside_the_card_ranges_are_not_reported() {
    let result = run("order_id: 1234567812345678\ntimestamp: 9999999999999999\n");
    assert!(from_rule(&result, 10).is_empty());
}

#[test]
fn each_card_network_and_length_the_rule_covers_is_reported() {
    // Published test numbers, one per network and length, in the forms people write them.
    let cards = [
        "4222222222222",       // Visa, 13 digits
        "4111 1111 1111 1111", // Visa
        "4000000000000000006", // Visa, 19 digits
        "5555-5555-5555-4444", // Mastercard
        "2223 0031 2200 3222", // Mastercard 2-series
        "3782 822463 10005",   // Amex
        "6011 0009 9013 9424", // Discover
        "3622 720627 1667",    // Diners Club
        "30569309025904",      // Diners Club
        "3566 0020 2036 0505", // JCB
        "6200 0000 0000 0005", // UnionPay
        "6205500000000000004", // UnionPay, 19 digits
    ];
    let text: String = cards.iter().map(|card| format!("card: {card}\n")).collect();
    let result = run(&text);
    let reported: Vec<&str> = reported_values(&text, &result)
        .into_iter()
        .map(|(_, value)| value)
        .collect();
    assert_eq!(reported, cards);
    assert!(
        from_rule(&result, 10)
            .iter()
            .all(|card| card.checksum_valid == Some(true))
    );
}

#[test]
fn a_card_number_split_once_across_lines_is_reported_but_a_column_of_numbers_is_not() {
    let text = "card was 4000 0566\n  55665556, call back\n";
    let result = run(text);
    assert_eq!(
        reported_values(text, &result),
        [(10, "4000 0566\n  55665556")]
    );
    assert_eq!(from_rule(&result, 10)[0].checksum_valid, Some(true));

    let result = run("ports:\n4000\n4001\n4002\n4003\n");
    assert!(from_rule(&result, 10).is_empty());
}

#[test]
fn a_grouped_card_followed_by_a_cvv_is_reported_without_the_cvv() {
    let text = "card: 4111 1111 1111 1111 123\n";
    let result = run(text);
    assert_eq!(
        reported_values(text, &result),
        [(10, "4111 1111 1111 1111")]
    );
}

#[test]
fn a_bitcoin_private_key_is_checked_with_base58check() {
    // The private key example from the Bitcoin wiki's Wallet Import Format page.
    let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
    let result = run(&format!("wallet_key: {wif}\n"));
    let keys = from_rule(&result, 11);
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].checksum_valid, Some(true));

    let changed = wif.replacen('H', "J", 1);
    let result = run(&format!("wallet_key: {changed}\n"));
    assert_eq!(from_rule(&result, 11)[0].checksum_valid, Some(false));
}

/// The values each rule reported, as (rule id, value) in text order.
fn reported_values<'t>(text: &'t str, result: &ScanResult) -> Vec<(i64, &'t str)> {
    result
        .findings
        .iter()
        .zip(matches(result))
        .map(|(finding, details)| {
            let location = details.location;
            (
                finding.rule_id,
                &text[location.start_byte..location.end_byte],
            )
        })
        .collect()
}

#[test]
fn the_made_up_passwords_yaml_sample_reports_each_password_once() {
    let text = include_str!("../../tests/made-up-passwords.yaml");
    let result = run(text);
    assert_eq!(result.format, Format::Yaml);
    assert_eq!(
        reported_values(text, &result),
        [
            (12, "myUnencryptedPWHERE"),
            (12, "Summer2024!"),
            (12, "Tr0ub4dor&3"),
            (12, "s3cretSauce99"),
            (12, "P@ssw0rd!"),
            (12, "hunter2"),
            (12, "Welcome123!"),
            (4, "Xk9mQ2vL7pR4w!"),
        ]
    );
    assert!(
        matches(&result)
            .iter()
            .filter(|details| details.rule_name == "Password-shaped value")
            .all(|details| details.severity.to_string() == "low")
    );
}

#[test]
fn the_made_up_passwords_json_sample_reports_each_password_once() {
    let text = include_str!("../../tests/made-up-passwords.json");
    let result = run(text);
    assert_eq!(result.format, Format::Json);
    assert_eq!(
        reported_values(text, &result),
        [
            (12, "myUnencryptedPWHERE"),
            (12, "Tr0ub4dor&3"),
            (12, "Summer2024!"),
        ]
    );
}

#[test]
fn the_made_up_passwords_env_sample_reports_each_password_once() {
    let text = include_str!("../../tests/made-up-passwords.env");
    let result = run(text);
    assert_eq!(result.format, Format::Dotenv);
    assert_eq!(
        reported_values(text, &result),
        [
            (12, "myUnencryptedPWHERE"),
            (12, "Kitt3nsRule!"),
            (12, "Welcome123!"),
        ]
    );
}

#[test]
fn the_password_lookalikes_sample_is_clean() {
    let text = include_str!("../../tests/password-lookalikes.yaml");
    let result = run(text);
    assert_eq!(result.format, Format::Yaml);
    assert_eq!(reported_values(text, &result), []);
}

#[test]
fn the_orders_export_sample_reports_each_card_and_no_masked_number_or_order_id() {
    let text = include_str!("../../tests/orders-export.csv");
    let result = run(text);
    assert_eq!(result.format, Format::Text);
    assert_eq!(
        reported_values(text, &result),
        [
            (10, "4012 8888 8888 1881"),
            (10, "4111111111111111"),
            (10, "5555 5555 5555 4444"),
            (10, "2223-0031-2200-3222"),
            (10, "3782 822463 10005"),
            (10, "371449635398431"),
            (10, "6011111111111117"),
            (10, "6011000990139424"),
            (10, "4111 1111 1111 1112"),
            (10, "4111111111111111"),
            (10, "5105105105105100"),
            (10, "4222222222222"),
            (10, "36227206271667"),
            (10, "6200000000000005"),
            (10, "3530111333300000"),
            (10, "6205500000000000004"),
            (10, "4000 0566\n55665556"),
        ]
    );
    let cards = from_rule(&result, 10);
    assert!(cards[0].in_comment);
    assert_eq!(cards[8].checksum_valid, Some(false));
    assert!(
        cards
            .iter()
            .enumerate()
            .all(|(index, card)| index == 8 || card.checksum_valid == Some(true))
    );
}

#[test]
fn no_other_sample_has_password_shaped_findings() {
    let samples = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests");
    let mut scanned = 0;
    for entry in std::fs::read_dir(samples).expect("tests/ should be readable") {
        let path = entry.expect("entry should be readable").path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("made-up-passwords") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("samples are UTF-8");
        let Ok(result) = scan(1, &text, &default_rule_set()) else {
            continue;
        };
        scanned += 1;
        let shaped: Vec<_> = reported_values(&text, &result)
            .into_iter()
            .filter(|&(rule_id, _)| rule_id == 12)
            .collect();
        assert_eq!(shaped, [], "{name}");
    }
    assert!(scanned >= 21, "scanned only {scanned} samples");
}

/// The values one rule reported, by rule name, in text order.
fn values_from<'t>(text: &'t str, result: &ScanResult, rule_name: &str) -> Vec<&'t str> {
    matches(result)
        .into_iter()
        .filter(|details| details.rule_name == rule_name)
        .map(|details| &text[details.location.start_byte..details.location.end_byte])
        .collect()
}

#[test]
fn each_sample_secret_is_found_by_the_rule_for_its_format() {
    let cases: [(&str, &str, &str, &str); 22] = [
        (
            "Dockerfile",
            include_str!("../../tests/Dockerfile"),
            "Slack token",
            "xoxb-174554240827-",
        ),
        (
            "deploy.sh",
            include_str!("../../tests/deploy.sh"),
            "Slack webhook URL",
            "https://hooks.slack.com/services/T7XLZ92GH/",
        ),
        (
            "deploy.sh",
            include_str!("../../tests/deploy.sh"),
            "Bearer token in a header",
            "ghp_kEPW",
        ),
        (
            "payment_client.py",
            include_str!("../../tests/payment_client.py"),
            "Stripe live secret key",
            "sk_live_rAdP",
        ),
        (
            "payment_client.py",
            include_str!("../../tests/payment_client.py"),
            "Stripe live restricted key",
            "rk_live_hd5Q",
        ),
        (
            "app.env",
            include_str!("../../tests/app.env"),
            "SendGrid API key",
            "SG.z3jo",
        ),
        (
            "appsettings.json",
            include_str!("../../tests/appsettings.json"),
            "Google API key",
            "AIzauCro",
        ),
        (
            "appsettings.json",
            include_str!("../../tests/appsettings.json"),
            "OpenAI API key",
            "sk-proj-BPRE",
        ),
        (
            "appsettings.json",
            include_str!("../../tests/appsettings.json"),
            "Password in a connection string",
            "Wint3r!sC0ming2026",
        ),
        (
            "config.toml",
            include_str!("../../tests/config.toml"),
            "Anthropic API key",
            "sk-ant-api03-fnwn",
        ),
        (
            "config.toml",
            include_str!("../../tests/config.toml"),
            "GitHub fine-grained token",
            "github_pat_HPVq",
        ),
        (
            "config.toml",
            include_str!("../../tests/config.toml"),
            "Credentials in a URL",
            "mysql://ingest:hunter2@",
        ),
        (
            "docker-compose.yml",
            include_str!("../../tests/docker-compose.yml"),
            "Credentials in a URL",
            "redis://:9fK2#qLz8mVw!pR4@",
        ),
        (
            "docker-compose.yml",
            include_str!("../../tests/docker-compose.yml"),
            "Sentry DSN",
            "3c9cd0808be816f1cdd9c068ec2121b2",
        ),
        (
            "main.tf",
            include_str!("../../tests/main.tf"),
            "AWS secret access key",
            "WiLKgmKI",
        ),
        (
            "main.tf",
            include_str!("../../tests/main.tf"),
            ".netrc password",
            "ghp_kEPW",
        ),
        (
            "storage.go",
            include_str!("../../tests/storage.go"),
            "AWS secret access key",
            "WiLKgmKI",
        ),
        (
            "access.log",
            include_str!("../../tests/access.log"),
            "Basic auth header",
            "Y2ktYm90",
        ),
        (
            "access.log",
            include_str!("../../tests/access.log"),
            "JSON Web Token",
            "eyJhbGciOiJIUzI1NiIs",
        ),
        (
            "migration.sql",
            include_str!("../../tests/migration.sql"),
            "Password in a SQL statement",
            "R3p0rt1ng-Only!2026",
        ),
        (
            "migration.sql",
            include_str!("../../tests/migration.sql"),
            "Password in a SQL statement",
            "etl_Batch#88",
        ),
        (
            "migration.sql",
            include_str!("../../tests/migration.sql"),
            "Password hash",
            "$argon2id$",
        ),
    ];
    for (sample, text, rule_name, expected) in cases {
        let result = run(text);
        let found = values_from(text, &result, rule_name);
        assert!(
            found.iter().any(|value| value.starts_with(expected)),
            "{sample}: {rule_name} found {found:?}"
        );
    }
}

#[test]
fn documented_placeholders_in_the_new_formats_score_as_examples() {
    let readme = include_str!("../../tests/README-setup.md");
    let result = run(readme);
    let urls: Vec<_> = matches(&result)
        .into_iter()
        .filter(|details| details.rule_name == "Credentials in a URL")
        .collect();
    assert_eq!(urls.len(), 1);
    assert_eq!(urls[0].placeholder_score, Some(95));
    assert_eq!(values_from(readme, &result, "Slack token"), [] as [&str; 0]);

    let migration = include_str!("../../tests/migration.sql");
    let result = run(migration);
    let change_me = matches(&result)
        .into_iter()
        .find(|details| {
            &migration[details.location.start_byte..details.location.end_byte] == "CHANGE_ME"
        })
        .expect("the placeholder password is reported");
    assert_eq!(change_me.placeholder_score, Some(95));
}

#[test]
fn templates_and_prose_are_not_credentials_in_a_known_syntax() {
    for text in [
        "Docs: `PASSWORD '…'` and `IDENTIFIED BY`",
        r#"return fmt.Sprintf("postgres://storage:%s@%s:5432/blobs", password, host)"#,
        "curl -H \"Authorization: Bearer $TOKEN\" https://api.example.com",
        "Server=sql01;Database=x;User Id=u;Pwd={password};",
        r#"{"auth": "anonymous"}"#,
        "Cookie: theme=dark; lang=en-GB",
    ] {
        let result = run(text);
        assert!(
            result.findings.iter().all(|finding| finding.rule_id < 13),
            "{text}: {:?}",
            matches(&result)
        );
    }
}

#[test]
fn the_expected_clean_samples_have_no_findings_from_the_format_rules() {
    for text in [
        include_str!("../../tests/clean-lookalikes.yaml"),
        include_str!("../../tests/password-lookalikes.yaml"),
    ] {
        let result = run(text);
        assert!(result.findings.iter().all(|finding| finding.rule_id < 13));
    }
}

#[test]
fn a_pgp_private_key_block_is_a_private_key_block() {
    let text =
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF0abcd\n-----END PGP PRIVATE KEY BLOCK-----\n";
    let result = run(text);
    assert_eq!(
        values_from(text, &result, "Private key block"),
        [text.trim_end()]
    );
}

#[test]
fn a_jwk_with_a_private_member_is_found_and_a_public_one_is_not() {
    let private = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","d":"jpsQnnGQmL-YBIffH1136cLSf8nM2ObX9fPFXfaQZ5c"}"#;
    let public = r#"{"kty":"RSA","kid":"signing-2026","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4","e":"AQAB"}"#;
    let text = format!("private = {private}\npublic = {public}\n");
    let result = run(&text);
    assert_eq!(
        values_from(&text, &result, "JSON Web Key with private material"),
        [private]
    );
}

#[test]
fn a_putty_key_is_found_through_its_mac_line() {
    let text = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nPrivate-Lines: 1\nAAAAIGZ2c2Rm\nPrivate-MAC: 8a7b6c5d\n";
    let result = run(text);
    assert_eq!(
        values_from(text, &result, "PuTTY private key"),
        [text.trim_end()]
    );
}

#[test]
fn a_base64_key_without_pem_armor_is_found_but_a_pem_body_is_not_reported_twice() {
    // Built from pieces so no key-shaped string sits in the source for secret scanners. Each
    // is a real DER prefix followed by filler, so none of them is a usable key.
    let filler = "Zq7Lm2Xc9Vb4Nn6Tt1Rr8Pp3Kk5Hh0Aa".repeat(4);
    for prefix in [
        ["MIIEowIBAA", "KCAQEA"].concat(),
        ["MIIEvQIBADANBgkqhkiG9w0BAQEF", "AASC"].concat(),
        ["MHcCAQEEI", "Hr"].concat(),
        ["MC4CAQAwBQYDK2VwBCIEI", "Ji"].concat(),
    ] {
        let key = format!("{prefix}{filler}");
        let text = format!("signing_material: \"{key}\"\n");
        let result = run(&text);
        assert_eq!(
            values_from(&text, &result, "Private key without PEM armor"),
            [key.as_str()]
        );
    }

    let pem = include_str!("../../tests/server-key.pem");
    let result = run(pem);
    assert!(values_from(pem, &result, "Private key without PEM armor").is_empty());
}

#[test]
fn a_base64_keystore_is_found() {
    // A PKCS#12 file starts with a version 3 SEQUENCE; a Java keystore with FEEDFEED.
    let filler = "Zq7Lm2Xc9Vb4Nn6Tt1Rr8Pp3Kk5Hh0Aa";
    for prefix in [
        ["MIIJ5wIBAzCC", "CZUG"].concat(),
        ["/u3+7QAAAA", "KZkt"].concat(),
    ] {
        let keystore = format!("{prefix}{filler}");
        let text = format!("keystore: {keystore}\n");
        let result = run(&text);
        assert_eq!(
            values_from(&text, &result, "Keystore file in base64"),
            [keystore.as_str()]
        );
    }
}

#[test]
fn a_kubernetes_secret_with_data_is_found_in_either_field_order() {
    let text = "\
apiVersion: v1
kind: Secret
metadata:
  name: db-creds
data:
  password: UzNjcjN0LVBhNTUh
---
apiVersion: v1
data:
  api-key: c2stbGl2ZS14eXo=
kind: Secret
metadata:
  name: from-kubectl
---
apiVersion: v1
kind: Secret
stringData:
  password: \"{{ .Values.password }}\"
---
apiVersion: v1
kind: ConfigMap
data:
  mode: fast
";
    let result = run(text);
    let secrets = values_from(text, &result, "Kubernetes Secret with inline data");
    assert_eq!(secrets.len(), 2, "{secrets:?}");
    assert!(secrets[0].starts_with("kind: Secret") && secrets[0].ends_with("UzNjcjN0LVBhNTUh"));
    assert!(secrets[1].starts_with("data:") && secrets[1].ends_with("kind: Secret"));
    let scores: Vec<_> = matches(&result)
        .into_iter()
        .filter(|details| details.rule_name == "Kubernetes Secret with inline data")
        .map(|details| details.placeholder_score)
        .collect();
    assert_eq!(scores, [Some(5), Some(5)]);
}

#[test]
fn registry_auth_netrc_cookies_and_presigned_urls_are_found() {
    let signature = "ab12".repeat(16);
    let cases = [
        (
            r#"{"auths":{"ghcr.io":{"auth":"Y2ktYm90OmdocF9rRVBXcGZZ"}}}"#.to_string(),
            "Registry auth (base64 user and password)",
            "Y2ktYm90OmdocF9rRVBXcGZZ",
        ),
        (
            "_auth = dXNlcjpzM2NyM3RQYTU1\n".to_string(),
            "Registry auth (base64 user and password)",
            "dXNlcjpzM2NyM3RQYTU1",
        ),
        (
            "machine api.example.net login ci password Zx9-Kp2_Lm7qWe\n".to_string(),
            ".netrc password",
            "Zx9-Kp2_Lm7qWe",
        ),
        (
            "Cookie: theme=dark; sessionid=Qm9vS2xhc2hBc2Rmc2RmNzg5\n".to_string(),
            "Session cookie",
            "Qm9vS2xhc2hBc2Rmc2RmNzg5",
        ),
        (
            format!(
                "url: https://bucket.s3.amazonaws.com/a.pdf?X-Amz-Expires=60&X-Amz-Signature={signature}\n"
            ),
            "Pre-signed storage URL",
            "https://bucket.s3.amazonaws.com/a.pdf?",
        ),
    ];
    for (text, rule_name, expected) in &cases {
        let result = run(text);
        let found = values_from(text, &result, rule_name);
        assert_eq!(found.len(), 1, "{rule_name}: {found:?}");
        assert!(found[0].starts_with(expected), "{rule_name}: {found:?}");
    }
}
#[cfg(not(feature = "ml"))]
#[test]
fn without_the_ml_feature_a_model_rule_is_a_rule_error() {
    use secrets_scanner_engine::{DetectionType, ModelRef};

    let mut rule_set = default_rule_set();
    rule_set.rules.push(Rule {
        id: 100,
        definition: RuleDefinition {
            name: Some("Model rule".into()),
            detection_type: Some(DetectionType::ModelAssessment),
            model: Some(ModelRef {
                id: None,
                sha256: Some("0".repeat(64)),
            }),
            threshold: Some(50),
            ..RuleDefinition::default()
        },
    });
    let result = scan(1, &format!("key: {AWS_KEY}"), &rule_set).expect("scan should run");
    assert_eq!(matches(&result).len(), 1);
    let error = match &result.findings.last().unwrap().violation {
        Violation::RuleError(error) => error,
        Violation::Match(_) => panic!("expected a rule error last"),
    };
    assert_eq!(
        (error.rule_id, error.field, error.code),
        (100, RuleField::Model, ErrorCode::ModelUnavailable)
    );
    assert_eq!(
        error.message,
        "This engine was built without model support."
    );
}

#[test]
fn a_short_value_with_no_repeated_characters_is_as_confident_as_a_long_random_one() {
    let short = run(&format!("password = {RANDOM_PASSWORD}"));
    let found = matches(&short);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].confidence, 92);
    assert!(
        found[0]
            .why_flagged
            .contains("of a possible 3.6 bits per character")
    );

    let repetitive = run("password = aabbccddeeff1122");
    assert!(matches(&repetitive)[0].confidence < 92);
}

/// A rule set holding only a rule with this type and pattern, so no built-in rule overlaps it.
fn only_rule(detection_type: DetectionType, pattern: &str) -> RuleSet {
    RuleSet {
        rules: vec![Rule {
            id: 500,
            definition: RuleDefinition {
                name: Some("Custom".into()),
                detection_type: Some(detection_type),
                severity: Some(Severity::High),
                pattern: Some(pattern.into()),
                ..RuleDefinition::default()
            },
        }],
    }
}

#[test]
fn the_same_evidence_scores_the_same_whatever_the_rule_type() {
    let text = format!("k = {AWS_KEY}");
    let confidences: Vec<u8> = [
        DetectionType::DirectCredential,
        DetectionType::LikelyCredential,
    ]
    .into_iter()
    .map(|detection_type| {
        let result = scan(
            1,
            &text,
            &only_rule(detection_type, r"\bAKIA[0-9A-Z]{16}\b"),
        )
        .expect("scan should run");
        matches(&result)[0].confidence
    })
    .collect();
    assert_eq!(confidences[0], confidences[1]);
}

#[test]
fn a_logged_secret_name_in_code_or_labelling_a_value_outranks_a_mention_which_outranks_a_message() {
    let confidence = |line: &str| {
        let found = from_rule(&run(line), 5);
        assert_eq!(found.len(), 1, "{line}");
        found[0].confidence
    };
    let in_code = [
        "console.log(\"db password\", dbPassword);",
        "logger.info(f\"api_key={api_key}\")",
        "console.log(`using ${token}`)",
        "println!(\"{}\", token);",
    ]
    .map(confidence);
    let labels = [
        "console.log(\"password:\", pw)",
        "logger.info(\"token=%s\" % t)",
        "print(f\"secret: {s}\")",
        "console.log(\"passwordHash = \" + h)",
    ]
    .map(confidence);
    let beside = confidence("logger.info(\"password reset for\", user)");
    let message = confidence("logger.info(\"token refresh scheduled\")");
    let unlabelled = confidence("console.log(\"password:\")");
    let escaped = confidence(r#"print("say \"token\" twice")"#);
    for strong in in_code.iter().chain(&labels) {
        assert_eq!(*strong, in_code[0]);
    }
    assert!(labels[0] > beside, "{} vs {beside}", labels[0]);
    assert!(beside > message, "{beside} vs {message}");
    assert!(message < 50);
    assert_eq!(unlabelled, message);
    assert_eq!(escaped, message);
    let why = |line: &str| from_rule(&run(line), 5)[0].why_flagged.clone();
    assert!(why("console.log(\"password:\", pw)").contains("labels the value it logs"));
    assert!(
        why("logger.info(\"token refresh scheduled\")").contains("only a word in a quoted message")
    );
}

/// The confidence of the one match a shell echo rule finds in a line.
fn echo_confidence(line: &str) -> u8 {
    let rule_set = only_rule(
        DetectionType::UnsafeHandling,
        r"(?i)\b(?:echo|printf)\b[^\n|>]*\$\{?(?P<key>[A-Za-z_]*(?:token|secret|password|api_key|apikey)[A-Za-z_]*)",
    );
    let result = scan(1, line, &rule_set).expect("scan should run");
    let found = matches(&result);
    assert_eq!(found.len(), 1, "{line}");
    found[0].confidence
}

#[test]
fn a_shell_variable_inside_double_quotes_is_code() {
    let braced = echo_confidence(r#"printf 'db password: %s\n' "${DB_PASSWORD}""#);
    assert_eq!(braced, 82);
    assert_eq!(
        echo_confidence(r#"echo "Deploying with token $NIMBUS_TOKEN""#),
        braced
    );
}

#[test]
fn a_shell_variable_quoted_on_its_own_is_code() {
    assert_eq!(echo_confidence(r#"echo "$NIMBUS_TOKEN" > /tmp/token"#), 82);
}

#[test]
fn a_shell_variable_in_single_quotes_or_escaped_is_only_text() {
    assert_eq!(echo_confidence(r#"echo 'Set $NIMBUS_TOKEN first'"#), 12);
    assert_eq!(echo_confidence(r#"echo "Set \$NIMBUS_TOKEN first""#), 12);
}

#[test]
fn a_plain_secret_word_in_a_message_still_scores_low_beside_shell_variables() {
    let found = from_rule(&run("logger.info(\"token refresh scheduled\")"), 5);
    assert_eq!(found[0].confidence, 12);
    let found = from_rule(&run("logger.info(\"cost $5, token refresh scheduled\")"), 5);
    assert_eq!(found[0].confidence, 12);
}

#[test]
fn a_logging_rule_without_a_key_group_has_no_evidence_either_way() {
    let rule_set = only_rule(
        DetectionType::UnsafeHandling,
        r"(?i)\bconsole\.log\s*\([^)\n]*token",
    );
    let result = scan(1, "console.log(token)", &rule_set).expect("scan should run");
    let found = matches(&result);
    assert_eq!(found[0].confidence, 50);
    assert!(
        found[0]
            .why_flagged
            .contains("nothing else about this match")
    );
}
