use secrets_scanner_engine::{
    DetectionType, ErrorCode, Rule, RuleDefinition, RuleField, Severity, WarningCode, check_rule,
    check_rule_set, default_rules,
};

fn rule(id: i64, definition: RuleDefinition) -> Rule {
    Rule { id, definition }
}

fn valid(pattern: &str) -> RuleDefinition {
    RuleDefinition {
        name: Some("Test rule".into()),
        detection_type: Some(DetectionType::DirectCredential),
        severity: Some(Severity::High),
        pattern: Some(pattern.into()),
        ..RuleDefinition::default()
    }
}

#[test]
fn the_built_in_rules_are_valid_and_raise_no_warnings() {
    let rules: Vec<Rule> = default_rules()
        .into_iter()
        .enumerate()
        .map(|(index, definition)| rule(index as i64 + 1, definition))
        .collect();
    let check = check_rule_set(&rules);
    assert_eq!(check.errors, []);
    assert_eq!(check.warnings, []);
}

#[test]
fn an_empty_draft_reports_each_missing_required_field() {
    let check = check_rule(&rule(1, RuleDefinition::default()));
    let missing: Vec<(RuleField, ErrorCode)> = check
        .errors
        .iter()
        .map(|error| (error.field, error.code))
        .collect();
    assert_eq!(
        missing,
        [
            (RuleField::Name, ErrorCode::Required),
            (RuleField::DetectionType, ErrorCode::Required),
            (RuleField::Severity, ErrorCode::Required),
            (RuleField::Pattern, ErrorCode::Required),
        ]
    );
}

#[test]
fn an_invalid_pattern_points_at_the_bad_spot() {
    let check = check_rule(&rule(7, valid("ab(c")));
    let [error] = check.errors.as_slice() else {
        panic!("expected one error, got {:?}", check.errors);
    };
    assert_eq!(error.rule_id, 7);
    assert_eq!(error.field, RuleField::Pattern);
    assert_eq!(error.code, ErrorCode::InvalidRegex);
    let (start, end) = error.span.expect("a syntax error should carry a span");
    assert!(start <= 2 && 2 < end.max(start + 1), "span {start}..{end}");
}

#[test]
fn a_pattern_too_large_to_compile_is_rejected() {
    let check = check_rule(&rule(1, valid(r"(?:\w{100}){100}")));
    assert_eq!(check.errors.len(), 1);
    assert_eq!(check.errors[0].code, ErrorCode::TooLarge);
}

#[test]
fn entropy_outside_zero_to_eight_is_out_of_range() {
    let check = check_rule(&rule(
        1,
        RuleDefinition {
            min_entropy: Some(9.0),
            ..valid("x")
        },
    ));
    assert_eq!(check.errors.len(), 1);
    assert_eq!(
        (check.errors[0].field, check.errors[0].code),
        (RuleField::MinEntropy, ErrorCode::OutOfRange)
    );
}

#[test]
fn a_pattern_that_can_match_nothing_is_a_warning_not_an_error() {
    let check = check_rule(&rule(1, valid("a*")));
    assert!(check.is_valid());
    assert_eq!(check.warnings.len(), 1);
    assert_eq!(check.warnings[0].code, WarningCode::MatchesEmpty);
}

#[test]
fn repeated_names_in_a_set_flag_the_later_rule_ignoring_case() {
    let rules = [
        rule(1, valid("a")),
        rule(
            2,
            RuleDefinition {
                name: Some("  test RULE ".into()),
                ..valid("b")
            },
        ),
    ];
    let check = check_rule_set(&rules);
    assert_eq!(check.errors.len(), 1);
    assert_eq!(check.errors[0].rule_id, 2);
    assert_eq!(check.errors[0].code, ErrorCode::DuplicateName);
}

#[test]
fn a_definition_reads_from_the_forms_camel_case_json() {
    let definition: RuleDefinition = serde_json::from_str(
        r#"{"name": "Slack token", "enabled": false, "detectionType": "direct_credential",
            "severity": "medium", "pattern": "xoxb-[0-9a-z-]+", "keyNames": ["slack"],
            "minEntropy": 2.5}"#,
    )
    .expect("definition should parse");
    assert!(!definition.is_enabled());
    assert_eq!(definition.severity, Some(Severity::Medium));
    assert_eq!(definition.key_names, ["slack"]);
    assert_eq!(definition.min_entropy, Some(2.5));
    assert!(check_rule(&rule(1, definition)).is_valid());
}
