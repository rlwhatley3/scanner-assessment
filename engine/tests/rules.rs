use secrets_scanner_engine::{
    DetectionType, ErrorCode, Rule, RuleDefinition, RuleField, RuleSet, Severity, WarningCode,
    check_rule, check_rule_set, default_rule_set,
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
    let check = check_rule_set(&default_rule_set().rules);
    assert_eq!(check.errors, []);
    assert_eq!(check.warnings, []);
}

#[test]
fn the_built_in_rule_set_file_is_in_the_scan_contract_shape() {
    let rule_set = default_rule_set();
    let ids: Vec<i64> = rule_set.rules.iter().map(|rule| rule.id).collect();
    assert_eq!(ids, [1, 2, 3, 4, 5, 6]);
    let types: Vec<DetectionType> = rule_set
        .rules
        .iter()
        .filter_map(|rule| rule.definition.detection_type)
        .collect();
    for detection_type in [
        DetectionType::DirectCredential,
        DetectionType::LikelyCredential,
        DetectionType::UnsafeHandling,
        DetectionType::PlaceholderVsReal,
    ] {
        assert!(
            types.contains(&detection_type),
            "no {detection_type:?} rule"
        );
    }

    let json = serde_json::to_string(&rule_set).expect("rule set should serialize");
    let reparsed: RuleSet = serde_json::from_str(&json).expect("rule set should parse back");
    assert_eq!(reparsed, rule_set);
}

#[test]
fn the_contract_rejects_unknown_or_misspelled_fields_at_every_level() {
    let rule_set = r#"{"rules": [], "placeholders": []}"#;
    let rule = r#"{"rules": [{"id": 1, "definition": {}, "draft": true}]}"#;
    let definition = r#"{"rules": [{"id": 1, "definition": {"detectiontype": "x"}}]}"#;
    for json in [rule_set, rule, definition] {
        assert!(
            serde_json::from_str::<RuleSet>(json).is_err(),
            "should be rejected: {json}"
        );
    }
}

#[test]
fn the_contract_requires_a_rule_id_and_definition() {
    for json in [
        r#"{"rules": [{"definition": {}}]}"#,
        r#"{"rules": [{"id": 1}]}"#,
    ] {
        assert!(serde_json::from_str::<RuleSet>(json).is_err(), "{json}");
    }
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
fn a_placeholder_rule_needs_no_severity_but_other_types_do() {
    let placeholder = RuleDefinition {
        detection_type: Some(DetectionType::PlaceholderVsReal),
        severity: None,
        ..valid("changeme")
    };
    assert!(check_rule(&rule(1, placeholder)).is_valid());

    let credential = RuleDefinition {
        severity: None,
        ..valid("x")
    };
    let check = check_rule(&rule(2, credential));
    assert_eq!(check.errors.len(), 1);
    assert_eq!(check.errors[0].field, RuleField::Severity);
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
