use secrets_scanner_engine::{
    DetectionType, ErrorCode, ModelRef, Rule, RuleDefinition, RuleField, RuleSet, Severity,
    ValueClassifierSetting, WarningCode, check_rule, check_rule_set, default_rule_set,
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
    assert_eq!(ids, (1..=40).collect::<Vec<i64>>());
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
            "minEntropy": 2.5,
            "checksum": {"algorithm": "crc32", "encoding": "hex", "prefixLength": 5, "length": 8}}"#,
    )
    .expect("definition should parse");
    assert!(!definition.is_enabled());
    assert_eq!(definition.severity, Some(Severity::Medium));
    assert_eq!(definition.key_names, ["slack"]);
    assert_eq!(definition.min_entropy, Some(2.5));
    assert!(check_rule(&rule(1, definition)).is_valid());
}

#[test]
fn an_unknown_checksum_is_rejected_by_the_contract() {
    for checksum in [
        r#""github_crc32""#,
        r#"{"algorithm": "md5", "encoding": "hex", "prefixLength": 0, "length": 8}"#,
        r#"{"algorithm": "crc32", "encoding": "base64", "prefixLength": 0, "length": 8}"#,
        r#"{"encoding": "hex", "prefixLength": 0, "length": 8}"#,
        r#"{"algorithm": "crc32", "encoding": "hex", "length": 8}"#,
        r#"{"algorithm": "crc32", "encoding": "hex", "prefixLength": 0, "length": 8, "x": 1}"#,
    ] {
        let json =
            format!(r#"{{"rules": [{{"id": 1, "definition": {{"checksum": {checksum}}}}}]}}"#);
        assert!(
            serde_json::from_str::<RuleSet>(&json).is_err(),
            "{checksum}"
        );
    }
}

#[test]
fn in_house_checksum_settings_that_cant_run_are_errors_on_the_checksum_field() {
    for (checksum, code) in [
        (
            r#"{"algorithm": "check_digit", "alphabet": "0012", "weights": [1], "modulus": 3, "prefixLength": 0, "length": 1}"#,
            ErrorCode::InvalidFormat,
        ),
        (
            r#"{"algorithm": "check_digit", "alphabet": "0123456789", "weights": [1], "modulus": 97, "prefixLength": 0, "length": 1}"#,
            ErrorCode::OutOfRange,
        ),
        (
            r#"{"algorithm": "hash", "hash": "md5", "bytes": 8, "encoding": "hex", "prefixLength": 0, "length": 8}"#,
            ErrorCode::OutOfRange,
        ),
    ] {
        let definition: RuleDefinition = serde_json::from_str(&format!(
            r#"{{"name": "x", "detectionType": "direct_credential", "severity": "high",
                "pattern": "x", "checksum": {checksum}}}"#
        ))
        .expect("definition should parse");
        let check = check_rule(&rule(1, definition));
        assert_eq!(
            check
                .errors
                .iter()
                .map(|error| (error.field, error.code))
                .collect::<Vec<_>>(),
            [(RuleField::Checksum, code)],
            "{checksum}"
        );
    }
}

#[test]
fn a_checksum_too_short_or_too_long_for_its_value_is_out_of_range() {
    for length in [5, 17] {
        let definition: RuleDefinition = serde_json::from_str(&format!(
            r#"{{"name": "x", "detectionType": "direct_credential", "severity": "high",
                "pattern": "x", "checksum": {{"algorithm": "crc32", "encoding": "base62",
                "prefixLength": 4, "length": {length}}}}}"#
        ))
        .expect("definition should parse");
        let check = check_rule(&rule(1, definition));
        assert_eq!(check.errors.len(), 1, "length {length}");
        assert_eq!(
            (check.errors[0].field, check.errors[0].code),
            (RuleField::Checksum, ErrorCode::OutOfRange)
        );
    }
}

#[test]
fn setups_without_options_need_no_other_fields() {
    for checksum in [
        r#"{"algorithm": "luhn"}"#,
        r#"{"algorithm": "base58check"}"#,
        r#"{"algorithm": "bech32"}"#,
        r#"{"algorithm": "bech32m"}"#,
        r#"{"algorithm": "bip39"}"#,
        r#"{"algorithm": "verhoeff"}"#,
        r#"{"algorithm": "mod11"}"#,
        r#"{"algorithm": "mod97"}"#,
        r#"{"algorithm": "marvin32", "seed": "Default0"}"#,
        r#"{"algorithm": "check_digit", "alphabet": "0123456789X", "weights": [2, 3], "modulus": 11, "prefixLength": 0, "length": 1}"#,
        r#"{"algorithm": "hash", "hash": "sha256", "bytes": 4, "encoding": "digits", "prefixLength": 5, "length": 10}"#,
    ] {
        let json =
            format!(r#"{{"rules": [{{"id": 1, "definition": {{"checksum": {checksum}}}}}]}}"#);
        assert!(serde_json::from_str::<RuleSet>(&json).is_ok(), "{checksum}");
    }
}

fn model_rule(detection_type: DetectionType) -> RuleDefinition {
    RuleDefinition {
        name: Some("Model rule".into()),
        detection_type: Some(detection_type),
        model: Some(ModelRef {
            id: Some("triage-small".into()),
            sha256: Some("AB".repeat(32)),
        }),
        threshold: Some(80),
        ..RuleDefinition::default()
    }
}

fn errors(definition: RuleDefinition) -> Vec<(RuleField, ErrorCode)> {
    check_rule(&rule(1, definition))
        .errors
        .iter()
        .map(|error| (error.field, error.code))
        .collect()
}

#[test]
fn a_model_rule_needs_a_model_and_threshold_but_no_pattern() {
    assert_eq!(errors(model_rule(DetectionType::ModelAssessment)), []);
    assert_eq!(
        errors(RuleDefinition {
            model: None,
            threshold: None,
            ..model_rule(DetectionType::ModelAssessment)
        }),
        [
            (RuleField::Model, ErrorCode::Required),
            (RuleField::Threshold, ErrorCode::Required),
        ]
    );
}

#[test]
fn a_model_hash_must_be_64_hex_characters_and_the_threshold_0_to_100() {
    for (sha256, threshold) in [("abc", 80), (&*"g".repeat(64), 80)] {
        assert_eq!(
            errors(RuleDefinition {
                model: Some(ModelRef {
                    id: None,
                    sha256: Some(sha256.into()),
                }),
                threshold: Some(threshold),
                ..model_rule(DetectionType::ModelAssessment)
            }),
            [(RuleField::Model, ErrorCode::InvalidFormat)]
        );
    }
    for threshold in [-1, 101] {
        assert_eq!(
            errors(RuleDefinition {
                threshold: Some(threshold),
                ..model_rule(DetectionType::ModelAssessment)
            }),
            [(RuleField::Threshold, ErrorCode::OutOfRange)]
        );
    }
}

#[test]
fn a_model_detection_rule_needs_a_severity_and_an_assessment_rule_does_not() {
    assert_eq!(
        errors(model_rule(DetectionType::ModelDetection)),
        [(RuleField::Severity, ErrorCode::Required)]
    );
    assert_eq!(
        errors(RuleDefinition {
            severity: Some(Severity::High),
            ..model_rule(DetectionType::ModelDetection)
        }),
        []
    );
}

#[test]
fn a_model_rule_reads_from_the_forms_camel_case_json() {
    let definition: RuleDefinition = serde_json::from_str(&format!(
        r#"{{"name": "ML: real vs example", "detectionType": "model_assessment",
            "model": {{"id": "triage-small", "sha256": "{}"}}, "threshold": 80}}"#,
        "0f".repeat(32)
    ))
    .expect("definition should parse");
    assert_eq!(definition.threshold, Some(80));
    assert!(check_rule(&rule(1, definition)).is_valid());
    assert!(
        serde_json::from_str::<RuleDefinition>(r#"{"model": {"sha": "x"}}"#).is_err(),
        "a misspelled model field should be rejected"
    );
}

#[test]
fn a_value_classifier_setting_needs_a_valid_model_and_a_minimum_score() {
    let with_setting = |setting| RuleDefinition {
        value_classifier: Some(setting),
        ..valid("x")
    };
    assert_eq!(
        errors(with_setting(ValueClassifierSetting::default())),
        [
            (RuleField::ValueClassifier, ErrorCode::Required),
            (RuleField::ValueClassifier, ErrorCode::Required),
        ]
    );
    assert_eq!(
        errors(with_setting(ValueClassifierSetting {
            model: Some(ModelRef {
                id: None,
                sha256: Some("abc".into()),
            }),
            min_score: Some(101),
        })),
        [
            (RuleField::ValueClassifier, ErrorCode::InvalidFormat),
            (RuleField::ValueClassifier, ErrorCode::OutOfRange),
        ]
    );
    assert_eq!(
        errors(with_setting(ValueClassifierSetting {
            model: Some(ModelRef {
                id: Some("value-classifier".into()),
                sha256: Some("0f".repeat(32)),
            }),
            min_score: Some(50),
        })),
        []
    );
}
