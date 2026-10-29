use secrets_scanner_engine::{
    CaseKind, CheckDigitChecksum, CheckRule, Checksum, ChecksumEncoding, Crc32Checksum,
    DetectionType, Expectation, FindingKind, HashChecksum, HashFunction, Marvin32Checksum,
    MatchDetails, Rule, RuleDefinition, RuleSet, Severity, TestSuite, Violation, default_rule_set,
    generate_test_data, pattern_matches_value, scan,
};

fn rule(id: i64, name: &str, pattern: &str) -> Rule {
    Rule {
        id,
        definition: RuleDefinition {
            name: Some(name.into()),
            detection_type: Some(DetectionType::DirectCredential),
            severity: Some(Severity::High),
            pattern: Some(pattern.into()),
            ..RuleDefinition::default()
        },
    }
}

fn placeholders(id: i64) -> Rule {
    Rule {
        id,
        definition: RuleDefinition {
            name: Some("Placeholders".into()),
            detection_type: Some(DetectionType::PlaceholderVsReal),
            pattern: Some("(?i)example|xxxx|test".into()),
            ..RuleDefinition::default()
        },
    }
}

/// A case's label and the matches that overlap it, by rule id.
type Scanned = (Expectation, CaseKind, Option<i64>, Vec<(i64, MatchDetails)>);

/// Each case with the matches that overlap it, from scanning every document with `rule_set`.
fn scanned(suite: &TestSuite, rule_set: &RuleSet) -> Vec<Scanned> {
    let mut cases = Vec::new();
    for document in &suite.documents {
        let result = scan(1, &document.text, rule_set).expect("a generated document scans");
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.kind == FindingKind::Match),
            "{} had rule errors",
            document.name
        );
        for case in &document.cases {
            let overlapping = result
                .findings
                .iter()
                .filter_map(|finding| match &finding.violation {
                    Violation::Match(details)
                        if details.location.start_byte < case.end
                            && case.start < details.location.end_byte =>
                    {
                        Some((finding.rule_id, details.clone()))
                    }
                    _ => None,
                })
                .collect();
            cases.push((case.expect, case.kind, case.rule_id, overlapping));
        }
    }
    cases
}

#[test]
fn the_same_rule_set_and_seed_always_give_the_same_data() {
    let rule_set = default_rule_set();
    assert_eq!(
        generate_test_data(&rule_set, None, 7),
        generate_test_data(&rule_set, None, 7)
    );
    assert_ne!(
        generate_test_data(&rule_set, None, 7).documents,
        generate_test_data(&rule_set, None, 8).documents
    );
}

#[test]
fn each_rule_s_data_depends_only_on_the_seed_and_that_rule() {
    let rule_set = default_rule_set();
    let alone = generate_test_data(&rule_set, Some(&[1]), 3);
    let all = generate_test_data(&rule_set, None, 3);
    let positive = |suite: &TestSuite| {
        suite
            .documents
            .iter()
            .find_map(|document| {
                document
                    .cases
                    .iter()
                    .find(|case| case.id == "r1-positive")
                    .map(|case| document.text[case.start..case.end].to_string())
            })
            .expect("rule 1 has a positive")
    };
    assert_eq!(positive(&alone), positive(&all));
    assert!(
        alone
            .documents
            .iter()
            .flat_map(|document| &document.cases)
            .all(|case| case.rule_id.is_none_or(|id| id == 1))
    );
}

#[test]
fn every_built_in_rule_finds_its_positives_and_leaves_its_lookalikes_alone() {
    let rule_set = default_rule_set();
    let suite = generate_test_data(&rule_set, None, 1);
    let cases = scanned(&suite, &rule_set);
    let positives = cases
        .iter()
        .filter(|(_, kind, _, _)| *kind == CaseKind::Positive)
        .count();
    // Every built-in rule that creates findings from a pattern gets one.
    assert_eq!(positives, 39, "{:#?}", suite.skipped);
    for (expect, kind, rule_id, found) in &cases {
        let by_rule: Vec<&MatchDetails> = found
            .iter()
            .filter(|(id, _)| Some(*id) == *rule_id)
            .map(|(_, details)| details)
            .collect();
        match kind {
            CaseKind::Positive | CaseKind::Assignment => {
                assert_eq!(*expect, Expectation::Secret);
                assert!(!by_rule.is_empty(), "rule {rule_id:?} missed its {kind:?}");
                assert!(
                    by_rule
                        .iter()
                        .all(|details| details.checksum_valid != Some(false))
                );
            }
            CaseKind::BrokenChecksum => {
                assert_eq!(*expect, Expectation::Example);
                assert!(
                    by_rule
                        .iter()
                        .all(|details| details.checksum_valid == Some(false)
                            && details.placeholder_score >= Some(70)),
                    "rule {rule_id:?}"
                );
            }
            CaseKind::Placeholder => {
                assert!(
                    by_rule
                        .iter()
                        .any(|details| details.placeholder_score == Some(95)),
                    "rule {rule_id:?}"
                );
            }
            CaseKind::WrongPrefix
            | CaseKind::OneShort
            | CaseKind::LowEntropy
            | CaseKind::NeutralKey => {
                assert!(by_rule.is_empty(), "rule {rule_id:?} found its {kind:?}");
            }
            CaseKind::Lookalike => assert_eq!(*rule_id, None),
        }
    }
}

#[test]
fn generated_values_pass_each_kind_of_checksum_and_broken_copies_fail_it() {
    let crc32 = |encoding, prefix_length, length| {
        Checksum::Crc32(Crc32Checksum {
            encoding,
            prefix_length,
            length,
        })
    };
    let checksums = [
        (
            rule(1, "Base62 token", r"\bacme_[A-Za-z0-9]{30}\b"),
            crc32(ChecksumEncoding::Base62, 5, 6),
        ),
        (
            rule(2, "Base36 token", r"\bzed-[a-z0-9]{24}\b"),
            crc32(ChecksumEncoding::Base36, 0, 7),
        ),
        (
            rule(3, "Hex token", r"\bhx_[0-9a-f]{40}\b"),
            crc32(ChecksumEncoding::Hex, 3, 8),
        ),
        (rule(4, "Card", r"\b4\d{15}\b"), Checksum::Luhn),
        (
            rule(5, "WIF", r"\b5[1-9A-HJ-NP-Za-km-z]{50}\b"),
            Checksum::Base58check,
        ),
        (
            rule(
                6,
                "age key",
                r"\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b",
            ),
            Checksum::Bech32,
        ),
        (
            rule(
                7,
                "Taproot",
                r"\bbc1p[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}\b",
            ),
            Checksum::Bech32m,
        ),
        (
            rule(8, "Seed phrase", r"\b(?:[a-z]{3,8} ){11}[a-z]{3,8}\b"),
            Checksum::Bip39,
        ),
        (
            rule(10, "Azure key", r"\b[A-Za-z0-9]{43}="),
            Checksum::Marvin32(Marvin32Checksum::AZURE_STORAGE),
        ),
        (rule(11, "Aadhaar", r"\b\d{12}\b"), Checksum::Verhoeff),
        (rule(12, "ISBN", r"\b\d{9}[\dX]\b"), Checksum::Mod11),
        (
            rule(13, "IBAN", r"\bGB\d{2}[A-Z]{4}\d{14}\b"),
            Checksum::Mod97,
        ),
        (
            rule(14, "In-house check digit", r"\bacc_\d{12}\b"),
            Checksum::CheckDigit(CheckDigitChecksum {
                alphabet: "0123456789".into(),
                weights: vec![3, 1],
                modulus: 97,
                check: CheckRule::Complement,
                prefix_length: 4,
                length: 2,
            }),
        ),
        (
            rule(15, "In-house hash", r"\bhh_[A-Za-z0-9]{30}\b"),
            Checksum::Hash(HashChecksum {
                hash: HashFunction::Sha1,
                bytes: 4,
                encoding: ChecksumEncoding::Base62,
                prefix_length: 3,
                length: 6,
            }),
        ),
    ];
    let mut rules: Vec<Rule> = checksums
        .iter()
        .map(|(rule, checksum)| {
            let mut rule = rule.clone();
            rule.definition.checksum = Some(checksum.clone());
            rule
        })
        .collect();
    rules.push(placeholders(9));
    let rule_set = RuleSet { rules };
    let suite = generate_test_data(&rule_set, None, 11);
    for document in &suite.documents {
        for case in &document.cases {
            let Some((_, checksum)) = checksums
                .iter()
                .find(|(rule, _)| Some(rule.id) == case.rule_id)
            else {
                continue;
            };
            let value = &document.text[case.start..case.end];
            match case.kind {
                CaseKind::Positive | CaseKind::Placeholder => {
                    assert!(checksum.is_valid(value), "{}", case.id)
                }
                CaseKind::BrokenChecksum => assert!(!checksum.is_valid(value), "{}", case.id),
                _ => {}
            }
        }
    }
    for (rule, _) in &checksums {
        let id = rule.id;
        for kind in ["positive", "broken-checksum"] {
            let case_id = format!("r{id}-{kind}");
            assert!(
                suite
                    .documents
                    .iter()
                    .flat_map(|document| &document.cases)
                    .any(|case| case.id == case_id),
                "no {case_id}: {:#?}",
                suite.skipped
            );
        }
    }
}

#[test]
fn a_rule_with_key_names_gets_assignments_in_each_format_and_a_neutral_name() {
    let mut assignment = rule(
        1,
        "Token in a query",
        r"[?&](?P<key>[a-z_]*token)=(?P<value>[A-Za-z0-9]{16,})",
    );
    assignment.definition.detection_type = Some(DetectionType::LikelyCredential);
    assignment.definition.key_names = vec!["token".into()];
    let suite = generate_test_data(
        &RuleSet {
            rules: vec![assignment],
        },
        None,
        5,
    );
    let names: Vec<&str> = suite
        .documents
        .iter()
        .map(|document| document.name.as_str())
        .collect();
    for name in ["assignments.env", "assignments.yaml", "assignments.json"] {
        assert!(names.contains(&name), "{names:?}");
    }
    let json = suite
        .documents
        .iter()
        .find(|document| document.name == "assignments.json")
        .unwrap();
    serde_json::from_str::<serde_json::Value>(&json.text).expect("the JSON document parses");
    assert!(
        json.cases
            .iter()
            .any(|case| case.kind == CaseKind::NeutralKey && case.expect == Expectation::NotSecret)
    );
}

#[test]
fn a_pattern_that_does_not_require_its_prefix_is_reported_as_skipped() {
    let mut loose = rule(1, "Loose", r"[a-z]{3}_[A-Za-z0-9]{20}");
    loose.definition.prefix = Some("abc_".into());
    let suite = generate_test_data(&RuleSet { rules: vec![loose] }, None, 1);
    let skipped = suite
        .skipped
        .iter()
        .find(|skipped| skipped.kind == CaseKind::WrongPrefix)
        .expect("the wrong-prefix case is skipped");
    assert!(
        skipped.reason.contains("doesn't require the prefix"),
        "{}",
        skipped.reason
    );
}

#[test]
fn disabled_placeholder_and_model_rules_get_no_cases_and_say_why() {
    let mut disabled = rule(1, "Off", r"\bAKIA[0-9A-Z]{16}\b");
    disabled.definition.enabled = Some(false);
    let model = Rule {
        id: 2,
        definition: RuleDefinition {
            name: Some("Detector".into()),
            detection_type: Some(DetectionType::ModelDetection),
            severity: Some(Severity::High),
            model: Some(secrets_scanner_engine::ModelRef {
                id: Some("detector".into()),
                sha256: Some("a".repeat(64)),
            }),
            threshold: Some(50),
            ..RuleDefinition::default()
        },
    };
    let suite = generate_test_data(
        &RuleSet {
            rules: vec![disabled, model, placeholders(3)],
        },
        None,
        1,
    );
    let reasons: Vec<(i64, &str)> = suite
        .skipped
        .iter()
        .map(|skipped| (skipped.rule_id, skipped.reason.as_str()))
        .collect();
    assert!(
        reasons
            .iter()
            .any(|(id, reason)| *id == 1 && reason.contains("disabled"))
    );
    assert!(
        reasons
            .iter()
            .any(|(id, reason)| *id == 2 && reason.contains("Model rules"))
    );
    assert!(
        reasons
            .iter()
            .any(|(id, reason)| *id == 3 && reason.contains("Placeholder rules"))
    );
    // Only the lookalikes file, which is for no rule.
    assert_eq!(suite.documents.len(), 1);
    assert!(
        suite.documents[0]
            .cases
            .iter()
            .all(|case| case.rule_id.is_none())
    );
}

#[test]
fn a_value_found_only_as_a_parsed_pair_is_not_a_pattern_match() {
    let mut query = rule(
        1,
        "Token in a query",
        r"[?&](?P<key>token)=(?P<value>[A-Za-z0-9]{16,})",
    );
    query.definition.detection_type = Some(DetectionType::LikelyCredential);
    query.definition.key_names = vec!["token".into()];
    let text = "API_TOKEN=Zq7Lm2Xc9Vb4Nn6Tt1Rr\nURL=https://x.test/?token=Pp3Kk5Hh0Zq7Lm2X\n";
    let result = scan(
        1,
        text,
        &RuleSet {
            rules: vec![query.clone()],
        },
    )
    .unwrap();
    let spans: Vec<(usize, usize)> = result
        .findings
        .iter()
        .filter_map(|finding| match &finding.violation {
            Violation::Match(details) => {
                Some((details.location.start_byte, details.location.end_byte))
            }
            Violation::RuleError(_) => None,
        })
        .collect();
    assert_eq!(spans.len(), 2);
    assert!(!pattern_matches_value(&query, text, spans[0].0, spans[0].1));
    assert!(pattern_matches_value(&query, text, spans[1].0, spans[1].1));
}
