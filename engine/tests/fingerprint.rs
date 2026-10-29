use secrets_scanner_engine::{
    FindingKind, FingerprintKey, Rule, RuleDefinition, RuleSet, ScanOptions, ScanResult,
    default_rule_set, scan, scan_with_options,
};
use sha2::{Digest, Sha256};

const AWS_KEY: &str = "AKIAZ7Q3LMN4XWY2PRT6";
const OTHER_AWS_KEY: &str = "AKIAZ7Q3LMN4XWY2PRT7";

fn key(byte: u8) -> FingerprintKey {
    FingerprintKey::new([byte; 32])
}

fn run(text: &str, key: &FingerprintKey) -> ScanResult {
    let options = ScanOptions {
        fingerprint_key: Some(key),
        ..ScanOptions::default()
    };
    scan_with_options(1, text, &default_rule_set(), options).expect("scan should run")
}

/// The fingerprints of every match, in text order.
fn fingerprints(result: &ScanResult) -> Vec<String> {
    result
        .findings
        .iter()
        .filter(|finding| finding.kind == FindingKind::Match)
        .map(|finding| {
            finding
                .fingerprint
                .clone()
                .expect("a match scanned with a key has a fingerprint")
        })
        .collect()
}

#[test]
fn a_fingerprint_is_hmac_sha256() {
    // RFC 4231 test case 1. HMAC pads a short key with zeros, so twenty 0x0b bytes followed by
    // twelve zero bytes is the same key.
    let mut bytes = [0; 32];
    bytes[..20].fill(0x0b);
    assert_eq!(
        FingerprintKey::new(bytes).fingerprint(b"Hi There"),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

#[test]
fn the_same_value_has_the_same_fingerprint_wherever_it_is() {
    let key = key(7);
    let first = run(&format!("aws = {AWS_KEY}\n"), &key);
    let later = run(&format!("# moved\n\n  other_key: {AWS_KEY}\n"), &key);
    assert_eq!(fingerprints(&first).len(), 1);
    assert_eq!(fingerprints(&first), fingerprints(&later));
}

#[test]
fn a_changed_value_has_a_different_fingerprint() {
    let key = key(7);
    let first = run(&format!("aws = {AWS_KEY}\n"), &key);
    let changed = run(&format!("aws = {OTHER_AWS_KEY}\n"), &key);
    assert_ne!(fingerprints(&first), fingerprints(&changed));
}

#[test]
fn another_key_gives_another_fingerprint() {
    let text = format!("aws = {AWS_KEY}\n");
    assert_ne!(
        fingerprints(&run(&text, &key(7))),
        fingerprints(&run(&text, &key(8)))
    );
}

#[test]
fn a_fingerprint_is_not_a_plain_hash_and_never_holds_the_value() {
    let result = run(&format!("aws = {AWS_KEY}\n"), &key(7));
    let fingerprint = &fingerprints(&result)[0];
    let plain: String = Sha256::digest(AWS_KEY.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_ne!(fingerprint, &plain);
    assert_eq!(fingerprint.len(), 64);
    assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));

    let serialized = serde_json::to_string(&result.findings).expect("findings serialize");
    assert!(!serialized.contains(AWS_KEY));
    assert!(serialized.contains(fingerprint.as_str()));
}

#[test]
fn without_a_key_or_for_a_rule_error_there_is_no_fingerprint() {
    let result = scan(1, &format!("aws = {AWS_KEY}\n"), &default_rule_set()).expect("scan runs");
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.fingerprint.is_none())
    );
    let serialized = serde_json::to_string(&result.findings).expect("findings serialize");
    assert!(!serialized.contains("fingerprint"));

    let broken = RuleSet {
        rules: vec![Rule {
            id: 1,
            definition: RuleDefinition {
                name: Some("Broken".to_string()),
                pattern: Some("AKIA(".to_string()),
                ..default_rule_set().rules[0].definition.clone()
            },
        }],
    };
    let options = ScanOptions {
        fingerprint_key: Some(&key(7)),
        ..ScanOptions::default()
    };
    let result = scan_with_options(1, AWS_KEY, &broken, options).expect("scan runs");
    assert_eq!(result.findings[0].kind, FindingKind::RuleError);
    assert_eq!(result.findings[0].fingerprint, None);
}
