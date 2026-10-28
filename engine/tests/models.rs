//! Model rules, run against tiny ONNX models built here so the tests need no model files.
#![cfg(feature = "ml")]

use prost::Message;
use secrets_scanner_engine::{
    DetectionType, ErrorCode, MIN_DETECTION_BYTES, MatchDetails, ModelAssessment, ModelInfo,
    ModelLoadError, ModelRef, ModelVerdict, Models, Rule, RuleDefinition, RuleField, RuleSet,
    ScanError, ScanResult, Severity, Violation, default_rule_set, scan, scan_with_models,
};
use tract_onnx::pb;

const AWS_KEY: &str = "AKIAZ7Q3LMN4XWY2PRT6";
/// The byte the test models react to.
const TRIGGER: u8 = b'~';

const FLOAT: i32 = 1;
const INT64: i32 = 7;

fn tensor_type(elem_type: i32, dims: &[i64]) -> pb::TypeProto {
    let dim = dims
        .iter()
        .map(|&size| pb::tensor_shape_proto::Dimension {
            value: Some(pb::tensor_shape_proto::dimension::Value::DimValue(size)),
            ..Default::default()
        })
        .collect();
    pb::TypeProto {
        value: Some(pb::type_proto::Value::TensorType(pb::type_proto::Tensor {
            elem_type,
            shape: Some(pb::TensorShapeProto { dim }),
        })),
        ..Default::default()
    }
}

fn value_info(name: &str, elem_type: i32, dims: &[i64]) -> pb::ValueInfoProto {
    pb::ValueInfoProto {
        name: name.into(),
        r#type: Some(tensor_type(elem_type, dims)),
        ..Default::default()
    }
}

fn node(
    op: &str,
    inputs: &[&str],
    output: &str,
    attribute: Vec<pb::AttributeProto>,
) -> pb::NodeProto {
    pb::NodeProto {
        op_type: op.into(),
        name: output.into(),
        input: inputs.iter().map(|&input| input.into()).collect(),
        output: vec![output.into()],
        attribute,
        ..Default::default()
    }
}

fn cast_to_float() -> Vec<pb::AttributeProto> {
    vec![pb::AttributeProto {
        name: "to".into(),
        r#type: 2,
        i: FLOAT.into(),
        ..Default::default()
    }]
}

fn reduce_over_row() -> Vec<pb::AttributeProto> {
    vec![
        pb::AttributeProto {
            name: "axes".into(),
            r#type: 7,
            ints: vec![1],
            ..Default::default()
        },
        pb::AttributeProto {
            name: "keepdims".into(),
            r#type: 2,
            i: 1,
            ..Default::default()
        },
    ]
}

fn float_scalar(name: &str, value: f32) -> pb::TensorProto {
    pb::TensorProto {
        name: name.into(),
        data_type: FLOAT,
        float_data: vec![value],
        ..Default::default()
    }
}

fn trigger_id() -> pb::TensorProto {
    pb::TensorProto {
        name: "trigger".into(),
        data_type: INT64,
        int64_data: vec![i64::from(TRIGGER) + 3],
        ..Default::default()
    }
}

fn onnx(
    node: Vec<pb::NodeProto>,
    initializer: Vec<pb::TensorProto>,
    input_len: i64,
    output_dims: &[i64],
) -> Vec<u8> {
    pb::ModelProto {
        ir_version: 7,
        opset_import: vec![pb::OperatorSetIdProto {
            domain: String::new(),
            version: 11,
        }],
        graph: Some(pb::GraphProto {
            name: "test".into(),
            node,
            initializer,
            input: vec![value_info("ids", INT64, &[1, input_len])],
            output: vec![value_info("scores", FLOAT, output_dims)],
            ..Default::default()
        }),
        ..Default::default()
    }
    .encode_to_vec()
}

/// An assessment model that gives every value the same score.
fn constant_assessor(score: f32) -> Vec<u8> {
    onnx(
        vec![
            node("Cast", &["ids"], "as_float", cast_to_float()),
            node("ReduceSum", &["as_float"], "sum", reduce_over_row()),
            node("Mul", &["sum", "zero"], "zeroed", vec![]),
            node("Add", &["zeroed", "score"], "scores", vec![]),
        ],
        vec![float_scalar("zero", 0.0), float_scalar("score", score)],
        32,
        &[1, 1],
    )
}

/// An assessment model that scores 1 when the trigger byte is anywhere in what it sees, else 0.
fn trigger_assessor(input_len: i64) -> Vec<u8> {
    onnx(
        vec![
            node("Equal", &["ids", "trigger"], "hit", vec![]),
            node("Cast", &["hit"], "hit_float", cast_to_float()),
            node("ReduceMax", &["hit_float"], "scores", reduce_over_row()),
        ],
        vec![trigger_id()],
        input_len,
        &[1, 1],
    )
}

/// A detection model that scores 1 for every trigger byte, else 0.
fn trigger_detector(input_len: i64) -> Vec<u8> {
    onnx(
        vec![
            node("Equal", &["ids", "trigger"], "hit", vec![]),
            node("Cast", &["hit"], "scores", cast_to_float()),
        ],
        vec![trigger_id()],
        input_len,
        &[1, input_len],
    )
}

fn load(bytes: &[u8]) -> (Models, String) {
    let mut models = Models::new();
    let sha256 = models.load(bytes).expect("test model should load");
    (models, sha256)
}

fn model_rule(id: i64, detection_type: DetectionType, sha256: &str, threshold: i64) -> Rule {
    Rule {
        id,
        definition: RuleDefinition {
            name: Some(format!("Model rule {id}")),
            detection_type: Some(detection_type),
            severity: (detection_type == DetectionType::ModelDetection).then_some(Severity::Medium),
            model: Some(ModelRef {
                id: Some("test-model".into()),
                sha256: Some(sha256.into()),
            }),
            threshold: Some(threshold),
            ..RuleDefinition::default()
        },
    }
}

/// The built-in rules (ids 1–12) plus one model rule as id 100.
fn with_default_rules(rule: Rule) -> RuleSet {
    let mut rule_set = default_rule_set();
    rule_set.rules.push(rule);
    rule_set
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

fn assess(text: &str, model: &[u8], threshold: i64) -> ScanResult {
    let (models, sha256) = load(model);
    let rule_set = with_default_rules(model_rule(
        100,
        DetectionType::ModelAssessment,
        &sha256,
        threshold,
    ));
    scan_with_models(1, text, &rule_set, &models).expect("scan should run")
}

fn detect(text: &str, input_len: i64) -> ScanResult {
    let (models, sha256) = load(&trigger_detector(input_len));
    let rule_set = RuleSet {
        rules: vec![model_rule(1, DetectionType::ModelDetection, &sha256, 50)],
    };
    scan_with_models(1, text, &rule_set, &models).expect("scan should run")
}

#[test]
fn a_model_is_known_by_its_sha256_and_bad_bytes_do_not_load() {
    let mut models = Models::new();
    let sha256 = models.load(&constant_assessor(0.5)).unwrap();
    assert_eq!(sha256.len(), 64);
    assert!(sha256.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(models.load(&constant_assessor(0.5)).unwrap(), sha256);
    assert_ne!(models.load(&constant_assessor(0.6)).unwrap(), sha256);
    assert!(matches!(
        models.load(b"not a model"),
        Err(ModelLoadError::Invalid(_))
    ));
}

#[test]
fn an_assessment_rates_the_value_without_changing_the_rule_scores() {
    let text = format!("aws_access_key_id = {AWS_KEY}");
    let plain = scan(1, &text, &default_rule_set()).unwrap();
    let assessed = assess(&text, &constant_assessor(0.9), 80);

    let (before, after) = (matches(&plain)[0], matches(&assessed)[0]);
    assert_eq!(after.confidence, before.confidence);
    assert_eq!(after.placeholder_score, before.placeholder_score);
    assert_eq!(after.location, before.location);
    assert_eq!(
        after.model_assessments,
        [ModelAssessment {
            rule_id: 100,
            rule_name: "Model rule 100".into(),
            score: 90,
            verdict: ModelVerdict::LikelyReal,
        }]
    );
    assert!(
        after
            .why_flagged
            .ends_with("The Model rule 100 model rates it likely real (score 90, threshold 80).")
    );
    assert!(before.model_assessments.is_empty());
}

#[test]
fn a_score_below_the_threshold_is_likely_an_example() {
    let result = assess(&format!("key: {AWS_KEY}"), &constant_assessor(0.3), 80);
    let assessment = &matches(&result)[0].model_assessments[0];
    assert_eq!(assessment.score, 30);
    assert_eq!(assessment.verdict, ModelVerdict::LikelyExample);
}

#[test]
fn the_assessment_model_sees_the_text_around_the_value() {
    let model = trigger_assessor(32);
    let near = assess(&format!("~ key: {AWS_KEY}"), &model, 50);
    assert_eq!(
        matches(&near)[0].model_assessments[0].verdict,
        ModelVerdict::LikelyReal
    );

    let far = format!("~{}\nkey: {AWS_KEY}", " ".repeat(100));
    let far = assess(&far, &model, 50);
    assert_eq!(
        matches(&far)[0].model_assessments[0].verdict,
        ModelVerdict::LikelyExample
    );
}

#[test]
fn findings_with_no_value_get_no_assessment() {
    let result = assess("console.log(password)", &constant_assessor(0.9), 50);
    let found = matches(&result);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].detection_type, DetectionType::UnsafeHandling);
    assert!(found[0].model_assessments.is_empty());
}

#[test]
fn a_model_that_was_not_loaded_is_a_rule_error_and_the_other_rules_still_run() {
    let rule_set = with_default_rules(model_rule(
        100,
        DetectionType::ModelAssessment,
        &"0".repeat(64),
        50,
    ));
    let result = scan_with_models(1, &format!("key: {AWS_KEY}"), &rule_set, &Models::new())
        .expect("scan should run");
    assert_eq!(matches(&result).len(), 1);
    let error = result
        .findings
        .iter()
        .find_map(|finding| match &finding.violation {
            Violation::RuleError(error) => Some(error),
            Violation::Match(_) => None,
        })
        .expect("the model rule should be a rule error");
    assert_eq!(error.rule_id, 100);
    assert_eq!(error.field, RuleField::Model);
    assert_eq!(error.code, ErrorCode::ModelUnavailable);
    assert_eq!(
        error.message,
        "The model test-model was not loaded into the engine."
    );
}

#[test]
fn a_model_that_does_not_fit_its_rule_type_is_a_rule_error() {
    for (model, detection_type) in [
        (trigger_detector(16), DetectionType::ModelAssessment),
        (constant_assessor(0.5), DetectionType::ModelDetection),
    ] {
        let (models, sha256) = load(&model);
        let rule_set = with_default_rules(model_rule(100, detection_type, &sha256, 50));
        let result = scan_with_models(1, &format!("key: {AWS_KEY}"), &rule_set, &models).unwrap();
        let codes: Vec<ErrorCode> = result
            .findings
            .iter()
            .filter_map(|finding| match &finding.violation {
                Violation::RuleError(error) => Some(error.code),
                Violation::Match(_) => None,
            })
            .collect();
        assert_eq!(codes, [ErrorCode::ModelUnavailable], "{detection_type:?}");
    }
}

#[test]
fn a_detector_finds_spans_no_pattern_describes() {
    let text = "config: ~~~~~~~~~~~~ end";
    let result = detect(text, 16);
    let found = matches(&result);
    assert_eq!(found.len(), 1);
    let start = text.find('~').unwrap();
    assert_eq!(
        (found[0].location.start_byte, found[0].location.end_byte),
        (start, start + 12)
    );
    assert_eq!(found[0].detection_type, DetectionType::ModelDetection);
    assert_eq!(found[0].severity, Severity::Medium);
    assert_eq!(found[0].confidence, 100);
    assert_eq!(
        found[0].why_flagged,
        "Flagged by the Model rule 1 model (score 100, threshold 50). \
         Looks like an example: very little randomness."
    );
}

#[test]
fn detector_spans_shorter_than_the_minimum_are_dropped() {
    let short = "~".repeat(MIN_DETECTION_BYTES - 1);
    assert!(matches(&detect(&format!("a {short} b"), 16)).is_empty());
}

#[test]
fn a_span_across_window_edges_is_one_finding() {
    let text = format!("{}{}{}", "a".repeat(20), "~".repeat(30), "b".repeat(21));
    let result = detect(&text, 16);
    let found = matches(&result);
    assert_eq!(found.len(), 1);
    assert_eq!(
        (found[0].location.start_byte, found[0].location.end_byte),
        (20, 50)
    );
}

#[test]
fn model_scans_give_the_same_result_every_time() {
    let text = format!("~ key: {AWS_KEY}\nnotes: ~~~~~~~~~~~~");
    let (mut models, assessor) = load(&trigger_assessor(32));
    let detector = models.load(&trigger_detector(16)).unwrap();
    let rule_set = RuleSet {
        rules: vec![
            default_rule_set().rules[0].clone(),
            model_rule(7, DetectionType::ModelAssessment, &assessor, 50),
            model_rule(8, DetectionType::ModelDetection, &detector, 50),
        ],
    };
    let first = scan_with_models(1, &text, &rule_set, &models).unwrap();
    assert_eq!(matches(&first).len(), 2);
    for _ in 0..5 {
        assert_eq!(
            scan_with_models(1, &text, &rule_set, &models).unwrap(),
            first
        );
    }
}

#[test]
fn assessment_rules_alone_cannot_scan() {
    let (models, sha256) = load(&constant_assessor(0.5));
    let rule_set = RuleSet {
        rules: vec![model_rule(1, DetectionType::ModelAssessment, &sha256, 50)],
    };
    assert_eq!(
        scan_with_models(1, "key = value", &rule_set, &models),
        Err(ScanError::NoRulesEnabled)
    );
}

#[test]
fn listing_models_says_which_rule_types_each_fits() {
    let mut models = Models::new();
    let assessor = models.load(&constant_assessor(0.5)).unwrap();
    let detector = models.load(&trigger_detector(16)).unwrap();
    let mut expected = vec![
        ModelInfo {
            sha256: assessor,
            input_len: 32,
            output_len: 1,
            detection_types: vec![DetectionType::ModelAssessment],
        },
        ModelInfo {
            sha256: detector,
            input_len: 16,
            output_len: 16,
            detection_types: vec![DetectionType::ModelDetection],
        },
    ];
    expected.sort_by(|a, b| a.sha256.cmp(&b.sha256));
    assert_eq!(models.list(), expected);
}
