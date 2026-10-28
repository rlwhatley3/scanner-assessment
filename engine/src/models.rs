//! The models that model rules run.
//!
//! The engine does no I/O, so callers read model files themselves and hand the bytes to
//! [`Models::load`]. A model is known by the SHA-256 of its bytes, which is what a rule's
//! `model.sha256` names, so a rule set version always points at the exact model it scanned with.
//!
//! Every model reads one row of token ids, `int64[1, L]`, where `L` is fixed by the model:
//! `0` pads, `1` and `2` mark where a value starts and ends, and each byte `b` of the text is
//! `b + 3`. What a model returns depends on the rule type that runs it; see `engine/README.md`.
//!
//! Models run on the CPU through tract with the `ml` feature. Without it, nothing can be loaded
//! and every model rule reports that the engine was built without model support.

use crate::rules::DetectionType;
use serde::Serialize;
use std::collections::HashMap;

const PAD_ID: i64 = 0;
const VALUE_START_ID: i64 = 1;
const VALUE_END_ID: i64 = 2;
const BYTE_OFFSET: i64 = 3;

/// The models a scan can use, keyed by the SHA-256 of their bytes.
#[derive(Default)]
pub struct Models {
    loaded: HashMap<String, LoadedModel>,
}

/// Why a model could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelLoadError {
    /// The engine was built without the `ml` feature.
    Unsupported,
    /// The bytes are not an ONNX model the engine can run.
    Invalid(String),
}

impl std::fmt::Display for ModelLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelLoadError::Unsupported => {
                f.write_str("This engine was built without model support.")
            }
            ModelLoadError::Invalid(reason) => write!(f, "The model could not be loaded: {reason}"),
        }
    }
}

impl std::error::Error for ModelLoadError {}

impl Models {
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads an ONNX model and returns its SHA-256, which is how rules refer to it. Loading
    /// the same bytes twice is a no-op.
    pub fn load(&mut self, bytes: &[u8]) -> Result<String, ModelLoadError> {
        let sha256 = sha256_hex(bytes)?;
        if !self.loaded.contains_key(&sha256) {
            let model = LoadedModel::from_onnx(bytes).map_err(ModelLoadError::Invalid)?;
            self.loaded.insert(sha256.clone(), model);
        }
        Ok(sha256)
    }

    pub(crate) fn get(&self, sha256: &str) -> Option<&LoadedModel> {
        self.loaded.get(sha256)
    }

    /// Every loaded model, by hash, with the model rule types it can run as.
    pub fn list(&self) -> Vec<ModelInfo> {
        let mut models: Vec<ModelInfo> = self
            .loaded
            .iter()
            .map(|(sha256, model)| ModelInfo {
                sha256: sha256.clone(),
                input_len: model.input_len(),
                output_len: model.output_len(),
                detection_types: [
                    DetectionType::ModelAssessment,
                    DetectionType::ModelDetection,
                ]
                .into_iter()
                .filter(|&detection_type| model.fits(detection_type))
                .collect(),
            })
            .collect();
        models.sort_by(|a, b| a.sha256.cmp(&b.sha256));
        models
    }
}

/// A loaded model's shape, and which model rule types it fits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelInfo {
    pub sha256: String,
    pub input_len: usize,
    pub output_len: usize,
    pub detection_types: Vec<DetectionType>,
}

impl LoadedModel {
    /// Whether the model's shape fits a rule type: an assessment returns one score for a value
    /// (with room for the value's markers), a detection one score per byte of its window.
    pub(crate) fn fits(&self, detection_type: DetectionType) -> bool {
        match detection_type {
            DetectionType::ModelAssessment => self.output_len() == 1 && self.input_len() >= 3,
            DetectionType::ModelDetection => self.output_len() == self.input_len(),
            _ => false,
        }
    }
}

/// Turns a model output into a 0–100 score. Rounding before any threshold is applied keeps tiny
/// floating-point differences from flipping a result.
pub(crate) fn to_score(probability: f32) -> u8 {
    (probability.clamp(0.0, 1.0) * 100.0).round() as u8
}

/// A classifier's input for one value: the value between its markers, with as much of the text
/// on either side as fits, split evenly when both sides have room. A value too long to fit is
/// cut short and gets no surrounding text.
pub(crate) fn encode_value(text: &[u8], start: usize, end: usize, len: usize) -> Vec<i64> {
    let budget = len.saturating_sub(2);
    let value_end = end.min(start + budget);
    let room = budget - (value_end - start);
    let after = (room - (room / 2).min(start)).min(text.len() - end);
    let before = (room - after).min(start);

    let mut ids = Vec::with_capacity(len);
    ids.extend(text[start - before..start].iter().map(byte_id));
    ids.push(VALUE_START_ID);
    ids.extend(text[start..value_end].iter().map(byte_id));
    ids.push(VALUE_END_ID);
    ids.extend(text[end..end + after].iter().map(byte_id));
    ids.resize(len, PAD_ID);
    ids
}

/// A detector's input for one window of text, padded to `len`.
pub(crate) fn encode_window(window: &[u8], len: usize) -> Vec<i64> {
    let mut ids: Vec<i64> = window.iter().map(byte_id).collect();
    ids.resize(len, PAD_ID);
    ids
}

fn byte_id(byte: &u8) -> i64 {
    i64::from(*byte) + BYTE_OFFSET
}

#[cfg(feature = "ml")]
fn sha256_hex(bytes: &[u8]) -> Result<String, ModelLoadError> {
    use sha2::{Digest, Sha256};
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(not(feature = "ml"))]
fn sha256_hex(_bytes: &[u8]) -> Result<String, ModelLoadError> {
    Err(ModelLoadError::Unsupported)
}

/// A model ready to run, with its input and output lengths.
#[cfg(feature = "ml")]
pub(crate) struct LoadedModel {
    plan: std::sync::Arc<tract_onnx::prelude::TypedRunnableModel>,
    input_len: usize,
    output_len: usize,
}

#[cfg(feature = "ml")]
impl LoadedModel {
    fn from_onnx(bytes: &[u8]) -> Result<Self, String> {
        use tract_onnx::prelude::*;

        let model = tract_onnx::onnx()
            .model_for_read(&mut &bytes[..])
            .map_err(|_| "it is not a valid ONNX model.".to_string())?;
        if model.inputs.len() != 1 || model.outputs.is_empty() {
            return Err("it must have exactly one input.".to_string());
        }
        // The batch size may be left open; the engine always runs one row at a time.
        let input_len = model
            .input_fact(0)
            .ok()
            .map(|fact| fact.shape.clone())
            .and_then(|mut shape| {
                shape.set_dim(0, TDim::from(1));
                shape.as_concrete_finite().ok().flatten()
            })
            .filter(|dims| dims.len() == 2 && dims[1] > 0)
            .map(|dims| dims[1])
            .ok_or("its input must be int64[1, L] with a fixed length L.")?;
        let plan = model
            .with_input_fact(0, i64::fact([1, input_len]).into())
            .and_then(|model| model.into_optimized())
            .and_then(|model| model.into_runnable())
            .map_err(|error| format!("tract could not prepare it ({error})."))?;

        let mut loaded = Self {
            plan,
            input_len,
            output_len: 0,
        };
        // One run on an empty input to learn how many scores the model returns.
        loaded.output_len = loaded
            .run(&vec![PAD_ID; input_len])
            .map_err(|_| "it failed on an empty input.".to_string())?
            .len();
        Ok(loaded)
    }

    pub fn input_len(&self) -> usize {
        self.input_len
    }

    pub fn output_len(&self) -> usize {
        self.output_len
    }

    /// Runs the model on one row of ids and returns its first output as scores between 0 and 1.
    /// The error never contains the input.
    pub fn run(&self, ids: &[i64]) -> Result<Vec<f32>, ()> {
        use tract_onnx::prelude::*;

        let input = Tensor::from_shape(&[1, self.input_len], ids).map_err(|_| ())?;
        let outputs = self.plan.run(tvec!(input.into())).map_err(|_| ())?;
        let output = outputs
            .first()
            .ok_or(())?
            .cast_to::<f32>()
            .map_err(|_| ())?;
        let scores: Vec<f32> = output
            .to_plain_array_view::<f32>()
            .map_err(|_| ())?
            .iter()
            .copied()
            .collect();
        if scores.iter().all(|score| score.is_finite()) {
            Ok(scores)
        } else {
            Err(())
        }
    }
}

/// Without the `ml` feature no model can be loaded, so this has no values.
#[cfg(not(feature = "ml"))]
pub(crate) enum LoadedModel {}

#[cfg(not(feature = "ml"))]
impl LoadedModel {
    fn from_onnx(_bytes: &[u8]) -> Result<Self, String> {
        Err("this engine was built without model support.".to_string())
    }

    pub fn input_len(&self) -> usize {
        match *self {}
    }

    pub fn output_len(&self) -> usize {
        match *self {}
    }

    pub fn run(&self, _ids: &[i64]) -> Result<Vec<f32>, ()> {
        match *self {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(ids: &[i64]) -> String {
        ids.iter()
            .map(|&id| match id {
                PAD_ID => '_',
                VALUE_START_ID => '[',
                VALUE_END_ID => ']',
                id => char::from((id - BYTE_OFFSET) as u8),
            })
            .collect()
    }

    #[test]
    fn a_value_gets_markers_and_an_even_share_of_text_on_each_side() {
        let text = b"0123456789KEY0123456789";
        assert_eq!(bytes(&encode_value(text, 10, 13, 11)), "789[KEY]012");
    }

    #[test]
    fn room_one_side_cannot_use_goes_to_the_other() {
        let text = b"KEY0123456789";
        assert_eq!(bytes(&encode_value(text, 0, 3, 11)), "[KEY]012345");
        let text = b"0123456789KEY";
        assert_eq!(bytes(&encode_value(text, 10, 13, 11)), "456789[KEY]");
    }

    #[test]
    fn short_text_is_padded_and_long_values_are_cut_short() {
        assert_eq!(bytes(&encode_value(b"a KEY b", 2, 5, 12)), "a [KEY] b___");
        assert_eq!(bytes(&encode_value(b"a LONGVALUE b", 2, 11, 6)), "[LONG]");
    }

    #[test]
    fn a_window_is_its_bytes_then_padding() {
        assert_eq!(bytes(&encode_window(b"abc", 5)), "abc__");
    }

    #[test]
    fn scores_round_and_stay_in_range() {
        assert_eq!(to_score(0.874), 87);
        assert_eq!(to_score(0.875), 88);
        assert_eq!(to_score(-1.0), 0);
        assert_eq!(to_score(2.0), 100);
    }
}
