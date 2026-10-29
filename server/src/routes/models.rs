use super::AppState;
use axum::{Json, extract::State};
use secrets_scanner_engine::ModelUse;
use serde::Serialize;

#[derive(Serialize, utoipa::ToSchema, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ModelResponse {
    /// A readable name for the model.
    id: String,
    /// The SHA-256 of the model file, which is how a rule names the model.
    sha256: String,
    /// How many token ids the model reads at once.
    input_length: usize,
    /// What the model can be used for: `model_assessment` or `model_detection` rules, or a
    /// rule's `value_classifier` setting.
    #[schema(value_type = Vec<String>)]
    #[schemars(with = "Vec<String>")]
    uses: Vec<ModelUse>,
}

#[utoipa::path(
    get,
    path = "/api/models",
    tag = "Models",
    summary = "List models",
    description = "The models this API has loaded, which model rules can name by SHA-256.",
    responses((status = 200, description = "Loaded models, by name", body = [ModelResponse]))
)]
pub async fn list(State(state): State<AppState>) -> Json<Vec<ModelResponse>> {
    Json(loaded_models(&state))
}

/// The loaded models, by name. The MCP server lists them the same way.
pub fn loaded_models(state: &AppState) -> Vec<ModelResponse> {
    let mut models: Vec<ModelResponse> = state
        .models
        .list()
        .into_iter()
        .map(|model| ModelResponse {
            id: state
                .model_names
                .get(&model.sha256)
                .cloned()
                .unwrap_or_else(|| model.sha256[..12].to_owned()),
            sha256: model.sha256,
            input_length: model.input_len,
            uses: model.uses,
        })
        .collect();
    models.sort_by(|a, b| a.id.cmp(&b.id));
    models
}
