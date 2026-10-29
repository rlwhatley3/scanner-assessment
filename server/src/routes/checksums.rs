//! Tries a checksum setup on one example value, so a rule author can see whether they described
//! their format right before saving the rule.

use super::{AppState, error::ApiError};
use axum::{Json, Router, routing::post};
use secrets_scanner_engine::Checksum;
use serde_json::Value;

/// The longest example value accepted; tokens are far shorter.
const MAX_VALUE_LENGTH: usize = 1000;

pub fn router() -> Router<AppState> {
    Router::new().route("/try", post(try_checksum))
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TryChecksumRequest {
    /// A rule's `checksum` setting, as it would be saved.
    #[schema(value_type = Object)]
    checksum: Value,
    /// One example value. It is checked and not stored.
    value: String,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct TryChecksumResponse {
    /// Whether the value passes the checksum.
    valid: bool,
    /// For setups read as prefix + covered part + checksum, where each part of this value
    /// starts; absent for other setups or a value too short to hold all three.
    layout: Option<ChecksumLayout>,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumLayout {
    /// Characters before this are the prefix the checksum doesn't cover.
    covered_start: usize,
    /// Characters from here to the end hold the checksum.
    checksum_start: usize,
}

#[utoipa::path(
    post,
    path = "/api/checksums/try",
    tag = "Rules",
    summary = "Try a checksum on one value",
    description = "Checks one example value against a checksum setup without saving anything, \
                   and says which characters are the prefix, the covered part, and the checksum.",
    request_body = TryChecksumRequest,
    responses(
        (status = 200, description = "Whether the value passes", body = TryChecksumResponse),
        (status = 422, description = "The setup can't run, or the value is too long", body = super::ErrorBody)
    )
)]
pub async fn try_checksum(
    Json(body): Json<TryChecksumRequest>,
) -> Result<Json<TryChecksumResponse>, ApiError> {
    let checksum: Checksum = serde_json::from_value(body.checksum)
        .map_err(|error| ApiError::invalid(format!("This checksum setup isn't valid: {error}")))?;
    if let Some(problem) = checksum.problem() {
        return Err(ApiError::invalid(problem));
    }
    if body.value.chars().count() > MAX_VALUE_LENGTH {
        return Err(ApiError::invalid(format!(
            "The example can be at most {MAX_VALUE_LENGTH} characters."
        )));
    }
    let value = body.value;
    let layout = checksum
        .layout()
        .filter(|&(prefix_length, length)| value.is_ascii() && value.len() > prefix_length + length)
        .map(|(prefix_length, length)| ChecksumLayout {
            covered_start: prefix_length,
            checksum_start: value.len() - length,
        });
    Ok(Json(TryChecksumResponse {
        valid: checksum.is_valid(&value),
        layout,
    }))
}
