use crate::validation::RuleError;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

/// The JSON body of every error response.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct ErrorBody {
    pub error: String,
    /// Per-rule problems, when the request failed validation.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<RuleError>,
}

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    NotFound(String),
    Conflict(String),
    Invalid {
        message: String,
        errors: Vec<RuleError>,
    },
    Internal,
}

impl ApiError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid {
            message: message.into(),
            errors: Vec::new(),
        }
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(error: rusqlite::Error) -> Self {
        // Rule definitions and findings never hold scan text, but keep the log to the error kind.
        eprintln!("database error: {error}");
        Self::Internal
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message, errors) = match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message, Vec::new()),
            Self::NotFound(message) => (StatusCode::NOT_FOUND, message, Vec::new()),
            Self::Conflict(message) => (StatusCode::CONFLICT, message, Vec::new()),
            Self::Invalid { message, errors } => {
                (StatusCode::UNPROCESSABLE_ENTITY, message, errors)
            }
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong on the server.".to_owned(),
                Vec::new(),
            ),
        };
        (
            status,
            Json(ErrorBody {
                error: message,
                errors,
            }),
        )
            .into_response()
    }
}

/// Reads a JSON text column, failing the row if it does not parse.
pub fn json_column<T: serde::de::DeserializeOwned>(
    row: &rusqlite::Row,
    index: usize,
) -> rusqlite::Result<T> {
    let text: String = row.get(index)?;
    serde_json::from_str(&text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}
