use crate::store::StoreError;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use secrets_scanner_engine::RuleError;

/// The JSON body of every error response.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct ErrorBody {
    pub error: String,
    /// Per-rule problems from the engine's checks, when the request failed them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<Object>)]
    pub errors: Vec<RuleError>,
}

#[derive(Debug)]
pub enum ApiError {
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

/// The default mapping. Routes override it where the HTTP meaning differs, e.g. an id named in
/// the request body that doesn't exist is a 422, not a 404.
impl From<StoreError> for ApiError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::NotFound(message) => Self::NotFound(message),
            StoreError::Invalid(message) => Self::invalid(message),
            StoreError::RulesInvalid(check) => Self::Invalid {
                message: "Some rules have errors. Fix them, then save the version again."
                    .to_owned(),
                errors: check.errors,
            },
            StoreError::Database(error) => error.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message, errors) = match self {
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
