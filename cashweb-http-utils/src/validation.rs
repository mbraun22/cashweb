//! Module validating HTTP requests.

use hyper::{header::CONTENT_TYPE, HeaderMap};

use bitcoinsuite_error::{ErrorMeta, Report};

use thiserror::Error;

/// HTTP request validation error.
#[derive(Debug, Error, ErrorMeta)]
pub enum CashwebValidationError {
    /// HTTP "Content-Type" header was not set.
    #[invalid_client_input()]
    #[error("No Content-Type set")]
    NoContentTypeSet,

    /// "Content-Type" header has bad encoding.
    #[invalid_client_input()]
    #[error("Content-Type bad encoding: {0}")]
    BadContentType(String),

    /// "Content-Type" header expected to be specific value.
    #[invalid_client_input()]
    #[error("Content-Type must be {expected}, got {actual}")]
    WrongContentType {
        /// Content-Type expected by the handler.
        expected: &'static str,
        /// Content-Type provided by the request.
        actual: String,
    },
}

use self::CashwebValidationError::*;

/// Validate the "Content-Type" header matches `expected`.
pub fn check_content_type(headers: &HeaderMap, expected: &'static str) -> Result<(), Report> {
    let content_type = headers.get(CONTENT_TYPE).ok_or(NoContentTypeSet)?;
    let content_type = content_type
        .to_str()
        .map_err(|err| BadContentType(err.to_string()))?;
    if content_type != expected {
        return Err(WrongContentType {
            expected,
            actual: content_type.to_string(),
        }
        .into());
    }
    Ok(())
}
