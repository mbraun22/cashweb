//! Module containing tools for mapping [`Report`]s to HTTP errors.

use axum::response::{IntoResponse, Response};
use bitcoinsuite_error::{report_to_details, ErrorDetails, ErrorMeta, ErrorSeverity, Report};
use hyper::StatusCode;

use crate::{
    proto,
    protobuf::{CashwebProtobufError, Protobuf},
    validation::CashwebValidationError,
};

/// Error newtype for [`Report`], for errors of this crate.
/// Implements [`IntoResponse`].
#[derive(Debug)]
pub struct HttpUtilError(pub Report);

impl From<Report> for HttpUtilError {
    fn from(err: Report) -> Self {
        HttpUtilError(err)
    }
}

impl From<CashwebProtobufError> for HttpUtilError {
    fn from(err: CashwebProtobufError) -> Self {
        HttpUtilError(err.into())
    }
}

impl IntoResponse for HttpUtilError {
    fn into_response(self) -> Response {
        let details = report_to_details(&self.0, self::report_to_error_meta);
        details_to_status_proto(details).into_response()
    }
}

/// Map the [`ErrorDetails`] to a [`StatusCode`] and [`proto::Error`] instance.
/// Status is based on the [`ErrorSeverity`] of `details`.
pub fn details_to_status_proto(details: ErrorDetails) -> (StatusCode, Protobuf<proto::Error>) {
    match details.severity {
        ErrorSeverity::NotFound => (
            StatusCode::NOT_FOUND,
            Protobuf(proto::Error {
                error_code: details.error_code.to_string(),
                msg: details.msg,
                is_user_error: true,
            }),
        ),
        ErrorSeverity::InvalidUserInput => (
            StatusCode::BAD_REQUEST,
            Protobuf(proto::Error {
                error_code: details.error_code.to_string(),
                msg: details.msg,
                is_user_error: true,
            }),
        ),
        ErrorSeverity::InvalidClientInput => {
            println!("Invalid client input: {}", details.msg);
            (
                StatusCode::BAD_REQUEST,
                Protobuf(proto::Error {
                    error_code: details.error_code.to_string(),
                    msg: details.msg,
                    is_user_error: false,
                }),
            )
        }
        ErrorSeverity::Critical
        | ErrorSeverity::Unknown
        | ErrorSeverity::Bug
        | ErrorSeverity::Warning => {
            println!("Unhandled error ({:?}):", details.severity);
            println!("{}", details.full_debug_report);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Protobuf(proto::Error {
                    error_code: "internal-server-error".into(),
                    msg: "Internal server error".to_string(),
                    is_user_error: false,
                }),
            )
        }
    }
}

/// Maps errors occuring in this crate to an [`ErrorMeta`] trait object.
pub fn report_to_error_meta(report: &Report) -> Option<&dyn ErrorMeta> {
    if let Some(err) = report.downcast_ref::<CashwebProtobufError>() {
        Some(err)
    } else if let Some(err) = report.downcast_ref::<CashwebValidationError>() {
        Some(err)
    } else {
        None
    }
}
