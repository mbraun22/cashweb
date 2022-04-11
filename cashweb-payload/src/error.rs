//! Module containing [`report_to_error_meta`] to map errors of this crate to [`ErrorMeta`].

use bitcoinsuite_error::{ErrorMeta, Report};

use crate::{payload::ParseSignedPayloadError, verify::ValidateSignedPayloadError};

/// Maps errors occuring in this crate to an [`ErrorMeta`] trait object.
pub fn report_to_error_meta(report: &Report) -> Option<&dyn ErrorMeta> {
    if let Some(err) = report.downcast_ref::<ParseSignedPayloadError>() {
        Some(err)
    } else if let Some(err) = report.downcast_ref::<ValidateSignedPayloadError>() {
        Some(err)
    } else {
        None
    }
}
