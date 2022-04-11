//! Module containing [`HttpRegistryError`], an error newtype and [`report_to_error_meta`] to map
//! errors of this crate to [`ErrorMeta`].

use axum::response::{IntoResponse, Response};
use bitcoinsuite_error::{report_to_details, ErrorMeta, Report};
use cashweb_http_utils::error::details_to_status_proto;

use crate::{
    http::server::RegistryServerError, registry::RegistryError, store::pubkeyhash::PkhError,
};

/// Newtype around [`Report`], implements [`IntoResponse`].
#[derive(Debug)]
pub struct HttpRegistryError(pub Report);

impl From<Report> for HttpRegistryError {
    fn from(err: Report) -> Self {
        HttpRegistryError(err)
    }
}

impl From<RegistryServerError> for HttpRegistryError {
    fn from(err: RegistryServerError) -> Self {
        HttpRegistryError(err.into())
    }
}

impl IntoResponse for HttpRegistryError {
    fn into_response(self) -> Response {
        let details = report_to_details(&self.0, self::report_to_error_meta);
        details_to_status_proto(details).into_response()
    }
}

/// Maps errors occuring in this crate to an [`ErrorMeta`] trait object.
pub fn report_to_error_meta(report: &Report) -> Option<&dyn ErrorMeta> {
    if let Some(err) = report.downcast_ref::<RegistryServerError>() {
        Some(err)
    } else if let Some(err) = report.downcast_ref::<RegistryError>() {
        Some(err)
    } else if let Some(err) = report.downcast_ref::<PkhError>() {
        Some(err)
    } else if let Some(err) = cashweb_payload::error::report_to_error_meta(report) {
        Some(err)
    } else {
        None
    }
}
