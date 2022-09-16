//! Module for [`RelayInfo`].

use std::str::Utf8Error;

use axum::http::HeaderMap;
use bitcoinsuite_error::{ErrorMeta, Result};
use reqwest::header::ORIGIN;
use thiserror::Error;

/// Data extracted from a request necessary for relaying.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct RelayInfo {
    /// 'Origin' header of the incoming metadata PUT request.
    pub origin: url::Url,
}

/// Errors parsing RelayInfo.
#[derive(Error, ErrorMeta, Clone, Debug, Eq, PartialEq)]
pub enum RelayInfoError {
    /// HTTP request is missing the 'Origin' header.
    #[invalid_client_input()]
    #[error("'Origin' header missing")]
    MissingOrigin,

    /// 'Origin' header is not valid UTF-8.
    #[invalid_client_input()]
    #[error("'Origin' header not valid UTF-8: {0}")]
    OriginInvalidUtf8(Utf8Error),

    /// 'Origin' header is not a valid URL.
    #[invalid_client_input()]
    #[error("'Origin' header not a valid URL: {0}")]
    OriginInvaidUrl(url::ParseError),
}

use self::RelayInfoError::*;

impl RelayInfo {
    /// Parse the [`RelayInfo`] from an HTTP [`HeaderMap`].
    pub fn parse_from_headers(header_map: &HeaderMap) -> Result<Self> {
        let origin = header_map.get(ORIGIN).ok_or(MissingOrigin)?;
        let origin = std::str::from_utf8(origin.as_bytes()).map_err(OriginInvalidUtf8)?;
        let origin = url::Url::parse(origin).map_err(OriginInvaidUrl)?;
        Ok(RelayInfo { origin })
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};
    use bitcoinsuite_error::Result;
    use reqwest::header::ORIGIN;

    use crate::p2p::relay_info::{RelayInfo, RelayInfoError};

    #[test]
    fn test_parse_from_headers() -> Result<()> {
        assert_eq!(
            RelayInfo::parse_from_headers(&HeaderMap::new())
                .unwrap_err()
                .downcast::<RelayInfoError>()?,
            RelayInfoError::MissingOrigin,
        );

        let mut header_map = HeaderMap::new();
        header_map.insert(ORIGIN, HeaderValue::from_bytes(&[0xf0, 0x20])?);
        assert_eq!(
            RelayInfo::parse_from_headers(&header_map)
                .unwrap_err()
                .downcast::<RelayInfoError>()?
                .to_string(),
            "'Origin' header not valid UTF-8: invalid utf-8 sequence of 1 bytes from index 0",
        );

        header_map.insert(ORIGIN, HeaderValue::from_static("http://anywhere.com"));
        assert_eq!(
            RelayInfo::parse_from_headers(&header_map)?,
            RelayInfo {
                origin: "http://anywhere.com".parse()?,
            },
        );

        Ok(())
    }
}
