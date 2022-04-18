//! Module containing [`RegistryServer`] to run the registry HTTP server.

use std::sync::Arc;

use axum::{body::Body, extract::Path, http::Response, routing, Extension, Router};
use bitcoinsuite_core::{Hashed, LotusAddress, LotusAddressError};
use bitcoinsuite_error::{ErrorMeta, Result};
use cashweb_http_utils::protobuf::Protobuf;
use thiserror::Error;

use crate::{http::error::HttpRegistryError, proto, registry::Registry};

/// Provides endpoints to read and write from the Cashweb Registry.
#[derive(Debug, Clone)]
pub struct RegistryServer {
    /// [`Registry`] this server accesses.
    pub registry: Arc<Registry>,
}

/// Errors indicating invalid requests being sent to the Registry endpoint.
#[derive(Debug, Error, ErrorMeta)]
pub enum RegistryServerError {
    /// Invalid lotus address in request.
    #[invalid_user_input()]
    #[error("Invalid lotus address: {0}")]
    InvalidAddress(LotusAddressError),

    /// Address metadata not found in registry.
    #[not_found()]
    #[error("Not found: No address metadata for {0} in registry")]
    AddressMetadataNotFound(LotusAddress),
}

use self::RegistryServerError::*;

impl RegistryServer {
    /// Turn this registry server into a [`Router`].
    pub fn into_router(self) -> Router {
        Router::new()
            .route(
                "/metadata/:addr",
                routing::put(handle_put_registry)
                    .get(handle_get_registry)
                    .options(handle_post_options),
            )
            .layer(Extension(self))
    }
}

async fn handle_post_options() -> Result<Response<Body>, HttpRegistryError> {
    Response::builder()
        .header("Allow", "OPTIONS, HEAD, POST, PUT, GET")
        .body(axum::body::Body::empty())
        .map_err(|err| HttpRegistryError(err.into()))
}

async fn handle_put_registry(
    Path(address): Path<String>,
    Protobuf(signed_metadata): Protobuf<cashweb_payload::proto::SignedPayload>,
    Extension(server): Extension<RegistryServer>,
) -> Result<Protobuf<proto::PutAddressMetadataResponse>, HttpRegistryError> {
    let address = address.parse::<LotusAddress>().map_err(InvalidAddress)?;
    let result = server
        .registry
        .put_metadata(&address, &signed_metadata)
        .await?;
    Ok(Protobuf(proto::PutAddressMetadataResponse {
        txid: result
            .txids
            .into_iter()
            .map(|txid| txid.as_slice().to_vec())
            .collect(),
    }))
}

async fn handle_get_registry(
    Path(address): Path<String>,
    Extension(server): Extension<RegistryServer>,
) -> Result<Protobuf<cashweb_payload::proto::SignedPayload>, HttpRegistryError> {
    let address = address.parse::<LotusAddress>().map_err(InvalidAddress)?;
    let signed_payload = server
        .registry
        .get_metadata(&address)?
        .ok_or(AddressMetadataNotFound(address))?;
    Ok(Protobuf(signed_payload.to_proto()))
}
