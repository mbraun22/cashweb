//! Module containing [`RegistryServer`] to run the registry HTTP server.

use std::sync::Arc;

use axum::{body::Body, extract::Path, http::Response, routing, Extension, Router};
use bitcoinsuite_core::{Hashed, LotusAddress, LotusAddressError, Net, ScriptVariant};
use bitcoinsuite_error::{ErrorMeta, Result};
use cashweb_http_utils::protobuf::Protobuf;
use thiserror::Error;

use crate::{
    http::error::HttpRegistryError,
    proto,
    registry::Registry,
    store::pubkeyhash::{PkhAlgorithm, PubKeyHash},
};

/// Provides endpoints to read and write from the Cashweb Registry.
#[derive(Debug, Clone)]
pub struct RegistryServer {
    /// [`Registry`] this server accesses.
    pub registry: Arc<Registry>,
    /// Whether server is running on a mainnet or regtest network.
    pub net: Net,
}

/// Errors indicating invalid requests being sent to the Registry endpoint.
#[derive(Debug, Error, ErrorMeta)]
pub enum RegistryServerError {
    /// Provided string doesn't name a known [`PkhAlgorithm`].
    #[invalid_client_input()]
    #[error("Invalid public key hash algorithm {0:?}, expected \"p2pkh\"")]
    InvalidPkhAlgorithm(String),

    /// Invalid lotus address in request.
    #[invalid_user_input()]
    #[error("Invalid lotus address: {0}")]
    InvalidAddress(LotusAddressError),

    /// Invalid lotus address in request.
    #[invalid_user_input()]
    #[error("Invalid address net, expected {expected:?} but got {actual:?}")]
    InvalidAddressNet {
        /// Net expected by the server.
        expected: Net,
        /// Net encoded in the address.
        actual: Net,
    },

    /// Invalid lotus address in request.
    #[invalid_client_input()]
    #[error("Unsupported address script variant: {0:?}")]
    UnsupportedScriptVariant(ScriptVariant),

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

    fn parse_address(&self, address: &LotusAddress) -> Result<PubKeyHash> {
        if address.net() != self.net {
            return Err(InvalidAddressNet {
                expected: self.net,
                actual: address.net(),
            }
            .into());
        }
        match address.script().parse_variant() {
            ScriptVariant::P2PKH(hash) => {
                PubKeyHash::new(PkhAlgorithm::Sha256Ripemd160, hash.as_slice().into())
            }
            variant => Err(UnsupportedScriptVariant(variant).into()),
        }
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
    let pkh = server.parse_address(&address)?;
    let txids = server.registry.put_metadata(&pkh, signed_metadata).await?;
    Ok(Protobuf(proto::PutAddressMetadataResponse {
        txid: txids
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
    let pkh = server.parse_address(&address)?;
    let signed_payload = server
        .registry
        .get_metadata(&pkh)?
        .ok_or(AddressMetadataNotFound(address))?;
    Ok(Protobuf(signed_payload.to_proto()))
}
