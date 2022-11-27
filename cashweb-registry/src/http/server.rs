//! Module containing [`RegistryServer`] to run the registry HTTP server.

use std::{collections::HashMap, str::FromStr, sync::Arc};

use axum::{
    body::Body,
    extract::{Path, Query},
    http::{HeaderMap, Response},
    routing, Extension, Router,
};
use bitcoinsuite_core::{Hashed, LotusAddress, LotusAddressError};
use bitcoinsuite_error::{ErrorMeta, Result};
use cashweb_http_utils::protobuf::Protobuf;
use thiserror::Error;

use crate::{
    http::error::HttpRegistryError,
    p2p::{peers::Peers, relay_info::RelayInfo},
    proto,
    registry::{PutMetadataResult, Registry},
};

/// Provides endpoints to read and write from the Cashweb Registry.
#[derive(Debug, Clone)]
pub struct RegistryServer {
    /// [`Registry`] this server accesses.
    pub registry: Arc<Registry>,
    /// [`Peers`] connected to the server.
    pub peers: Arc<Peers>,
}

/// Relevant parts of an HTTP request to put new address metadata.
#[derive(Debug, Clone)]
pub struct PutMetadataRequest {
    /// Address the metadata should be updated for.
    pub address: LotusAddress,
    /// HTTP headers of the PUT request.
    pub header_map: HeaderMap,
    /// Signed serialized [`proto::AddressMetadata`] payload.
    pub signed_metadata: cashweb_payload::proto::SignedPayload,
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

    /// A query param is not valid.
    #[invalid_client_input()]
    #[error("Invalid {param}: {value:?} is invalid: {msg}")]
    InvalidQueryParam {
        /// Name of the query param in question.
        param: &'static str,
        /// Value provided for the query param.
        value: String,
        /// Why the value is invalid.
        msg: String,
    },
}

use self::RegistryServerError::*;

impl RegistryServer {
    /// Turn this registry server into a [`Router`].
    pub fn into_router(self) -> Router {
        Router::new()
            .route("/metadata", routing::get(handle_get_metadata_range))
            .route(
                "/metadata/:addr",
                routing::put(handle_put_registry)
                    .get(handle_get_registry)
                    .options(handle_post_options),
            )
            .layer(Extension(self))
    }

    async fn put_metadata(&self, request: PutMetadataRequest) -> Result<PutMetadataResult> {
        let relay_info = RelayInfo::parse_from_headers(&request.header_map)?;
        let result = self
            .registry
            .put_metadata(&request.address, &request.signed_metadata)
            .await?;
        // Relay to peers in a separate task
        tokio::spawn({
            let signed_metadata = result.signed_metadata.clone();
            let peers = Arc::clone(&self.peers);
            async move {
                peers
                    .relay_metadata(&relay_info, &request, &signed_metadata)
                    .await
            }
        });
        Ok(result)
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
    header_map: HeaderMap,
) -> Result<Protobuf<proto::PutSignedPayloadResponse>, HttpRegistryError> {
    let address = address.parse::<LotusAddress>().map_err(InvalidAddress)?;
    let request = PutMetadataRequest {
        address,
        header_map,
        signed_metadata,
    };
    let result = server.put_metadata(request).await?;
    Ok(Protobuf(proto::PutSignedPayloadResponse {
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

async fn handle_get_metadata_range(
    Query(params): Query<HashMap<String, String>>,
    Extension(server): Extension<RegistryServer>,
) -> Result<Protobuf<proto::GetMetadataRangeResponse>, HttpRegistryError> {
    const START_TIMESTAMP: &str = "start_timestamp";
    const END_TIMESTAMP: &str = "end_timestamp";
    const NUM_ITEMS: &str = "num_items";
    const LAST_ADDRESS: &str = "last_address";
    const MAX_NUM_ITEMS: usize = 100;
    let start_timestamp = match params.get(START_TIMESTAMP) {
        Some(start_timestamp) => {
            start_timestamp
                .parse::<i64>()
                .map_err(|err| InvalidQueryParam {
                    param: START_TIMESTAMP,
                    value: start_timestamp.to_string(),
                    msg: err.to_string(),
                })?
        }
        None => 0,
    };
    let end_timestamp = match params.get(END_TIMESTAMP) {
        Some(end_timestamp) => {
            Some(
                end_timestamp
                    .parse::<i64>()
                    .map_err(|err| InvalidQueryParam {
                        param: END_TIMESTAMP,
                        value: end_timestamp.to_string(),
                        msg: err.to_string(),
                    })?,
            )
        }
        None => None,
    };
    let num_items = match params.get(NUM_ITEMS) {
        Some(num_items) => num_items
            .parse::<usize>()
            .map_err(|err| InvalidQueryParam {
                param: NUM_ITEMS,
                value: num_items.to_string(),
                msg: err.to_string(),
            })?
            .min(MAX_NUM_ITEMS),
        None => MAX_NUM_ITEMS,
    };
    let last_address = match params.get(LAST_ADDRESS) {
        Some(last_address) => {
            Some(
                LotusAddress::from_str(last_address).map_err(|err| InvalidQueryParam {
                    param: LAST_ADDRESS,
                    value: last_address.to_string(),
                    msg: err.to_string(),
                })?,
            )
        }
        None => None,
    };
    let metadata_range = server.registry.get_metadata_range(
        start_timestamp,
        end_timestamp,
        last_address.as_ref(),
        num_items,
    )?;
    Ok(Protobuf(proto::GetMetadataRangeResponse {
        entries: metadata_range
            .entries
            .into_iter()
            .map(|(address, signed_payload)| proto::GetMetadataRangeEntry {
                address: address.as_str().to_string(),
                signed_payload: Some(signed_payload.to_proto()),
            })
            .collect(),
    }))
}
