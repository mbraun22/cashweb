//! Module containing [`RegistryServer`] to run the registry HTTP server.

use crate::{
    http::error::HttpRegistryError,
    p2p::{peers::Peers, relay_info::RelayInfo},
    proto::{self},
    registry::Registry,
};
use axum::{
    extract::{Path, Query},
    http::{header, HeaderMap, Method},
    middleware::from_fn,
    routing, Extension, Router,
};
use bitcoinsuite_core::{Hashed, LotusAddress, LotusAddressError};
use bitcoinsuite_error::{ErrorMeta, Result};
use cashweb_http_utils::protobuf::Protobuf;
use cashweb_payload::proto::SignedPayloadSet;
use serde::Deserialize;
use std::{collections::HashMap, str::FromStr, sync::Arc};
use thiserror::Error;
use tower_http::cors::{Any, CorsLayer};
use tracing::Level;

#[derive(Deserialize)]
struct MessagesQuery {
    from: Option<i64>,
    to: Option<i64>,
}

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

async fn log_request<B>(
    request: axum::http::Request<B>,
    next: axum::middleware::Next<B>,
) -> axum::response::Response {
    let method = request.method().to_owned();
    let uri = request.uri().to_owned();
    let start = std::time::Instant::now();

    let response = next.run(request).await;

    tracing::event!(
        Level::INFO,
        method = method.as_str(),
        path = uri.path(),
        // latency = format_args!("{} ms", latency.as_millis()),
        status = response.status().as_u16(),
        duration = format!("{} mcs", start.elapsed().as_micros()),
        "finished processing request"
    );

    response
}

impl RegistryServer {
    /// Turn this registry server into a [`Router`].
    pub fn into_router(self) -> Router {
        Router::new()
            .route("/metadata", routing::get(handle_get_metadata_range))
            .route(
                "/metadata/:addr",
                routing::put(handle_put_registry).get(handle_get_registry),
            )
            .route("/messages/:topic", routing::get(handle_get_messages))
            .route("/messages", routing::get(handle_get_all_messages))
            .route("/message", routing::put(handle_put_message))
            .route("/message/:payload_hash", routing::get(handle_get_message))
            .layer(Extension(self))
            .layer(
                CorsLayer::new()
                    .allow_methods([
                        Method::GET,
                        Method::PUT,
                        Method::POST,
                        Method::HEAD,
                        Method::OPTIONS,
                    ])
                    .allow_headers([header::CONTENT_TYPE])
                    // allow requests from any origin
                    .allow_origin(Any),
            )
            .layer(from_fn(log_request))
    }
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

    let relay_info = RelayInfo::parse_from_headers(&request.header_map)?;
    let result = server
        .registry
        .put_metadata(&request.address, &request.signed_metadata)
        .await?;
    // Relay to peers in a separate task
    tokio::spawn({
        let signed_metadata = result.signed_metadata.clone();
        let peers = Arc::clone(&server.peers);
        async move {
            peers
                .relay_metadata(&relay_info, &request, &signed_metadata)
                .await
        }
    });

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

async fn handle_get_messages(
    Path(topic): Path<String>,
    Query(params): Query<MessagesQuery>,
    Extension(server): Extension<RegistryServer>,
) -> Result<Protobuf<cashweb_payload::proto::SignedPayloadSet>, HttpRegistryError> {
    let from = params.from.unwrap_or_default();
    let to = params.to.unwrap_or(i64::MAX);

    let signed_payloads = server
        .registry
        .get_messages(topic.as_str(), from, to)?
        .iter()
        .map(|signed_payload| signed_payload.to_proto())
        .collect();

    let payload_page = SignedPayloadSet {
        items: signed_payloads,
    };

    Ok(Protobuf(payload_page))
}

async fn handle_get_all_messages(
    Query(params): Query<MessagesQuery>,
    Extension(server): Extension<RegistryServer>,
) -> Result<Protobuf<cashweb_payload::proto::SignedPayloadSet>, HttpRegistryError> {
    let from = params.from.unwrap_or_default();
    let to = params.to.unwrap_or(i64::MAX);

    let signed_payloads = server
        .registry
        .get_messages("", from, to)?
        .iter()
        .map(|signed_payload| signed_payload.to_proto())
        .collect();

    let payload_page = SignedPayloadSet {
        items: signed_payloads,
    };

    Ok(Protobuf(payload_page))
}

async fn handle_get_message(
    Path(hex_hash): Path<String>,
    Extension(server): Extension<RegistryServer>,
) -> Result<Protobuf<cashweb_payload::proto::SignedPayload>, HttpRegistryError> {
    let payload_hash = hex::decode(&hex_hash).map_err(|err| HttpRegistryError(err.into()))?;
    let message = server.registry.get_message(payload_hash)?;

    Ok(Protobuf(message.to_proto()))
}

async fn handle_put_message(
    Protobuf(message): Protobuf<cashweb_payload::proto::SignedPayload>,
    Extension(server): Extension<RegistryServer>,
) -> Result<Protobuf<proto::PutSignedPayloadResponse>, HttpRegistryError> {
    let result = server.registry.put_message(&message).await?;

    Ok(Protobuf(proto::PutSignedPayloadResponse {
        txid: result
            .txids
            .into_iter()
            .map(|txid| txid.as_slice().to_vec())
            .collect(),
    }))
}
