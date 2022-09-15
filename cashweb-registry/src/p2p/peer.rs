//! Module containing the logic for an individual peer.

use std::str::FromStr;

use bitcoinsuite_core::{Hashed, LotusAddress};
use bitcoinsuite_error::Report;
use bloom::{BloomFilter, ASMS};
use cashweb_http_utils::protobuf::CONTENT_TYPE_PROTOBUF;
use cashweb_payload::payload::SignedPayload;
use reqwest::{
    header::{CONTENT_TYPE, ORIGIN},
    StatusCode,
};

use crate::{http::server::PutMetadataRequest, p2p::relay_info::RelayInfo, proto};

/// A single registry peer.
#[derive(Debug)]
pub struct Peer {
    url: url::Url,
    /// Mutable state of a [`Peer`].
    pub state: tokio::sync::Mutex<PeerState>,
}

/// The (mutable) state of a peer.
pub struct PeerState {
    /// Bloom filters of the payload hashes this peer has seen.
    pub filters: Vec<BloomFilter>,
    /// Number of items in the most recent Bloom filter.
    pub cur_num_items: usize,
    /// Max number of items in a Bloom filter.
    pub max_filter_items: usize,
    /// Max number of Bloom filters.
    pub max_filters: usize,
    /// Last reqwest error of this peer.
    pub last_error: Option<Report>,
    /// Status code of the last HTTP response.
    pub last_status: Option<StatusCode>,
    /// Bytes of the last HTTP response.
    pub last_http_response: Option<Vec<u8>>,
}

/// What action has been taken for an individual peer when relaying metadata (for testing)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelayAction {
    /// The peer is the origin of the PUT request.
    /// Sending the same request back would be unnecessary.
    SkippedOrigin,
    /// Peer (probably) already knows about the PUT request.
    KnowsPayload,
    /// Sending to the peer failed (e.g. timeout, not online).
    SendError,
    /// Reading the response from the peer failed.
    ResponseError,
    /// Relaying didn't result in the expected OK response.
    HttpError,
    /// Relaying OK.
    Success,
}

/// What action has been taken for an individual peer when fetching metadata (for testing)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FetchError {
    /// Sending to the peer failed (e.g. timeout, not online).
    SendError,
    /// Reading the response from the peer failed.
    ResponseError,
    /// Relaying didn't result in the expected OK response.
    HttpError,
    /// Response is not the expected protobuf.
    InvalidProtobufError,
    /// Response contained an invalid [`LotusAddress`].
    InvalidLotusAddress,
    /// Response `signed_payload` is empty.
    MissingMetadata,
    /// Response `signed_payload` could not be parsed into valid [`SignedPayload<proto::AddressMetadata>`].
    ParseMetadataError,
}

impl Peer {
    /// Make new peer with the given URL.
    pub fn new(url: url::Url) -> Self {
        Peer {
            url,
            state: tokio::sync::Mutex::new(PeerState {
                filters: Vec::new(),
                cur_num_items: 0,
                max_filter_items: 10_000,
                max_filters: 8,
                last_error: None,
                last_status: None,
                last_http_response: None,
            }),
        }
    }

    /// Relay the PUT metadata request to the peer.
    /// Skips sending if request originated from this peer, or if it (probably) already knows it.
    pub async fn relay_to(
        &self,
        relay_info: &RelayInfo,
        request: &PutMetadataRequest,
        signed_metadata: &SignedPayload<proto::AddressMetadata>,
        own_origin: &str,
        client: &reqwest::Client,
    ) -> RelayAction {
        use prost::Message;
        let mut state = self.state.lock().await;
        let payload_hash = signed_metadata.payload_hash().as_slice();
        if self.should_skip_relay(relay_info) {
            state.add_known_payload(payload_hash);
            return RelayAction::SkippedOrigin;
        }
        if state.knows_payload(payload_hash) {
            return RelayAction::KnowsPayload;
        }
        let response = client
            .put(format!("{}metadata/{}", self.url, request.address.as_str()))
            .header(CONTENT_TYPE, CONTENT_TYPE_PROTOBUF)
            .header(ORIGIN, own_origin)
            .body(request.signed_metadata.encode_to_vec())
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(err) => {
                state.last_error = Some(err.into());
                return RelayAction::SendError;
            }
        };
        let status = response.status();
        state.last_status = Some(status);
        let response = match response.bytes().await {
            Ok(response) => response,
            Err(err) => {
                state.last_error = Some(err.into());
                return RelayAction::ResponseError;
            }
        };
        state.last_http_response = Some(response.to_vec());
        state.last_error = None;
        if status != StatusCode::OK {
            return RelayAction::HttpError;
        }
        state.add_known_payload(payload_hash);
        RelayAction::Success
    }

    /// Fetch a bunch of address metadata since the given timestamp and address.
    pub async fn fetch_range_since(
        &self,
        timestamp: i64,
        address: &LotusAddress,
        client: &reqwest::Client,
    ) -> Result<Vec<(LotusAddress, SignedPayload<proto::AddressMetadata>)>, FetchError> {
        use prost::Message;
        let response = client
            .get(format!(
                "{}metadata?start_timestamp={}&last_address={}",
                self.url, timestamp, address,
            ))
            .send()
            .await;
        let mut state = self.state.lock().await;
        let response = match response {
            Ok(response) => response,
            Err(err) => {
                state.last_error = Some(err.into());
                return Err(FetchError::SendError);
            }
        };
        let status = response.status();
        state.last_status = Some(status);
        let response = match response.bytes().await {
            Ok(response) => response,
            Err(err) => {
                state.last_error = Some(err.into());
                return Err(FetchError::ResponseError);
            }
        };
        state.last_http_response = Some(response.to_vec());
        state.last_error = None;
        if status != StatusCode::OK {
            return Err(FetchError::HttpError);
        }
        let response = match proto::GetMetadataRangeResponse::decode(response) {
            Ok(response) => response,
            Err(err) => {
                state.last_error = Some(err.into());
                return Err(FetchError::InvalidProtobufError);
            }
        };
        let mut entries = Vec::new();
        for entry in response.entries {
            let address = match LotusAddress::from_str(&entry.address) {
                Ok(address) => address,
                Err(err) => {
                    state.last_error = Some(err.into());
                    return Err(FetchError::InvalidLotusAddress);
                }
            };
            let signed_payload = entry.signed_payload.ok_or(FetchError::MissingMetadata)?;
            let signed_payload =
                SignedPayload::<proto::AddressMetadata>::parse_proto(&signed_payload);
            let signed_metadata = match signed_payload {
                Ok(signed_payload) => signed_payload,
                Err(err) => {
                    state.last_error = Some(err);
                    return Err(FetchError::ParseMetadataError);
                }
            };
            entries.push((address, signed_metadata));
        }
        Ok(entries)
    }

    fn should_skip_relay(&self, relay_info: &RelayInfo) -> bool {
        if relay_info.origin.scheme() != self.url.scheme() {
            return false;
        }
        if relay_info.origin.host() != self.url.host() {
            return false;
        }
        if relay_info.origin.port() != self.url.port() {
            return false;
        }
        true
    }

    /// URL of the [`Peer`]
    pub fn url(&self) -> &url::Url {
        &self.url
    }
}

impl PeerState {
    fn add_known_payload(&mut self, payload_hash: &[u8]) {
        if self.filters.is_empty() || self.max_filter_items == self.cur_num_items {
            self.cur_num_items = 0;
            self.filters.insert(
                0,
                BloomFilter::with_rate(0.0001, self.max_filter_items as u32),
            );
        }
        if self.filters.len() > self.max_filters {
            self.filters.pop();
        }
        self.filters[0].insert(&payload_hash);
        self.cur_num_items += 1;
    }

    fn knows_payload(&self, payload_hash: &[u8]) -> bool {
        for filter in &self.filters {
            if filter.contains(&payload_hash) {
                return true;
            }
        }
        false
    }
}

impl std::fmt::Debug for PeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerState")
            .field("filters", &"vec![...]")
            .field("cur_num_items", &self.cur_num_items)
            .field("max_filter_items", &self.max_filter_items)
            .field("max_filters", &self.max_filters)
            .field("last_error", &self.last_error)
            .field("last_status", &self.last_status)
            .field("last_http_response", &self.last_http_response)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, net::SocketAddr};

    use axum::{
        body::Body,
        extract::{Path, Query},
        http::HeaderMap,
        response::Response,
        routing,
    };
    use bitcoinsuite_core::{LotusAddress, LotusAddressError};
    use bitcoinsuite_error::Result;
    use bitcoinsuite_test_utils::pick_ports;
    use cashweb_payload::payload::{ParseSignedPayloadError, SignatureScheme, SignedPayload};
    use pretty_assertions::assert_eq;
    use prost::Message;
    use reqwest::StatusCode;

    use crate::{
        http::server::PutMetadataRequest,
        p2p::peer::{FetchError, Peer, PeerState, RelayAction, RelayInfo},
        proto,
    };

    #[test]
    fn test_bloom() {
        let mut state = PeerState {
            filters: vec![],
            cur_num_items: 0,
            max_filter_items: 4,
            max_filters: 3,
            last_error: None,
            last_status: None,
            last_http_response: None,
        };
        state.add_known_payload(&[1; 32]);
        assert_eq!(state.filters.len(), 1);
        assert_eq!(state.cur_num_items, 1);
        assert!(state.knows_payload(&[1; 32]));
        assert!(!state.knows_payload(&[2; 32]));

        state.add_known_payload(&[2; 32]);
        assert_eq!(state.filters.len(), 1);
        assert_eq!(state.cur_num_items, 2);
        assert!(state.knows_payload(&[1; 32]));
        assert!(state.knows_payload(&[2; 32]));
        assert!(!state.knows_payload(&[3; 32]));

        state.add_known_payload(&[3; 32]);
        state.add_known_payload(&[4; 32]);
        assert_eq!(state.filters.len(), 1);
        assert_eq!(state.cur_num_items, 4);
        assert!(state.knows_payload(&[1; 32]));
        assert!(state.knows_payload(&[4; 32]));
        assert!(!state.knows_payload(&[5; 32]));

        state.add_known_payload(&[5; 32]);
        assert_eq!(state.filters.len(), 2);
        assert_eq!(state.cur_num_items, 1);
        assert!(state.knows_payload(&[1; 32]));
        assert!(state.knows_payload(&[5; 32]));
        assert!(!state.knows_payload(&[6; 32]));

        for i in 6..=12 {
            state.add_known_payload(&[i; 32]);
        }
        assert_eq!(state.filters.len(), 3);
        assert_eq!(state.cur_num_items, 4);

        state.add_known_payload(&[13; 32]);
        assert_eq!(state.filters.len(), 3);
        assert_eq!(state.cur_num_items, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_relay_to() -> Result<()> {
        const INVALID_ADDRESS: &str = "lotusR16PSJNf1EDEfGvaYzaXJCJZrXH4pgiTo7kyVqAied";
        const VALID_ADDRESS: &str = "lotusR16PSJMw2kpXdpk9Kn7qX6cYA7MbLg23bfTtXL7zeQ";
        async fn handle_metadata(Path(path): Path<String>) -> Response<Body> {
            if path == INVALID_ADDRESS {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(format!("invalid address: {}", path).into())
                    .unwrap();
            }
            Response::new(format!("address: {}", path).into())
        }
        let router = axum::Router::new().route("/metadata/:address", routing::put(handle_metadata));

        let ports = pick_ports(2)?;
        let port = ports[0];
        let socket_addr = format!("127.0.0.1:{}", port).parse::<SocketAddr>()?;
        let url = format!("http://{}", socket_addr).parse::<url::Url>()?;

        let offline_port = ports[1];
        let offline_url = format!("http://127.0.0.1:{}", offline_port).parse::<url::Url>()?;

        let own_origin = "http://localhost";

        tokio::spawn(axum::Server::bind(&socket_addr).serve(router.into_make_service()));

        let peer = Peer::new(url.clone());
        let client = reqwest::Client::new();
        let request = PutMetadataRequest {
            address: VALID_ADDRESS.parse()?,
            header_map: HeaderMap::new(),
            signed_metadata: cashweb_payload::proto::SignedPayload::default(),
        };
        let signed_metadata = SignedPayload::parse_proto(&cashweb_payload::proto::SignedPayload {
            pubkey: vec![0; 33],
            sig: vec![],
            sig_scheme: SignatureScheme::Ecdsa as i32,
            payload: proto::AddressMetadata {
                timestamp: 1234,
                ..Default::default()
            }
            .encode_to_vec(),
            ..Default::default()
        })?;

        // Metadata originates from peer
        let relay_info = RelayInfo {
            origin: url.clone(),
        };
        let relay_action = peer
            .relay_to(&relay_info, &request, &signed_metadata, own_origin, &client)
            .await;
        assert_eq!(relay_action, RelayAction::SkippedOrigin);

        // Peer already knows payload from previous relay
        let relay_info = RelayInfo {
            origin: "http://anywhere.com".parse()?,
        };
        let relay_action = peer
            .relay_to(&relay_info, &request, &signed_metadata, own_origin, &client)
            .await;
        assert_eq!(relay_action, RelayAction::KnowsPayload);

        let offline_peer = Peer::new(offline_url.clone());
        let relay_action = offline_peer
            .relay_to(&relay_info, &request, &signed_metadata, own_origin, &client)
            .await;
        assert_eq!(relay_action, RelayAction::SendError);
        {
            let state = offline_peer.state.lock().await;
            let last_err = state.last_error.as_ref().unwrap();
            assert!(
                last_err
                    .to_string()
                    .starts_with("error sending request for url"),
                "Error doesn't start with expected string: {}",
                last_err,
            );
        }

        // New peer, returns HTTP error
        let peer = Peer::new(url.clone());
        let relay_info = RelayInfo {
            origin: "http://anywhere.com".parse()?,
        };
        let invalid_request = PutMetadataRequest {
            address: INVALID_ADDRESS.parse()?,
            header_map: HeaderMap::new(),
            signed_metadata: cashweb_payload::proto::SignedPayload::default(),
        };
        let relay_action = peer
            .relay_to(
                &relay_info,
                &invalid_request,
                &signed_metadata,
                own_origin,
                &client,
            )
            .await;
        assert_eq!(relay_action, RelayAction::HttpError);
        {
            let state = peer.state.lock().await;
            assert!(state.last_error.is_none());
            assert_eq!(state.last_status, Some(StatusCode::BAD_REQUEST));
            assert_eq!(
                state.last_http_response.as_deref(),
                Some(format!("invalid address: {}", INVALID_ADDRESS).as_bytes())
            );
        }

        // Relay accepted by peer
        let valid_request = PutMetadataRequest {
            address: VALID_ADDRESS.parse()?,
            header_map: HeaderMap::new(),
            signed_metadata: cashweb_payload::proto::SignedPayload::default(),
        };
        let relay_action = peer
            .relay_to(
                &relay_info,
                &valid_request,
                &signed_metadata,
                own_origin,
                &client,
            )
            .await;
        assert_eq!(relay_action, RelayAction::Success);
        {
            let state = peer.state.lock().await;
            assert!(state.last_error.is_none());
            assert_eq!(state.last_status, Some(StatusCode::OK));
            assert_eq!(
                state.last_http_response.as_deref(),
                Some(format!("address: {}", VALID_ADDRESS).as_bytes())
            );
        }

        // Trying to relaying again hits bloom filter
        let relay_action = peer
            .relay_to(
                &relay_info,
                &valid_request,
                &signed_metadata,
                own_origin,
                &client,
            )
            .await;
        assert_eq!(relay_action, RelayAction::KnowsPayload);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_fetch_range_since() -> Result<()> {
        const VALID_ADDRESS_STR: &str = "lotusR16PSJMw2kpXdpk9Kn7qX6cYA7MbLg23bfTtXL7zeQ";
        let valid_address: LotusAddress = VALID_ADDRESS_STR.parse()?;
        enum TestCase {
            BadRequest = 1111,
            InvalidProtobuf = 2222,
            InvalidAddress = 3333,
            MissingMetadata = 4444,
            InvalidMetadata = 5555,
            Valid = 6666,
        }
        async fn handle_metadata_range(
            Query(params): Query<HashMap<String, String>>,
        ) -> Response<Body> {
            let start_timestamp = params
                .get("start_timestamp")
                .unwrap()
                .parse::<i64>()
                .unwrap();
            if start_timestamp == TestCase::BadRequest as i64 {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body("invalid timestamp".into())
                    .unwrap();
            }
            if start_timestamp == TestCase::InvalidProtobuf as i64 {
                return Response::builder().body("invalid protobuf".into()).unwrap();
            }
            let proto_response = if start_timestamp == TestCase::InvalidAddress as i64 {
                proto::GetMetadataRangeResponse {
                    entries: vec![proto::GetMetadataRangeEntry {
                        address: "invalid*address".to_string(),
                        signed_payload: None,
                    }],
                }
            } else if start_timestamp == TestCase::MissingMetadata as i64 {
                proto::GetMetadataRangeResponse {
                    entries: vec![proto::GetMetadataRangeEntry {
                        address: VALID_ADDRESS_STR.to_string(),
                        signed_payload: None, // missing metadata
                    }],
                }
            } else if start_timestamp == TestCase::InvalidMetadata as i64 {
                proto::GetMetadataRangeResponse {
                    entries: vec![proto::GetMetadataRangeEntry {
                        address: VALID_ADDRESS_STR.to_string(),
                        signed_payload: Some(Default::default()),
                    }],
                }
            } else if start_timestamp == TestCase::Valid as i64 {
                proto::GetMetadataRangeResponse {
                    entries: vec![proto::GetMetadataRangeEntry {
                        address: VALID_ADDRESS_STR.to_string(),
                        signed_payload: Some(cashweb_payload::proto::SignedPayload {
                            pubkey: vec![0; 33],
                            sig: vec![],
                            sig_scheme: SignatureScheme::Ecdsa as i32,
                            payload: proto::AddressMetadata {
                                timestamp: 1234,
                                ttl: 10,
                                entries: vec![],
                            }
                            .encode_to_vec(),
                            payload_hash: vec![],
                            burn_amount: 0,
                            burn_txs: vec![],
                        }),
                    }],
                }
            } else {
                unimplemented!()
            };
            Response::builder()
                .body(proto_response.encode_to_vec().into())
                .unwrap()
        }
        let router = axum::Router::new().route("/metadata", routing::get(handle_metadata_range));

        let ports = pick_ports(2)?;
        let port = ports[0];
        let socket_addr = format!("127.0.0.1:{}", port).parse::<SocketAddr>()?;
        let url = format!("http://{}", socket_addr).parse::<url::Url>()?;

        let offline_port = ports[1];
        let offline_url = format!("http://127.0.0.1:{}", offline_port).parse::<url::Url>()?;

        tokio::spawn(axum::Server::bind(&socket_addr).serve(router.into_make_service()));

        let peer = Peer::new(url.clone());
        let client = reqwest::Client::new();

        {
            let offline_peer = Peer::new(offline_url.clone());
            let fetch_error = offline_peer
                .fetch_range_since(TestCase::BadRequest as i64, &valid_address, &client)
                .await
                .unwrap_err();
            assert_eq!(fetch_error, FetchError::SendError);
            let state = offline_peer.state.lock().await;
            let last_err = state.last_error.as_ref().unwrap();
            assert!(
                last_err
                    .to_string()
                    .starts_with("error sending request for url"),
                "Error doesn't start with expected string: {}",
                last_err,
            );
        }

        {
            let fetch_error = peer
                .fetch_range_since(TestCase::InvalidProtobuf as i64, &valid_address, &client)
                .await
                .unwrap_err();
            assert_eq!(fetch_error, FetchError::InvalidProtobufError);
            let state = peer.state.lock().await;
            assert_eq!(
                state.last_error.as_ref().unwrap().to_string(),
                "failed to decode Protobuf message: buffer underflow",
            );
            assert_eq!(state.last_status, Some(StatusCode::OK));
            assert_eq!(
                state.last_http_response.as_deref(),
                Some(b"invalid protobuf".as_ref()),
            );
        }

        {
            let fetch_error = peer
                .fetch_range_since(TestCase::InvalidAddress as i64, &valid_address, &client)
                .await
                .unwrap_err();
            assert_eq!(fetch_error, FetchError::InvalidLotusAddress);
            let state = peer.state.lock().await;
            assert_eq!(
                state
                    .last_error
                    .as_ref()
                    .unwrap()
                    .downcast_ref::<LotusAddressError>()
                    .unwrap(),
                &LotusAddressError::UnsupportedNet('*'),
            );
            assert_eq!(state.last_status, Some(StatusCode::OK));
        }

        {
            let fetch_error = peer
                .fetch_range_since(TestCase::MissingMetadata as i64, &valid_address, &client)
                .await
                .unwrap_err();
            assert_eq!(fetch_error, FetchError::MissingMetadata);
            let state = peer.state.lock().await;
            assert!(state.last_error.is_none());
            assert_eq!(state.last_status, Some(StatusCode::OK));
        }

        {
            let fetch_error = peer
                .fetch_range_since(TestCase::InvalidMetadata as i64, &valid_address, &client)
                .await
                .unwrap_err();
            assert_eq!(fetch_error, FetchError::ParseMetadataError);
            let state = peer.state.lock().await;
            assert_eq!(
                state
                    .last_error
                    .as_ref()
                    .unwrap()
                    .downcast_ref::<ParseSignedPayloadError>()
                    .unwrap(),
                &ParseSignedPayloadError::InvalidPubKeyLen(0),
            );
            assert_eq!(state.last_status, Some(StatusCode::OK));
        }

        {
            let entries = peer
                .fetch_range_since(TestCase::Valid as i64, &valid_address, &client)
                .await
                .unwrap();
            let state = peer.state.lock().await;
            assert!(state.last_error.is_none());
            assert_eq!(state.last_status, Some(StatusCode::OK));
            assert_eq!(
                entries,
                vec![(
                    valid_address,
                    SignedPayload::parse_proto(&cashweb_payload::proto::SignedPayload {
                        pubkey: vec![0; 33],
                        sig: vec![],
                        sig_scheme: SignatureScheme::Ecdsa as i32,
                        payload: proto::AddressMetadata {
                            timestamp: 1234,
                            ttl: 10,
                            entries: vec![],
                        }
                        .encode_to_vec(),
                        payload_hash: vec![],
                        burn_amount: 0,
                        burn_txs: vec![],
                    })?,
                )],
            );
        }

        Ok(())
    }
}
