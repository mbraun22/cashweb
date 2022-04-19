//! Module containing [`Peers`].

use cashweb_payload::payload::SignedPayload;

use crate::{
    http::server::PutMetadataRequest,
    p2p::{peer::Peer, relay_info::RelayInfo},
    proto,
};

/// Peers the Cashweb registry is connected to.
#[derive(Debug)]
pub struct Peers {
    client: reqwest::Client,
    own_origin: String,
    /// List of [`Peer`] instances connected to the registry server.
    pub peers: Vec<Peer>,
}

impl Peers {
    /// Create [`Peers`] from a fixed list of peers.
    pub fn new(own_origin: String, peers: Vec<Peer>) -> Self {
        Peers {
            client: reqwest::Client::new(),
            own_origin,
            peers,
        }
    }

    /// Relay the metadata to all the peers.
    /// It will not forward to peers that (probably) already know the payload.
    pub async fn relay_metadata(
        &self,
        relay_info: &RelayInfo,
        request: &PutMetadataRequest,
        signed_metadata: &SignedPayload<proto::AddressMetadata>,
    ) {
        futures::future::join_all(self.peers.iter().map(|peer| {
            peer.relay_to(
                relay_info,
                request,
                signed_metadata,
                &self.own_origin,
                &self.client,
            )
        }))
        .await;
    }
}
