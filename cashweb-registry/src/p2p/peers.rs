//! Module containing [`Peers`].

use std::{cmp::Ordering, time::Duration};

use bitcoinsuite_core::{LotusAddress, Script, ShaRmd160, LOTUS_PREFIX};
use bitcoinsuite_error::Result;
use cashweb_payload::payload::SignedPayload;
use futures::{FutureExt, StreamExt};
use rand::Rng;

use crate::{
    http::server::PutMetadataRequest,
    p2p::{peer::Peer, relay_info::RelayInfo},
    proto,
    registry::{Registry, RegistryError},
    store::pubkeyhash::PubKeyHash,
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

/// Params for how and where to download metadata from peers
#[derive(Debug)]
pub struct InitialMetadataDownloadParams<'a> {
    /// Registry to download the params into
    pub registry: &'a Registry,
    /// How many peers will be sampled each round when syncing
    pub num_sampled_peers: usize,
    /// When we stop waiting for a peer to respond
    pub timeout_peer: Duration,
    /// How many failed rounds (rounds with no successful results at all)
    /// of querying peers we do before we wait some time
    pub num_failed_for_wait: usize,
    /// How long we wait after N rounds failed
    pub fail_wait_duration: Duration,
}

impl Peers {
    /// Download initial metadata from peers.
    pub async fn initial_metadata_download(
        &self,
        rng: &mut impl Rng,
        params: &InitialMetadataDownloadParams<'_>,
    ) -> Result<()> {
        // Get the last timestamp and address from the registry
        let (mut timestamp, mut address) =
            params.registry.get_latest_metadata()?.unwrap_or_else(|| {
                let zero_pkh_script = Script::p2pkh(&ShaRmd160::new([0; 20]));
                let zero_pkh =
                    LotusAddress::new(LOTUS_PREFIX, params.registry.net(), zero_pkh_script);
                (0, zero_pkh)
            });
        // Exit already if there's no peers
        if self.peers.is_empty() {
            println!("No peers to sync from");
            return Ok(());
        }
        // How many rounds all peers failed (timeout/error)
        let mut num_failed_rounds = 0;
        loop {
            // Select a few peers to poll
            let sample_peers = self.pick_sample_peers(rng, params.num_sampled_peers);
            // The function gives us some stats on what happened
            let result = self
                .fetch_sample_peers(params, &sample_peers, &mut timestamp, &mut address)
                .await;
            match result {
                FetchSamplePeersResult::FinishedImd => return Ok(()),
                FetchSamplePeersResult::InProgress {
                    num_timeouts,
                    num_failed_fetches,
                    num_failed_entries,
                    num_outdated_entries,
                    num_successful_entries,
                } => {
                    println!(
                        "Fetched metadata: successes={}, timeouts={}, failed fetches={}, \
                         failed entries={}, outdated entries={}",
                        num_successful_entries,
                        num_timeouts,
                        num_failed_fetches,
                        num_failed_entries,
                        num_outdated_entries,
                    );
                    if num_successful_entries == 0 {
                        num_failed_rounds += 1;
                    } else {
                        num_failed_rounds = 0;
                    }
                    if num_failed_rounds >= params.num_failed_for_wait {
                        println!(
                            "Failed {} times in a row, waiting for {} seconds",
                            num_failed_rounds,
                            params.fail_wait_duration.as_secs_f64(),
                        );
                        num_failed_rounds = 0;
                        tokio::time::sleep(params.fail_wait_duration).await;
                    }
                }
            }
        }
    }

    fn pick_sample_peers(&self, rng: &mut impl Rng, num_sampled_peers: usize) -> Vec<&Peer> {
        let mut available_peers = self.peers.iter().collect::<Vec<_>>();
        let mut sample_peers = Vec::with_capacity(num_sampled_peers);
        for _ in 0..num_sampled_peers {
            if available_peers.is_empty() {
                return sample_peers;
            }
            let idx = rng.gen_range(0..available_peers.len());
            let peer = available_peers.swap_remove(idx);
            sample_peers.push(peer);
        }
        sample_peers
    }
}

enum FetchSamplePeersResult {
    FinishedImd,
    InProgress {
        num_timeouts: usize,
        num_failed_fetches: usize,
        num_failed_entries: usize,
        num_outdated_entries: usize,
        num_successful_entries: usize,
    },
}

impl Peers {
    async fn fetch_sample_peers(
        &self,
        params: &InitialMetadataDownloadParams<'_>,
        sample_peers: &[&Peer],
        last_timestamp: &mut i64,
        last_address: &mut LotusAddress,
    ) -> FetchSamplePeersResult {
        let last_address_clone = last_address.clone();
        let streams = sample_peers.iter().map(|&peer| {
            Box::pin(
                peer.fetch_range_since(*last_timestamp, &last_address_clone, &self.client)
                    .map(move |result| (peer, result))
                    .into_stream(),
            )
        });
        let mut results = futures::stream::select_all(streams);
        let mut num_timeouts = 0;
        let mut num_failed_fetches = 0;
        let mut num_failed_entries = 0;
        let mut num_outdated_entries = 0;
        let mut num_successful_entries = 0;
        let mut is_all_empty = true;
        for _ in sample_peers.iter() {
            let result = tokio::time::timeout(params.timeout_peer, results.next()).await;
            let (peer, result) = match result {
                Ok(result) => result.expect("should always have enough items"),
                Err(elapsed) => {
                    print!(
                        "ERROR: All peers timed out after {} (polled {:?})",
                        elapsed,
                        sample_peers
                            .iter()
                            .map(|peer| peer.url())
                            .collect::<Vec<_>>()
                    );
                    num_timeouts += 1;
                    continue;
                }
            };
            let entries = match result {
                Ok(entries) => entries,
                Err(fetch_err) => {
                    println!("Fetch failed for peer {}: {:?}", peer.url(), fetch_err);
                    num_failed_fetches += 1;
                    continue;
                }
            };
            if !entries.is_empty() {
                println!("Fetched {} entries from {}", entries.len(), peer.url());
            }
            for (address, signed_metadata) in entries {
                is_all_empty = false;
                let mut peer_state = peer.state.lock().await;
                match params
                    .registry
                    .put_metadata(&address, &signed_metadata.to_proto())
                    .await
                {
                    Ok(_result) => peer_state.last_error = None,
                    Err(err) => {
                        if let Some(RegistryError::TimestampNotMonotonicallyIncreasing { .. }) =
                            err.downcast_ref::<RegistryError>()
                        {
                            num_outdated_entries += 1;
                        } else {
                            peer_state.last_error = Some(err);
                            num_failed_entries += 1;
                        }
                        continue;
                    }
                }
                match signed_metadata.payload().timestamp.cmp(last_timestamp) {
                    Ordering::Less => {}
                    Ordering::Equal => {
                        let last_pkh =
                            PubKeyHash::from_address(last_address, last_address.net()).unwrap();
                        let pkh = PubKeyHash::from_address(&address, address.net()).unwrap();
                        if last_pkh.to_storage_bytes() < pkh.to_storage_bytes() {
                            *last_address = address;
                        }
                    }
                    Ordering::Greater => {
                        *last_timestamp = signed_metadata.payload().timestamp;
                        *last_address = address;
                    }
                }
                num_successful_entries += 1;
            }
        }
        if is_all_empty {
            FetchSamplePeersResult::FinishedImd
        } else {
            FetchSamplePeersResult::InProgress {
                num_timeouts,
                num_failed_fetches,
                num_failed_entries,
                num_outdated_entries,
                num_successful_entries,
            }
        }
    }
}
