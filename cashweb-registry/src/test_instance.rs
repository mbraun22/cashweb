//! Module for [`RegistryTestInstance`].

use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};

use bitcoinsuite_bitcoind::instance::{BitcoindConf, BitcoindInstance};
use bitcoinsuite_core::{
    ecc::{Ecc, PubKey, SecKey},
    BitcoinCode, Hashed, Net, OutPoint, Script, Sha256, TxOutput, UnhashedTx,
};
use bitcoinsuite_error::Result;
use bitcoinsuite_test_utils::{is_free_tcp, pick_ports};
use bitcoinsuite_test_utils_blockchain::build_tx;
use cashweb_payload::{payload::SignatureScheme, verify::build_commitment_script};
use prost::Message;

use crate::{
    http::server::RegistryServer,
    p2p::{peer::Peer, peers::Peers},
    proto,
    registry::Registry,
    store::db::Db,
};

/// A Registry instance connected to a regtest bitcoind instance.
#[derive(Debug)]
pub struct RegistryTestInstance {
    /// Regtest bitcoind instance.
    pub bitcoind: BitcoindInstance,
    /// URL of the registry server.
    pub url: String,
    /// Port of the registry server.
    pub port: u16,
    /// Registry of the server.
    pub registry: Arc<Registry>,
    /// Peers of the server.
    pub peers: Arc<Peers>,
}

impl RegistryTestInstance {
    /// Setup a new bitcoind and registry instance on regtest.
    pub async fn setup(dir: &Path, conf: BitcoindConf, peers: Vec<Peer>) -> Result<Self> {
        let db = Db::open(dir.join("db.rocksdb"))?;

        let bitcoind = BitcoindInstance::setup(conf)?;

        let port = pick_ports(1)?[0];
        let socket_addr = format!("127.0.0.1:{}", port).parse::<SocketAddr>()?;
        let url = format!("http://{}", socket_addr);

        let registry = Arc::new(Registry::new(
            db,
            bitcoind.rpc_client().clone(),
            Net::Regtest,
        ));
        let peers = Arc::new(Peers::new(url.clone(), peers));
        let server = RegistryServer {
            registry: Arc::clone(&registry),
            peers: Arc::clone(&peers),
        };

        let router = server.into_router();

        tokio::spawn(axum::Server::bind(&socket_addr).serve(router.into_make_service()));

        Ok(RegistryTestInstance {
            bitcoind,
            url,
            port,
            registry,
            peers,
        })
    }

    /// Wait until the bitcoind and registry server are live.
    pub async fn wait_for_ready(&mut self) -> Result<()> {
        self.bitcoind.wait_for_ready()?;
        let mut attempt = 0;
        while is_free_tcp(self.port) {
            attempt += 1;
            if attempt > 100 {
                panic!("Failed to start server");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    }

    /// Clean up the instance.
    pub fn cleanup(&self) -> Result<()> {
        self.bitcoind.cleanup()
    }
}

/// Build a [`cashweb_payload::proto::SignedPayload`] for testing.
pub fn build_signed_metadata(
    seckey: &SecKey,
    pubkey: PubKey,
    ecc: &dyn Ecc,
    utxos: &mut Vec<(OutPoint, i64)>,
    redeem_script: &Script,
    address_metadata: proto::AddressMetadata,
) -> (cashweb_payload::proto::SignedPayload, UnhashedTx) {
    let payload_hash = Sha256::digest(address_metadata.encode_to_vec().into());

    // Build burn commitment tx
    let (outpoint, amount) = utxos.pop().unwrap();
    let burn_amount = amount - 10_000;
    let tx = build_tx(
        outpoint,
        redeem_script,
        vec![TxOutput {
            value: burn_amount,
            script: build_commitment_script(pubkey.array(), &payload_hash),
        }],
    );

    // Sign address metadata
    let signed_metadata = cashweb_payload::proto::SignedPayload {
        pubkey: pubkey.array().to_vec(),
        sig: ecc.sign(seckey, payload_hash.byte_array().clone()).to_vec(),
        sig_scheme: SignatureScheme::Ecdsa.into(),
        payload: address_metadata.encode_to_vec(),
        payload_hash: payload_hash.as_slice().to_vec(),
        burn_amount,
        burn_txs: vec![cashweb_payload::proto::BurnTx {
            tx: tx.ser().to_vec(),
            burn_idx: 0,
        }],
    };

    (signed_metadata, tx)
}
