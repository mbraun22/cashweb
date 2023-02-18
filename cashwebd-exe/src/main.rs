use std::{io::Read, sync::Arc, time::Duration};

use bitcoinsuite_bitcoind::rpc_client::BitcoindRpcClient;
use bitcoinsuite_core::Net;
use bitcoinsuite_error::{Result, WrapErr};
use cashweb_config::parse_conf;
use cashweb_registry::{
    http::server::RegistryServer,
    p2p::{
        peer::Peer,
        peers::{InitialMetadataDownloadParams, Peers},
    },
    registry::Registry,
    store::db::Db,
};
use thiserror::Error;
use tracing::info;
use tracing_subscriber::fmt;

#[derive(Error, Debug)]
pub enum CashwebdExeError {
    #[error("No configuration file provided. Specify like this: cargo run -- <config path>")]
    NoConfigFile,

    #[error("Opening configuration file {0} failed")]
    OpenConfigFail(String),

    #[error("Failed to read configuration file {0}")]
    ReadConfigFail(String),

    #[error("Invalid configuration file {0}")]
    InvalidConfigFail(String),
}

use self::CashwebdExeError::*;

#[tokio::main]
async fn main() -> Result<()> {
    let format = fmt::format()
        .with_level(true) // don't include levels in formatted output
        .with_target(false) // don't include targets
        .compact(); // use the `Compact` formatting style.

    tracing_subscriber::fmt().event_format(format).init();
    bitcoinsuite_error::install()?;

    let conf_path = std::env::args().nth(1).ok_or(NoConfigFile)?;
    let mut file =
        std::fs::File::open(&conf_path).wrap_err_with(|| OpenConfigFail(conf_path.clone()))?;
    let mut conf_contents = String::new();
    file.read_to_string(&mut conf_contents)
        .wrap_err_with(|| ReadConfigFail(conf_path.clone()))?;
    let conf = parse_conf(&conf_contents).wrap_err_with(|| InvalidConfigFail(conf_path.clone()))?;

    let db = Db::open(&conf.registry.db_path)?;
    let bitcoind = BitcoindRpcClient::new(conf.bitcoin_rpc);

    let registry = Arc::new(Registry::new(db, bitcoind, Net::Regtest));
    let our_peers = conf
        .registry
        .peers
        .into_iter()
        .map(Peer::new)
        .collect::<Vec<_>>();
    let peers = Arc::new(Peers::new(conf.url.to_string(), our_peers));

    let imd_params = InitialMetadataDownloadParams {
        registry: &registry,
        num_sampled_peers: conf.registry.imd.num_sampled_peers,
        timeout_peer: Duration::from_millis(conf.registry.imd.timeout_peer_ms),
        num_failed_for_wait: conf.registry.imd.num_failed_for_wait,
        fail_wait_duration: Duration::from_secs(conf.registry.imd.fail_wait_duration_s),
    };
    let mut rng = rand::thread_rng();
    peers
        .initial_metadata_download(&mut rng, &imd_params)
        .await?;

    let server = RegistryServer {
        registry: Arc::clone(&registry),
        peers: Arc::clone(&peers),
    };

    let router = server.into_router();
    info!("Listening on {}", conf.host);
    axum::Server::bind(&conf.host)
        .serve(router.into_make_service())
        .await?;

    Ok(())
}
