use std::{ffi::OsString, time::Duration};

use bitcoinsuite_bitcoind::instance::{BitcoindChain, BitcoindConf};
use bitcoinsuite_core::{ecc::Ecc, Hashed, LotusAddress, Net, Network, Script, ShaRmd160};
use bitcoinsuite_ecc_secp256k1::EccSecp256k1;
use bitcoinsuite_error::Result;
use bitcoinsuite_test_utils::bin_folder;
use bitcoinsuite_test_utils_blockchain::setup_bitcoind_coins;
use cashweb_registry::{
    p2p::{peer::Peer, peers::InitialMetadataDownloadParams},
    proto,
    test_instance::{build_signed_metadata, RegistryTestInstance},
};
use rand::SeedableRng;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_imd() -> Result<()> {
    let _ = bitcoinsuite_error::install();

    let num_instances = 4;
    let mut instances = Vec::<RegistryTestInstance>::new();
    let mut tempdirs = Vec::<tempdir::TempDir>::new();

    // Spin up a few Registry servers.
    for i in 0..num_instances {
        let tempdir = tempdir::TempDir::new(&format!("cashweb-registry--imd-{}", i))?;

        let mut additional_args = vec![OsString::from("-txindex")];
        let mut peers = Vec::new();
        for instance in &instances {
            additional_args
                .push(format!("-addnode=127.0.0.1:{}", instance.bitcoind.p2p_port()).into());
        }
        // The last instance is connected to all previous ones
        if i == num_instances - 1 {
            for instance in &instances {
                peers.push(Peer::new(instance.url.parse()?));
            }
        }
        let conf =
            BitcoindConf::from_chain_regtest(bin_folder(), BitcoindChain::XPI, additional_args)?;

        let instance = RegistryTestInstance::setup(tempdir.path(), conf, peers).await?;
        instances.push(instance);
        tempdirs.push(tempdir);
    }

    for instance in &mut instances {
        instance.wait_for_ready().await?;
    }

    // Generate a few anyone can spend coins
    let anyone_script = Script::from_slice(&[0x51]);
    let anyone_address = LotusAddress::new(
        "lotus",
        Net::Regtest,
        Script::p2sh(&ShaRmd160::digest(anyone_script.bytecode().clone())),
    );
    let mut utxos = setup_bitcoind_coins(
        instances[0].bitcoind.cli(),
        Network::XPI,
        111,
        anyone_address.as_str(),
        &anyone_address.script().hex(),
    )?;
    let last_block_hash = instances[0]
        .bitcoind
        .cli()
        .cmd_string("getbestblockhash", &[])?;

    // Wait for all instances to have received the generated coins.
    let mut attempt = 0;
    while instances.iter().any(|instance| {
        instance
            .bitcoind
            .cmd_string("getblock", &[&last_block_hash])
            .is_err()
    }) {
        attempt += 1;
        if attempt > 150 {
            panic!("Failed to broadcast blocks");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mut metadata_vec = Vec::new();
    for address_idx in 1..=11 {
        // Make new p2pkh address
        let ecc = EccSecp256k1::default();
        let seckey = ecc.seckey_from_array([address_idx; 32])?;
        let pubkey = ecc.derive_pubkey(&seckey);
        let pkh = ShaRmd160::digest(pubkey.array().into());
        let address = LotusAddress::new("lotus", Net::Regtest, Script::p2pkh(&pkh));

        for (instance_idx, instance) in instances.iter().enumerate().take(num_instances - 1) {
            // Build valid address metadata
            let address_metadata = proto::AddressMetadata {
                timestamp: 1000 + instance_idx as i64,
                ttl: 10,
                entries: vec![],
            };

            let (signed_metadata, _) = build_signed_metadata(
                &seckey,
                pubkey,
                &ecc,
                &mut utxos,
                &anyone_script,
                address_metadata,
            );

            instance
                .registry
                .put_metadata(&address, &signed_metadata)
                .await?;

            if instance_idx == num_instances - 2 {
                metadata_vec.push((address.clone(), signed_metadata));
            }
        }
    }

    // This seed will select peer 0 and peer 1 in the first round
    // and peer 0 and peer 2 in the second round.
    // ROUND 1:
    // - Put the data from peer 1 into the db (has timestamp 1001)
    // - Ignore the data from peer 0 (has timestamp 1000)
    // ROUND 2:
    // - Update db using data from peer 2 (has timestamp 1002)
    // - Ignore the data from peer 0 (has timestmp 1000)
    // ROUND 3:
    // - Both peers return no entries, indicating that the IMD is finished

    // TODO: Currently untested are the different failure modes
    let mut rng = rand::rngs::StdRng::from_seed([11; 32]);
    let imd_params = InitialMetadataDownloadParams {
        registry: &instances[num_instances - 1].registry,
        num_sampled_peers: 2,
        timeout_peer: Duration::from_secs(1),
        num_failed_for_wait: 1,
        fail_wait_duration: Duration::from_secs(1),
    };

    let test_instance = &instances[num_instances - 1];
    test_instance
        .peers
        .initial_metadata_download(&mut rng, &imd_params)
        .await?;

    for (address, signed_metadata) in &metadata_vec {
        let payload = test_instance.registry.get_metadata(address)?.unwrap();
        assert_eq!(&payload.to_proto(), signed_metadata);
    }

    for instance in &mut instances {
        instance.bitcoind.cleanup()?;
    }

    Ok(())
}
