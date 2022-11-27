use std::{ffi::OsString, time::Duration};

use bitcoinsuite_bitcoind::instance::{BitcoindChain, BitcoindConf};
use bitcoinsuite_core::{
    ecc::Ecc, lotus_txid, Hashed, LotusAddress, Net, Network, Script, ShaRmd160,
};
use bitcoinsuite_ecc_secp256k1::EccSecp256k1;
use bitcoinsuite_error::Result;
use bitcoinsuite_test_utils::bin_folder;
use bitcoinsuite_test_utils_blockchain::setup_bitcoind_coins;
use cashweb_http_utils::protobuf::CONTENT_TYPE_PROTOBUF;
use cashweb_registry::{
    p2p::peer::Peer,
    proto,
    test_instance::{build_signed_metadata, RegistryTestInstance},
};
use prost::Message;
use reqwest::{
    header::{CONTENT_TYPE, ORIGIN},
    StatusCode,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_p2p() -> Result<()> {
    let _ = bitcoinsuite_error::install();

    let num_instances = 3;
    let mut instances = Vec::<RegistryTestInstance>::new();
    let mut tempdirs = Vec::<tempdir::TempDir>::new();

    // Spin up a few Registry servers.
    for i in 0..num_instances {
        let tempdir = tempdir::TempDir::new(&format!("cashweb-registry--registry-{}", i))?;

        let mut additional_args = vec![OsString::from("-txindex")];
        let mut peers = Vec::new();
        for instance in &instances {
            additional_args
                .push(format!("-addnode=127.0.0.1:{}", instance.bitcoind.p2p_port()).into());
        }
        if let Some(instance) = instances.last() {
            peers.push(Peer::new(instance.url.parse()?));
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
        3,
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
        if attempt > 100 {
            panic!("Failed to broadcast blocks");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Make new p2pkh address
    let ecc = EccSecp256k1::default();
    let seckey = ecc.seckey_from_array([5; 32])?;
    let pubkey = ecc.derive_pubkey(&seckey);
    let pkh = ShaRmd160::digest(pubkey.array().into());
    let address = LotusAddress::new("lotus", Net::Regtest, Script::p2pkh(&pkh));

    // Build valid address metadata
    let (signed_metadata, tx) = build_signed_metadata(
        &seckey,
        pubkey,
        &ecc,
        &mut utxos,
        &anyone_script,
        proto::AddressMetadata {
            timestamp: 1234,
            ttl: 10,
            entries: vec![],
        },
    );

    // Send request to last instance
    let client = reqwest::Client::new();
    let response = client
        .put(format!("{}/metadata/{}", instances[2].url, address))
        .body(signed_metadata.encode_to_vec())
        .header(CONTENT_TYPE, CONTENT_TYPE_PROTOBUF)
        .header(ORIGIN, "http://anywhere.com")
        .send()
        .await?;

    // Check request accepted
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.bytes().await?;
    let broadcast_response = proto::PutSignedPayloadResponse::decode(&mut body)?;
    assert_eq!(
        broadcast_response,
        proto::PutSignedPayloadResponse {
            txid: vec![lotus_txid(&tx).as_slice().to_vec()],
        },
    );

    // Wait for metadata to be relayed to middle instance
    let mut attempt = 0i32;
    loop {
        let state = instances[2].peers.peers[0].state.lock().await;
        if state.last_status.is_some() {
            assert_eq!(state.last_status, Some(StatusCode::OK));
            break;
        }
        std::mem::drop(state);
        attempt += 1;
        if attempt > 100 {
            panic!("Failed to broadcast metadata");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Query middle instance about the metadata
    let response = client
        .get(format!("{}/metadata/{}", instances[1].url, address))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.bytes().await?;
    let signed_payload = cashweb_payload::proto::SignedPayload::decode(&mut body)?;
    assert_eq!(signed_payload, signed_metadata);

    // Wait for metadata to be relayed to the first instance
    let mut attempt = 0i32;
    loop {
        let state = instances[1].peers.peers[0].state.lock().await;
        if state.last_status.is_some() {
            assert_eq!(state.last_status, Some(StatusCode::OK));
            break;
        }
        std::mem::drop(state);
        attempt += 1;
        if attempt > 100 {
            panic!("Failed to broadcast metadata");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Query first instance
    let response = client
        .get(format!("{}/metadata/{}", instances[0].url, address))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.bytes().await?;
    let signed_payload = cashweb_payload::proto::SignedPayload::decode(&mut body)?;
    assert_eq!(signed_payload, signed_metadata);

    Ok(())
}
