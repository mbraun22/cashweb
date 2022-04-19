use std::ffi::OsString;

use bitcoinsuite_bitcoind::instance::{BitcoindChain, BitcoindConf};
use bitcoinsuite_core::{
    ecc::Ecc, lotus_txid, BitcoinCode, Hashed, LotusAddress, Net, Network, P2PKHSignatory, Script,
    SequenceNo, Sha256, ShaRmd160, SigHashType, SignData, SignField, TxBuilder, TxBuilderInput,
    TxBuilderOutput, TxInput, TxOutput,
};
use bitcoinsuite_ecc_secp256k1::EccSecp256k1;
use bitcoinsuite_error::Result;
use bitcoinsuite_test_utils::bin_folder;
use bitcoinsuite_test_utils_blockchain::setup_bitcoind_coins;
use cashweb_http_utils::protobuf::CONTENT_TYPE_PROTOBUF;
use cashweb_payload::{payload::SignatureScheme, verify::build_commitment_script};
use cashweb_registry::{proto, test_instance::RegistryTestInstance};
use pretty_assertions::assert_eq;
use prost::Message;
use reqwest::{
    header::{CONTENT_TYPE, ORIGIN},
    StatusCode,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_registry_http() -> Result<()> {
    let _ = bitcoinsuite_error::install();
    let tempdir = tempdir::TempDir::new("cashweb-registry--registry")?;

    let conf = BitcoindConf::from_chain_regtest(
        bin_folder(),
        BitcoindChain::XPI,
        vec![OsString::from("-txindex")],
    )?;

    let mut instance = RegistryTestInstance::setup(tempdir.path(), conf, vec![]).await?;
    instance.wait_for_ready().await?;
    let url = instance.url.clone();

    let client = reqwest::Client::new();

    let ecc = EccSecp256k1::default();
    let seckey = ecc.seckey_from_array([5; 32])?;
    let pubkey = ecc.derive_pubkey(&seckey);
    let pkh = ShaRmd160::digest(pubkey.array().into());
    let address = LotusAddress::new("lotus", Net::Regtest, Script::p2pkh(&pkh));

    let mut utxos = setup_bitcoind_coins(
        instance.bitcoind.cli(),
        Network::XPI,
        3,
        address.as_str(),
        &address.script().hex(),
    )?;

    // Invalid address
    let response = client.get(format!("{}/metadata/A", url)).send().await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    check_proto_error(
        response,
        "invalid-address",
        "Invalid lotus address: Missing prefix",
        true,
    )
    .await?;

    // Expected "lotus" address prefix
    let response = client
        .get(format!(
            "{}/metadata/fooR16PSJNf1EDEfGvaYzaXJCJZrXH4pgiTo7kyVbTkkA",
            url
        ))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    check_proto_error(
        response,
        "invalid-address-prefix",
        "Invalid address prefix, expected \"lotus\" but got \"foo\"",
        true,
    )
    .await?;

    // Expected regtest, got mainnet address
    let response = client
        .get(format!(
            "{}/metadata/lotus_16PSJNf1EDEfGvaYzaXJCJZrXH4pgiTo7kyW61iGi",
            url
        ))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    check_proto_error(
        response,
        "invalid-address-net",
        "Invalid address net, expected Regtest but got Mainnet",
        true,
    )
    .await?;

    // Expected P2PKH, got P2SH
    let response = client
        .get(format!(
            "{}/metadata/lotusR1PrQReKdmXH6hyCk4NFR398HeWxvJWW4Hie3rA",
            url
        ))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    check_proto_error(
        response,
        "unsupported-script-variant",
        "Unsupported address script variant: P2SH(ShaRmd160(6a669cafca7fa9ab24ce712f10c968f6eb170626))",
        false,
    ).await?;

    // Metadata not found for that address (yet)
    let response = client
        .get(format!("{}/metadata/{}", url, address))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    check_proto_error(
        response,
        "address-metadata-not-found",
        "Not found: No address metadata for lotusR16PSJMw2kpXdpk9Kn7qX6cYA7MbLg23bfTtXL7zeQ in registry",
        true,
    ).await?;

    // Build valid request
    let address_metadata = proto::AddressMetadata {
        timestamp: 1234,
        ttl: 10,
        entries: vec![],
    };
    let payload_hash = Sha256::digest(address_metadata.encode_to_vec().into());

    let (outpoint, value) = utxos.pop().unwrap();
    let burn_amount = 10_000;
    let tx_builder = TxBuilder {
        version: 1,
        inputs: vec![TxBuilderInput::new(
            TxInput {
                prev_out: outpoint,
                script: Script::default(),
                sequence: SequenceNo::finalized(),
                sign_data: Some(SignData::new(vec![
                    SignField::OutputScript(address.script().clone()),
                    SignField::Value(value),
                ])),
            },
            Box::new(P2PKHSignatory {
                seckey: seckey.clone(),
                pubkey,
                sig_hash_type: SigHashType::ALL_BIP143,
            }),
        )],
        outputs: vec![
            TxBuilderOutput::Leftover(address.script().clone()),
            TxBuilderOutput::Fixed(TxOutput {
                value: burn_amount,
                script: build_commitment_script(pubkey.array(), &payload_hash),
            }),
        ],
        lock_time: 0,
    };
    let tx = tx_builder.sign(&ecc, 1000, 546)?;
    let mut signed_metadata = cashweb_payload::proto::SignedPayload {
        pubkey: pubkey.array().to_vec(),
        sig: vec![], // invalid sig
        sig_scheme: SignatureScheme::Ecdsa.into(),
        payload: address_metadata.encode_to_vec(),
        payload_hash: vec![],
        burn_amount: 0,
        burn_txs: vec![cashweb_payload::proto::BurnTx {
            tx: tx.ser().to_vec(),
            burn_idx: 1,
        }],
    };

    // Missing Content-Type (should be application/x-protobuf).
    let response = client
        .put(format!("{}/metadata/{}", url, address))
        .body(signed_metadata.encode_to_vec())
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    check_proto_error(
        response,
        "no-content-type-set",
        "No Content-Type set",
        false,
    )
    .await?;

    // Missing 'Origin' header
    let response = client
        .put(format!("{}/metadata/{}", url, address))
        .body(signed_metadata.encode_to_vec())
        .header(CONTENT_TYPE, CONTENT_TYPE_PROTOBUF)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    check_proto_error(response, "missing-origin", "'Origin' header missing", false).await?;

    // Invalid ECDSA signature: sig is empty
    let response = client
        .put(format!("{}/metadata/{}", url, address))
        .body(signed_metadata.encode_to_vec())
        .header(CONTENT_TYPE, CONTENT_TYPE_PROTOBUF)
        .header(ORIGIN, "http://localhost")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    check_proto_error(
        response,
        "invalid-ecdsa-signature",
        "Invalid payload ECDSA signature: Invalid signature format",
        false,
    )
    .await?;

    // Add valid response
    signed_metadata.sig = ecc
        .sign(&seckey, payload_hash.byte_array().clone())
        .to_vec();

    // Now request succeeds
    let response = client
        .put(format!("{}/metadata/{}", url, address))
        .body(signed_metadata.encode_to_vec())
        .header(CONTENT_TYPE, CONTENT_TYPE_PROTOBUF)
        .header(ORIGIN, "http://localhost")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.bytes().await?;
    let broadcast_response = proto::PutAddressMetadataResponse::decode(&mut body)?;
    assert_eq!(
        broadcast_response,
        proto::PutAddressMetadataResponse {
            txid: vec![lotus_txid(&tx).as_slice().to_vec()],
        },
    );

    // Query metadata
    let response = client
        .get(format!("{}/metadata/{}", url, address))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.bytes().await?;
    let signed_payload = cashweb_payload::proto::SignedPayload::decode(&mut body)?;
    signed_metadata.burn_amount = burn_amount;
    signed_metadata.payload_hash = payload_hash.as_slice().to_vec();
    assert_eq!(signed_payload, signed_metadata);

    // PUT again works
    let response = client
        .put(format!("{}/metadata/{}", url, address))
        .body(signed_metadata.encode_to_vec())
        .header(CONTENT_TYPE, CONTENT_TYPE_PROTOBUF)
        .header(ORIGIN, "http://localhost")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.bytes().await?;
    let broadcast_response = proto::PutAddressMetadataResponse::decode(&mut body)?;
    assert_eq!(
        broadcast_response,
        proto::PutAddressMetadataResponse {
            txid: vec![lotus_txid(&tx).as_slice().to_vec()],
        },
    );

    instance.cleanup()?;

    Ok(())
}

async fn check_proto_error(
    response: reqwest::Response,
    error_code: &str,
    msg: &str,
    is_user_error: bool,
) -> Result<()> {
    assert_eq!(response.headers()[CONTENT_TYPE], CONTENT_TYPE_PROTOBUF);
    let mut body = response.bytes().await?;
    let actual_error = cashweb_http_utils::proto::Error::decode(&mut body)?;
    let expected_error = cashweb_http_utils::proto::Error {
        error_code: error_code.to_string(),
        msg: msg.to_string(),
        is_user_error,
    };
    assert_eq!(actual_error, expected_error);
    Ok(())
}
