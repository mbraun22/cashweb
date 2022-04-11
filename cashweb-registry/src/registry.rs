//! Module containing [`Registry`].

use bitcoinsuite_bitcoind::rpc_client::BitcoindRpcClient;
use bitcoinsuite_core::{Hashed, Sha256d};
use bitcoinsuite_ecc_secp256k1::EccSecp256k1;
use bitcoinsuite_error::{ErrorMeta, Result, WrapErr};
use cashweb_payload::payload::SignedPayload;
use thiserror::Error;

use crate::{
    proto,
    store::{db::Db, pubkeyhash::PubKeyHash},
};

/// Cashweb [`Registry`] stores [`SignedPayload`]s containing [`proto::AddressMetadata`] for
/// addresses.
#[derive(Debug)]
pub struct Registry {
    /// Database storing the address metadata in RocksDB.
    db: Db,
    /// Ecc for verifying secp256k1 signatures.
    ecc: EccSecp256k1,
    /// RPC to a bitcoind instance for testing and broadcasting txs.
    bitcoind: BitcoindRpcClient,
}

/// Errors indicating some registry error.
#[derive(Debug, Error, ErrorMeta, PartialEq)]
pub enum RegistryError {
    /// Hash of `pubkey` of [`SignedPayload`] doesn't match provided [`PubKeyHash`].
    #[invalid_client_input()]
    #[error(
        "Hash of public key of SignedPayload doesn't match provided public key hash \
         Expected {expected:?}, but got {actual:?}"
    )]
    PubKeyHashMismatch {
        /// Expected pubkey hash of the address.
        expected: PubKeyHash,
        /// Actual hash of the provided pubkey.
        actual: PubKeyHash,
    },

    /// Bitcoind rejected the provided burn tx.
    #[invalid_user_input()]
    #[error("Bitcoind rejected tx: {0}")]
    BitcoindRejectedTx(String),

    /// Database contains an invalid protobuf MetadataEntry.
    #[critical()]
    #[error("Inconsistent db: Invalid SignedPayload in DB")]
    InvalidSignedPayloadInDb,
}

use self::RegistryError::*;

impl Registry {
    /// Construct new [`Registry`]
    pub fn new(db: Db, bitcoind: BitcoindRpcClient) -> Self {
        Registry {
            db,
            ecc: EccSecp256k1::default(),
            bitcoind,
        }
    }

    /// Read a signed [`proto::AddressMetadata`] entry from the database.
    /// [`None`] if no such entry exists.
    pub fn get_metadata(
        &self,
        pkh: &PubKeyHash,
    ) -> Result<Option<SignedPayload<proto::AddressMetadata>>> {
        let signed_payload = match self.db.metadata().get(pkh)? {
            Some(signed_payload) => signed_payload,
            None => return Ok(None),
        };
        let signed_payload =
            SignedPayload::from_proto(signed_payload).wrap_err(InvalidSignedPayloadInDb)?;
        Ok(Some(signed_payload))
    }
}

impl Registry {
    /// Fully verify and write a [`cashweb_payload::proto::SignedPayload`](SignedPayload) into the
    /// database.
    pub async fn put_metadata(
        &self,
        pkh: &PubKeyHash,
        signed_metadata: cashweb_payload::proto::SignedPayload,
    ) -> Result<Vec<Sha256d>> {
        // Decode SignedPayload
        let signed_metadata = SignedPayload::<proto::AddressMetadata>::from_proto(signed_metadata)?;

        // Check pubkey hash
        let actual_pkh = pkh.algorithm().hash_pubkey(*signed_metadata.pubkey());
        if *pkh != actual_pkh {
            return Err(PubKeyHashMismatch {
                expected: pkh.clone(),
                actual: actual_pkh,
            }
            .into());
        }

        // Verify burn amount and signatures check out
        signed_metadata.verify(&self.ecc)?;

        // Verify txs are valid on the network
        for burn_tx in signed_metadata.txs() {
            if let Err(msg) = self
                .bitcoind
                .test_mempool_accept(burn_tx.tx().raw())
                .await?
            {
                return Err(RegistryError::BitcoindRejectedTx(msg).into());
            }
        }

        // Broadcast txs onto the network
        let mut txids = Vec::with_capacity(signed_metadata.txs().len());
        for burn_tx in signed_metadata.txs() {
            let txid_hex = self
                .bitcoind
                .cmd_text("sendrawtransaction", &[burn_tx.tx().raw().hex().into()])
                .await?;
            txids.push(Sha256d::from_hex_be(&txid_hex)?);
        }

        // Write new metadata into the database
        self.db.metadata().put(pkh, &signed_metadata.to_proto())?;
        Ok(txids)
    }
}

#[cfg(test)]
mod tests {
    use bitcoinsuite_bitcoind::instance::{BitcoindChain, BitcoindConf, BitcoindInstance};
    use bitcoinsuite_core::{
        ecc::{Ecc, VerifySignatureError},
        lotus_txid, AddressType, BitcoinCode, CashAddress, Hashed, Network, P2PKHSignatory, Script,
        SequenceNo, Sha256, ShaRmd160, SigHashType, SignData, SignField, TxBuilder, TxBuilderInput,
        TxBuilderOutput, TxInput, TxOutput, UnhashedTx, BCHREG,
    };
    use bitcoinsuite_ecc_secp256k1::EccSecp256k1;
    use bitcoinsuite_error::Result;
    use bitcoinsuite_test_utils::bin_folder;
    use bitcoinsuite_test_utils_blockchain::setup_bitcoind_coins;
    use cashweb_payload::{
        payload::{ParseSignedPayloadError, SignatureScheme, SignedPayload},
        verify::{build_commitment_script, ValidateSignedPayloadError},
    };
    use pretty_assertions::assert_eq;
    use prost::Message;

    use crate::{
        proto,
        registry::{Registry, RegistryError},
        store::{
            db::Db,
            pubkeyhash::{PkhAlgorithm, PubKeyHash},
        },
    };

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_registry_metadata() -> Result<()> {
        let _ = bitcoinsuite_error::install();
        let tempdir = tempdir::TempDir::new("cashweb-registry--registry")?;
        let db = Db::open(tempdir.path().join("db.rocksdb"))?;

        let conf = BitcoindConf::from_chain_regtest(bin_folder(), BitcoindChain::XPI, vec![])?;
        let mut instance = BitcoindInstance::setup(conf)?;
        instance.wait_for_ready()?;
        let bitcoind = instance.rpc_client();

        let registry = Registry {
            db,
            ecc: EccSecp256k1::default(),
            bitcoind: bitcoind.clone(),
        };

        let seckey = registry.ecc.seckey_from_array([4; 32])?;
        let pubkey = registry.ecc.derive_pubkey(&seckey);
        let pkh = PkhAlgorithm::Sha256Ripemd160.hash_pubkey(pubkey.array());

        let address = CashAddress::from_hash(
            BCHREG,
            AddressType::P2PKH,
            ShaRmd160::digest(pubkey.array().into()),
        );
        let mut utxos = setup_bitcoind_coins(
            instance.cli(),
            Network::XPI,
            3,
            address.as_str(),
            &address.to_script().hex(),
        )?;

        // DB empty; querying for a PKH returns None
        assert_eq!(registry.get_metadata(&pkh)?, None);

        // Tx parses, but the output burn_index points to doesn't exist
        let address_metadata = proto::AddressMetadata {
            timestamp: 1234,
            ttl: 10,
            entries: vec![],
        };
        let payload_hash = Sha256::digest(address_metadata.encode_to_vec().into());
        let mut tx = UnhashedTx {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput {
                value: 1_000_000,
                script: build_commitment_script(pubkey.array(), &payload_hash),
            }],
            lock_time: 0,
        };
        let mut signed_metadata = cashweb_payload::proto::SignedPayload {
            pubkey: pubkey.array().to_vec(),
            sig: vec![], // invalid sig
            sig_scheme: SignatureScheme::Ecdsa.into(),
            payload: vec![77, 88, 99], // invalid payload
            payload_hash: vec![],
            burn_amount: 1_000_000,
            burn_txs: vec![cashweb_payload::proto::BurnTx {
                tx: tx.ser().to_vec(),
                burn_idx: 0,
            }],
        };

        // Invalid protobuf (checked in SignedPayload::from_proto)
        let err = registry
            .put_metadata(&pkh, signed_metadata.clone())
            .await
            .unwrap_err()
            .downcast::<ParseSignedPayloadError>()?;
        assert_eq!(
            err,
            ParseSignedPayloadError::ParsingPayloadFailed(prost::DecodeError::new(
                "buffer underflow"
            )),
        );

        // Wrong pubkeyhash
        signed_metadata.payload = address_metadata.encode_to_vec();
        let wrong_pkh = PubKeyHash::new(PkhAlgorithm::Sha256Ripemd160, [4; 20].into())?;
        let err = registry
            .put_metadata(&wrong_pkh, signed_metadata.clone())
            .await
            .unwrap_err()
            .downcast::<RegistryError>()?;
        assert_eq!(
            err,
            RegistryError::PubKeyHashMismatch {
                expected: wrong_pkh,
                actual: pkh.clone(),
            },
        );

        // Invalid signature (checked in SignedPayload::verify)
        let err = registry
            .put_metadata(&pkh, signed_metadata.clone())
            .await
            .unwrap_err()
            .downcast::<ValidateSignedPayloadError>()?;
        assert_eq!(
            err,
            ValidateSignedPayloadError::InvalidEcdsaSignature(VerifySignatureError::InvalidFormat),
        );

        // Valid signature, but failed to broadcast tx
        signed_metadata.sig = registry
            .ecc
            .sign(&seckey, payload_hash.byte_array().clone())
            .to_vec();
        let err = registry
            .put_metadata(&pkh, signed_metadata.clone())
            .await
            .unwrap_err()
            .downcast::<RegistryError>()?;
        assert_eq!(
            err,
            RegistryError::BitcoindRejectedTx("bad-txns-vin-empty".to_string()),
        );

        // Add valid input to tx
        let (outpoint, value) = utxos.pop().unwrap();
        let burn_amount = value - 10_000;
        tx.outputs[0].value = burn_amount;
        let mut tx_builder = TxBuilder::from_tx(tx);
        tx_builder.inputs.push(TxBuilderInput::new(
            TxInput {
                prev_out: outpoint,
                script: Script::default(),
                sequence: SequenceNo::finalized(),
                sign_data: Some(SignData::new(vec![
                    SignField::OutputScript(address.to_script()),
                    SignField::Value(value),
                ])),
            },
            Box::new(P2PKHSignatory {
                seckey: seckey.clone(),
                pubkey,
                sig_hash_type: SigHashType::ALL_BIP143,
            }),
        ));
        let tx = tx_builder.sign(&registry.ecc, 1000, 546)?;
        signed_metadata.burn_txs[0].tx = tx.ser().to_vec();
        signed_metadata.burn_amount = burn_amount;

        // Now, putting the metadata succeeds
        let txids = registry.put_metadata(&pkh, signed_metadata.clone()).await?;
        assert_eq!(txids, vec![lotus_txid(&tx)]);

        let signed_payload = registry.get_metadata(&pkh)?;
        assert_eq!(
            signed_payload,
            Some(SignedPayload::from_proto(signed_metadata.clone())?),
        );

        // Override address metadata with new SignedPayload
        let mut address_metadata = address_metadata.clone();
        let mut signed_metadata2 = signed_metadata.clone();
        address_metadata.timestamp = 5555;

        signed_metadata2.payload = address_metadata.encode_to_vec();
        let payload_hash = Sha256::digest(signed_metadata2.payload.clone().into());
        signed_metadata2.payload_hash = payload_hash.as_slice().to_vec();
        signed_metadata2.sig = registry
            .ecc
            .sign(&seckey, payload_hash.byte_array().clone())
            .to_vec();

        let (outpoint, value) = utxos.pop().unwrap();
        let burn_amount = value - 11_000;
        let tx_builder = TxBuilder {
            version: 1,
            inputs: vec![TxBuilderInput::new(
                TxInput {
                    prev_out: outpoint,
                    script: Script::default(),
                    sequence: SequenceNo::finalized(),
                    sign_data: Some(SignData::new(vec![
                        SignField::OutputScript(address.to_script()),
                        SignField::Value(value),
                    ])),
                },
                Box::new(P2PKHSignatory {
                    seckey,
                    pubkey,
                    sig_hash_type: SigHashType::ALL_BIP143,
                }),
            )],
            outputs: vec![
                TxBuilderOutput::Leftover(address.to_script()),
                TxBuilderOutput::Fixed(TxOutput {
                    value: burn_amount,
                    script: build_commitment_script(pubkey.array(), &payload_hash),
                }),
            ],
            lock_time: 0,
        };
        signed_metadata2.burn_amount = burn_amount;
        let tx2 = tx_builder.sign(&registry.ecc, 1000, 546)?;
        signed_metadata2.burn_txs[0].tx = tx2.ser().to_vec();
        signed_metadata2.burn_txs[0].burn_idx = 1;

        let txids = registry
            .put_metadata(&pkh, signed_metadata2.clone())
            .await?;
        assert_eq!(txids, vec![lotus_txid(&tx2)]);

        let signed_payload2 = registry.get_metadata(&pkh)?;
        assert_ne!(signed_payload2, signed_payload);
        assert_eq!(
            signed_payload2,
            Some(SignedPayload::from_proto(signed_metadata2)?)
        );

        Ok(())
    }
}
