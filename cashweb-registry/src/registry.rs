//! Module containing [`Registry`].

use bitcoinsuite_bitcoind::{rpc_client::BitcoindRpcClient, BitcoindError};
use bitcoinsuite_core::{lotus_txid, Hashed, LotusAddress, Net, Sha256d};
use bitcoinsuite_ecc_secp256k1::EccSecp256k1;
use bitcoinsuite_error::{ErrorMeta, Result};
use cashweb_payload::{
    payload::{BurnTx, SignedPayload},
    verify::ADDRESS_METADATA_LOKAD_ID,
};
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
    /// Whether server is running on a mainnet or regtest network.
    net: Net,
}

/// Result of putting metadata into the registry.
#[derive(Debug, Clone, PartialEq)]
pub struct PutMetadataResult {
    /// Transaction IDs of the burn txs for this payload.
    pub txids: Vec<Sha256d>,
    /// Which action happened with the blockchain.
    pub blockchain_action: PutBlockchainAction,
    /// Parsed signed payload.
    pub signed_metadata: SignedPayload<proto::AddressMetadata>,
}

/// Result of fetching a range of metadata by timestamp.
#[derive(Debug, Clone, PartialEq)]
pub struct GetMetadataRangeResult {
    /// Pairs of pubkey hashes and associated payload, ordered by timestamp.
    pub entries: Vec<(LotusAddress, SignedPayload<proto::AddressMetadata>)>,
}

/// Which action happened with the blockchain when putting address metadata.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PutBlockchainAction {
    /// Signed payload hash was already the current one in the database.
    /// Burn transactions were not validated.
    AlreadyKnowPayloadHash,
    /// Signed payload new, but txs already seen on the blockchain.
    /// Tx broadcast is skipped, but malleation is checked.
    AlreadyKnowTx,
    /// Txs not seen on the network yet, but between testmempoolaccept and sendrawtransaction,
    /// a block was found, which would make sendrawtransaction fail.
    BroadcastRaceCondition,
    /// Txs not seen on the network yet, and we were able to broadcast them successfully.
    Broadcast,
}

#[derive(Debug, PartialEq, Eq)]
enum BurnTxValidation {
    Known,
    NotYetBroadcast,
}

/// Errors indicating some registry error.
#[derive(Debug, Error, ErrorMeta, Eq, PartialEq)]
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

    /// Timestamps in the address payload must increase monotonically.
    /// Otherwise, attackers could re-submit old SignedPayloads and make them go back in time.
    #[invalid_user_input()]
    #[error("Payload timestamp is not monotonically increasing: {previous} >= {next}")]
    TimestampNotMonotonicallyIncreasing {
        /// Current payload timestamp as recorded in the database.
        previous: i64,
        /// Timestamp of the new payload.
        next: i64,
    },

    /// Bitcoind rejected the provided burn tx.
    #[invalid_user_input()]
    #[error("Bitcoind rejected tx: {0}")]
    BitcoindRejectedTx(String),

    /// Tx malleated.
    #[invalid_user_input()]
    #[error("Malleated tx, expected {expected}, but got {actual}")]
    TxMalleated {
        /// Tx hex as seen by this registry
        expected: String,
        /// Malleated tx hex with different input signatures.
        actual: String,
    },
}

use self::RegistryError::*;

impl Registry {
    /// Construct new [`Registry`]
    pub fn new(db: Db, bitcoind: BitcoindRpcClient, net: Net) -> Self {
        Registry {
            db,
            ecc: EccSecp256k1::default(),
            bitcoind,
            net,
        }
    }

    /// Read a signed [`proto::AddressMetadata`] entry from the database.
    /// [`None`] if no such entry exists.
    pub fn get_metadata(
        &self,
        address: &LotusAddress,
    ) -> Result<Option<SignedPayload<proto::AddressMetadata>>> {
        let pkh = PubKeyHash::from_address(address, self.net)?;
        self.get_metadata_pkh(&pkh)
    }

    fn get_metadata_pkh(
        &self,
        pkh: &PubKeyHash,
    ) -> Result<Option<SignedPayload<proto::AddressMetadata>>> {
        let signed_payload = match self.db.metadata().get(pkh)? {
            Some(signed_payload) => signed_payload,
            None => return Ok(None),
        };
        Ok(Some(signed_payload))
    }

    /// Fully verify and write a [`cashweb_payload::proto::SignedPayload`](SignedPayload) into the
    /// database.
    pub async fn put_metadata(
        &self,
        address: &LotusAddress,
        signed_metadata: &cashweb_payload::proto::SignedPayload,
    ) -> Result<PutMetadataResult> {
        let pkh = PubKeyHash::from_address(address, self.net)?;

        // Decode SignedPayload
        let signed_metadata =
            SignedPayload::<proto::AddressMetadata>::parse_proto(signed_metadata)?;

        // Check pubkey hash
        let actual_pkh = pkh.algorithm().hash_pubkey(*signed_metadata.pubkey());
        if pkh != actual_pkh {
            return Err(PubKeyHashMismatch {
                expected: pkh.clone(),
                actual: actual_pkh,
            }
            .into());
        }

        // Verify burn amount and signatures check out
        signed_metadata.verify(&self.ecc, ADDRESS_METADATA_LOKAD_ID)?;

        if let Some(existing_metadata) = self.get_metadata_pkh(&pkh)? {
            // If existing payload hash is the same as the new payload hash,
            // we don't need to verify anything.
            if signed_metadata.payload_hash() == existing_metadata.payload_hash() {
                return Ok(PutMetadataResult {
                    txids: signed_metadata
                        .txs()
                        .iter()
                        .map(|tx| lotus_txid(tx.tx().unhashed_tx()))
                        .collect(),
                    blockchain_action: PutBlockchainAction::AlreadyKnowPayloadHash,
                    signed_metadata,
                });
            }
            // Timestamp needs to be ascending.
            if existing_metadata.payload().timestamp >= signed_metadata.payload().timestamp {
                return Err(TimestampNotMonotonicallyIncreasing {
                    previous: existing_metadata.payload().timestamp,
                    next: signed_metadata.payload().timestamp,
                }
                .into());
            }
        }

        let (txids, blockchain_action) = self.validate_burn_txs(signed_metadata.txs()).await?;

        // Write new metadata into the database
        self.db.metadata().put(&pkh, &signed_metadata)?;
        Ok(PutMetadataResult {
            txids,
            blockchain_action,
            signed_metadata,
        })
    }

    async fn validate_burn_txs(
        &self,
        burn_txs: &[BurnTx],
    ) -> Result<(Vec<Sha256d>, PutBlockchainAction)> {
        // Verify txs are valid on the network
        let mut validations = Vec::with_capacity(burn_txs.len());
        for burn_tx in burn_txs {
            validations.push(self.validate_burn_tx(burn_tx).await?);
        }

        // Broadcast txs onto the network
        let mut txids = Vec::with_capacity(burn_txs.len());
        let mut blockchain_action = PutBlockchainAction::Broadcast;
        for (burn_tx, validation) in burn_txs.iter().zip(validations) {
            if validation == BurnTxValidation::Known {
                txids.push(lotus_txid(burn_tx.tx().unhashed_tx()));
                if blockchain_action == PutBlockchainAction::Broadcast {
                    blockchain_action = PutBlockchainAction::AlreadyKnowTx;
                }
                continue;
            }
            let broadcast_result = self
                .bitcoind
                .cmd_text("sendrawtransaction", &[burn_tx.tx().raw().hex().into()])
                .await;
            match broadcast_result {
                Ok(txid_hex) => {
                    txids.push(Sha256d::from_hex_be(&txid_hex)?);
                }
                Err(err) => {
                    // sendrawtransaction failed as there was a block found since the
                    // testmempoolaccept. We handle this gracefully.
                    let err = err.downcast::<BitcoindError>()?;
                    match err {
                        BitcoindError::JsonRpcCode { code: -27, .. } => {
                            txids.push(lotus_txid(burn_tx.tx().unhashed_tx()));
                            blockchain_action = PutBlockchainAction::BroadcastRaceCondition;
                        }
                        err => return Err(err.into()),
                    }
                }
            }
        }

        Ok((txids, blockchain_action))
    }

    async fn validate_burn_tx(&self, burn_tx: &BurnTx) -> Result<BurnTxValidation> {
        let txid = lotus_txid(burn_tx.tx().unhashed_tx());
        match self
            .bitcoind
            .cmd_text("getrawtransaction", &[txid.to_string().into()])
            .await
        {
            // Found txid
            Ok(tx_hex) => {
                let tx_raw = hex::decode(&tx_hex)?;
                if tx_raw != burn_tx.tx().raw().as_ref() {
                    return Err(TxMalleated {
                        expected: tx_hex,
                        actual: burn_tx.tx().raw().hex(),
                    }
                    .into());
                }
                Ok(BurnTxValidation::Known)
            }
            // Txid not found
            Err(err) => {
                let err = err.downcast::<BitcoindError>()?;
                match err {
                    BitcoindError::JsonRpcCode { code: -5, message }
                        if message.starts_with("No such mempool or blockchain transaction.") =>
                    {
                        // Test tx mempool acceptance
                        if let Err(msg) = self
                            .bitcoind
                            .test_mempool_accept(burn_tx.tx().raw())
                            .await?
                        {
                            return Err(RegistryError::BitcoindRejectedTx(msg).into());
                        }
                        Ok(BurnTxValidation::NotYetBroadcast)
                    }
                    err => Err(err.into()),
                }
            }
        }
    }

    /// Get all metadata entries in the given range.
    pub fn get_metadata_range(
        &self,
        start_timestamp: i64,
        end_timestamp: Option<i64>,
        last_address: Option<&LotusAddress>,
        max_num_items: usize,
    ) -> Result<GetMetadataRangeResult> {
        let mut entries = Vec::new();
        let last_pkh = last_address
            .map(|addr| PubKeyHash::from_address(addr, self.net))
            .transpose()?;
        for time_pkh in self.db.metadata().iter_by_time(start_timestamp) {
            if entries.len() == max_num_items {
                break;
            }
            let time_pkh = time_pkh?;
            if let Some(end_timestamp) = end_timestamp {
                if time_pkh.timestamp >= end_timestamp {
                    break;
                }
            }
            if let Some(last_pkh) = &last_pkh {
                // Skip pkhs that we already know for the start timestamp
                if time_pkh.timestamp == start_timestamp
                    && time_pkh.pkh.to_storage_bytes() <= last_pkh.to_storage_bytes()
                {
                    continue;
                }
            }
            let metadata = match self.db.metadata().get(&time_pkh.pkh)? {
                Some(metadata) => metadata,
                None => continue, // ignore stale metadata (should be impossible but doesn't matter)
            };
            if metadata.payload().timestamp != time_pkh.timestamp {
                continue; // ignore stale metadata
            }
            entries.push((time_pkh.pkh.to_address(self.net), metadata));
        }
        Ok(GetMetadataRangeResult { entries })
    }

    pub(crate) fn get_latest_metadata(&self) -> Result<Option<(i64, LotusAddress)>> {
        match self.db.metadata().get_latest()? {
            Some(time_pkh) => {
                let address = time_pkh.pkh.to_address(self.net);
                Ok(Some((time_pkh.timestamp, address)))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn net(&self) -> Net {
        self.net
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use bitcoinsuite_bitcoind::instance::{BitcoindChain, BitcoindConf, BitcoindInstance};
    use bitcoinsuite_core::{
        ecc::{Ecc, VerifySignatureError},
        lotus_txid, BitcoinCode, Hashed, LotusAddress, Net, Network, P2PKHSignatory, Script,
        SequenceNo, Sha256, ShaRmd160, SigHashType, SignData, SignField, TxBuilder, TxBuilderInput,
        TxBuilderOutput, TxInput, TxOutput, UnhashedTx,
    };
    use bitcoinsuite_ecc_secp256k1::EccSecp256k1;
    use bitcoinsuite_error::Result;
    use bitcoinsuite_test_utils::bin_folder;
    use bitcoinsuite_test_utils_blockchain::{build_tx, setup_bitcoind_coins};
    use cashweb_payload::{
        payload::{ParseSignedPayloadError, SignatureScheme, SignedPayload},
        verify::{build_commitment_script, ValidateSignedPayloadError, ADDRESS_METADATA_LOKAD_ID},
    };
    use pretty_assertions::assert_eq;
    use prost::Message;

    use crate::{
        proto,
        registry::{
            GetMetadataRangeResult, PutBlockchainAction, PutMetadataResult, Registry, RegistryError,
        },
        store::{
            db::{Db, CF_PKH_BY_TIME},
            pubkeyhash::{PkhAlgorithm, PubKeyHash, TimePkh},
        },
    };

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_registry_metadata() -> Result<()> {
        let _ = bitcoinsuite_error::install();
        let tempdir = tempdir::TempDir::new("cashweb-registry--registry")?;
        let db = Db::open(tempdir.path().join("db.rocksdb"))?;

        let conf = BitcoindConf::from_chain_regtest(
            bin_folder(),
            BitcoindChain::XPI,
            vec![OsString::from("-txindex")],
        )?;
        let mut instance = BitcoindInstance::setup(conf)?;
        instance.wait_for_ready()?;
        let bitcoind = instance.rpc_client();

        let registry = Registry {
            db,
            ecc: EccSecp256k1::default(),
            bitcoind: bitcoind.clone(),
            net: Net::Regtest,
        };

        let seckey = registry.ecc.seckey_from_array([4; 32])?;
        let pubkey = registry.ecc.derive_pubkey(&seckey);
        let address = LotusAddress::new(
            "lotus",
            Net::Regtest,
            Script::p2pkh(&ShaRmd160::digest(pubkey.array().into())),
        );
        let pkh = PkhAlgorithm::Sha256Ripemd160.hash_pubkey(pubkey.array());

        let mut utxos = setup_bitcoind_coins(
            instance.cli(),
            Network::XPI,
            100,
            address.as_str(),
            &address.script().hex(),
        )?;

        // DB empty; querying for a PKH returns None
        assert_eq!(registry.get_metadata(&address)?, None);

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
                script: build_commitment_script(
                    ADDRESS_METADATA_LOKAD_ID,
                    pubkey.array(),
                    &payload_hash,
                ),
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
            .put_metadata(&address, &signed_metadata)
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
        let wrong_address = LotusAddress::new(
            "lotus",
            Net::Regtest,
            Script::p2pkh(&ShaRmd160::new([4; 20])),
        );
        let err = registry
            .put_metadata(&wrong_address, &signed_metadata)
            .await
            .unwrap_err()
            .downcast::<RegistryError>()?;
        assert_eq!(
            err,
            RegistryError::PubKeyHashMismatch {
                expected: PubKeyHash::from_address(&wrong_address, Net::Regtest)?,
                actual: pkh.clone(),
            },
        );

        // Invalid signature (checked in SignedPayload::verify)
        let err = registry
            .put_metadata(&address, &signed_metadata)
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
            .put_metadata(&address, &signed_metadata)
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
                    SignField::OutputScript(address.script().clone()),
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
        let result = registry.put_metadata(&address, &signed_metadata).await?;
        assert_eq!(
            result,
            PutMetadataResult {
                txids: vec![lotus_txid(&tx)],
                blockchain_action: PutBlockchainAction::Broadcast,
                signed_metadata: SignedPayload::parse_proto(&signed_metadata)?,
            }
        );

        let signed_payload = registry.get_metadata(&address)?;
        assert_eq!(
            signed_payload,
            Some(SignedPayload::parse_proto(&signed_metadata)?),
        );

        // Putting the exact same metadata again works, the node already knows the payload hash.
        let result = registry.put_metadata(&address, &signed_metadata).await?;
        assert_eq!(
            result,
            PutMetadataResult {
                txids: vec![lotus_txid(&tx)],
                blockchain_action: PutBlockchainAction::AlreadyKnowPayloadHash,
                signed_metadata: SignedPayload::parse_proto(&signed_metadata)?,
            }
        );

        // Override address metadata with new SignedPayload
        let mut build_signed_metadata = |address_metadata: proto::AddressMetadata| -> Result<_> {
            let mut signed_metadata = signed_metadata.clone();

            signed_metadata.payload = address_metadata.encode_to_vec();
            let payload_hash = Sha256::digest(signed_metadata.payload.clone().into());
            signed_metadata.payload_hash = payload_hash.as_slice().to_vec();
            signed_metadata.sig = registry
                .ecc
                .sign(&seckey, payload_hash.byte_array().clone())
                .to_vec();

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
                        script: build_commitment_script(
                            ADDRESS_METADATA_LOKAD_ID,
                            pubkey.array(),
                            &payload_hash,
                        ),
                    }),
                ],
                lock_time: 0,
            };
            signed_metadata.burn_amount = burn_amount;
            let tx = tx_builder.sign(&registry.ecc, 1000, 546)?;
            signed_metadata.burn_txs[0].tx = tx.ser().to_vec();
            signed_metadata.burn_txs[0].burn_idx = 1;
            Ok((signed_metadata, tx))
        };

        let (signed_metadata, _) = build_signed_metadata(proto::AddressMetadata {
            timestamp: 1234,
            ttl: 10,
            entries: vec![proto::AddressEntry {
                kind: "test".to_string(),
                headers: [].into(),
                body: vec![],
            }],
        })?;
        let err = registry
            .put_metadata(&address, &signed_metadata)
            .await
            .unwrap_err()
            .downcast::<RegistryError>()?;
        assert_eq!(
            err,
            RegistryError::TimestampNotMonotonicallyIncreasing {
                previous: 1234,
                next: 1234,
            },
        );

        // With more recent timestamp, it succeeds.
        let (signed_metadata, tx) = build_signed_metadata(proto::AddressMetadata {
            timestamp: 1235,
            ttl: 10,
            entries: vec![],
        })?;
        let result = registry.put_metadata(&address, &signed_metadata).await?;
        assert_eq!(
            result,
            PutMetadataResult {
                txids: vec![lotus_txid(&tx)],
                blockchain_action: PutBlockchainAction::Broadcast,
                signed_metadata: SignedPayload::parse_proto(&signed_metadata)?,
            }
        );

        assert_eq!(
            registry.get_metadata(&address)?,
            Some(SignedPayload::parse_proto(&signed_metadata)?)
        );

        let (signed_metadata, tx) = build_signed_metadata(proto::AddressMetadata {
            timestamp: 1236,
            ttl: 10,
            entries: vec![],
        })?;
        // pre-broadcast tx works
        bitcoind
            .cmd_text("sendrawtransaction", &[tx.ser().hex().into()])
            .await?;
        // Mine block: This would make another "sendrawtransaction" of `tx` fail.
        bitcoind
            .cmd_text("generatetoaddress", &[1i32.into(), address.as_str().into()])
            .await?;
        let result = registry.put_metadata(&address, &signed_metadata).await?;
        assert_eq!(
            result,
            PutMetadataResult {
                txids: vec![lotus_txid(&tx)],
                blockchain_action: PutBlockchainAction::AlreadyKnowTx,
                signed_metadata: SignedPayload::parse_proto(&signed_metadata)?,
            }
        );

        assert_eq!(
            registry.get_metadata(&address)?,
            Some(SignedPayload::parse_proto(&signed_metadata)?),
        );

        // Malleate tx, will result in a different txid, but same raw tx hex
        let (mut signed_metadata, tx) = build_signed_metadata(proto::AddressMetadata {
            timestamp: 1237,
            ttl: 10,
            entries: vec![],
        })?;
        bitcoind
            .cmd_text("sendrawtransaction", &[tx.ser().hex().into()])
            .await?;
        let old_tx = tx.clone();
        let mut tx_builder = TxBuilder::from_tx(tx);
        *tx_builder.inputs[0].signatory_mut() = Some(Box::new(P2PKHSignatory {
            seckey: seckey.clone(),
            pubkey,
            sig_hash_type: SigHashType::ALL_BIP143,
        }));
        let tx = tx_builder.sign(&registry.ecc, 1000, 546)?;
        assert_ne!(old_tx, tx);
        signed_metadata.burn_txs[0].tx = tx.ser().to_vec();
        let err = registry
            .put_metadata(&address, &signed_metadata)
            .await
            .unwrap_err()
            .downcast::<RegistryError>()?;
        assert_eq!(
            err,
            RegistryError::TxMalleated {
                expected: old_tx.ser().hex(),
                actual: tx.ser().hex(),
            },
        );

        // this test is incredibly flaky, only meant to be run to verify race condition handling
        if false {
            let mut found_any_race_condition = false;
            for i in 3..95 {
                let (signed_metadata, tx) = build_signed_metadata(proto::AddressMetadata {
                    timestamp: 1234 + i,
                    ttl: 10,
                    entries: vec![],
                })?;
                println!("**** i = {}", i);
                // pre-broadcast tx works
                // Race condition:
                // Mine block: This would make another "sendrawtransaction" of `tx` fail.
                let handle = tokio::spawn({
                    let address = address.clone();
                    let bitcoind = bitcoind.clone();
                    let tx = tx.clone();
                    async move {
                        tokio::time::sleep(std::time::Duration::from_micros(3 + (i * 3) as u64))
                            .await;
                        bitcoind
                            .cmd_text("sendrawtransaction", &[tx.ser().hex().into()])
                            .await
                            .unwrap();
                        bitcoind
                            .cmd_text("generatetoaddress", &[1i32.into(), address.as_str().into()])
                            .await
                            .unwrap();
                    }
                });
                let result = registry.put_metadata(&address, &signed_metadata).await;
                if let Ok(result) = result {
                    if result.blockchain_action == PutBlockchainAction::BroadcastRaceCondition {
                        found_any_race_condition = true;
                        break;
                    }
                }
                handle.await?;
            }

            assert!(
                found_any_race_condition,
                "No block race condition could be simulated",
            );
        }

        instance.cleanup()?;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_registry_metadata_range() -> Result<()> {
        let _ = bitcoinsuite_error::install();
        let tempdir = tempdir::TempDir::new("cashweb-registry--registry")?;
        let db = Db::open(tempdir.path().join("db.rocksdb"))?;

        let conf = BitcoindConf::from_chain_regtest(
            bin_folder(),
            BitcoindChain::XPI,
            vec![OsString::from("-txindex")],
        )?;
        let mut instance = BitcoindInstance::setup(conf)?;
        instance.wait_for_ready()?;
        let bitcoind = instance.rpc_client();

        let registry = Registry {
            db,
            ecc: EccSecp256k1::default(),
            bitcoind: bitcoind.clone(),
            net: Net::Regtest,
        };

        // Generate a few anyone can spend coins
        let anyone_script = Script::from_slice(&[0x51]);
        let anyone_address = LotusAddress::new(
            "lotus",
            Net::Regtest,
            Script::p2sh(&ShaRmd160::digest(anyone_script.bytecode().clone())),
        );
        let mut utxos = setup_bitcoind_coins(
            instance.cli(),
            Network::XPI,
            10,
            anyone_address.as_str(),
            &anyone_address.script().hex(),
        )?;

        let items = registry.get_metadata_range(0, None, None, 10)?;
        assert_eq!(items, GetMetadataRangeResult { entries: vec![] });

        let mut entries = Vec::new();
        let test_cases = [
            (1, 1000),
            (2, 1000),
            (2, 1001),
            (3, 1001),
            (4, 1001),
            (3, 1002),
        ];
        for (seckey_byte, timestamp) in test_cases {
            let seckey = registry.ecc.seckey_from_array([seckey_byte; 32])?;
            let pubkey = registry.ecc.derive_pubkey(&seckey);
            let address = LotusAddress::new(
                "lotus",
                Net::Regtest,
                Script::p2pkh(&ShaRmd160::digest(pubkey.array().into())),
            );
            let pkh = PkhAlgorithm::Sha256Ripemd160.hash_pubkey(pubkey.array());

            // Build valid address metadata
            let address_metadata = proto::AddressMetadata {
                timestamp,
                ttl: 10,
                entries: vec![],
            };
            let payload_hash = Sha256::digest(address_metadata.encode_to_vec().into());

            // Build burn commitment tx
            let (outpoint, amount) = utxos.pop().unwrap();
            let burn_amount = amount - 10_000;
            let tx = build_tx(
                outpoint,
                &anyone_script,
                vec![TxOutput {
                    value: burn_amount,
                    script: build_commitment_script(
                        ADDRESS_METADATA_LOKAD_ID,
                        pubkey.array(),
                        &payload_hash,
                    ),
                }],
            );

            // Sign address metadata
            let signed_metadata = cashweb_payload::proto::SignedPayload {
                pubkey: pubkey.array().to_vec(),
                sig: registry
                    .ecc
                    .sign(&seckey, payload_hash.byte_array().clone())
                    .to_vec(),
                sig_scheme: SignatureScheme::Ecdsa.into(),
                payload: address_metadata.encode_to_vec(),
                payload_hash: payload_hash.as_slice().to_vec(),
                burn_amount,
                burn_txs: vec![cashweb_payload::proto::BurnTx {
                    tx: tx.ser().to_vec(),
                    burn_idx: 0,
                }],
            };

            registry.put_metadata(&address, &signed_metadata).await?;
            // Even gets overridden by odd
            entries.push((
                pkh.to_address(Net::Regtest),
                SignedPayload::<proto::AddressMetadata>::parse_proto(&signed_metadata)?,
            ));
        }

        let index_entries = |indices: &[usize]| GetMetadataRangeResult {
            entries: indices.iter().map(|&idx| entries[idx].clone()).collect(),
        };

        let items = registry.get_metadata_range(0, None, None, 1)?;
        assert_eq!(items, index_entries(&[0]));

        let items = registry.get_metadata_range(0, None, None, 4)?;
        assert_eq!(items, index_entries(&[0, 4, 2, 5]));

        let items = registry.get_metadata_range(0, Some(1002), None, 3)?;
        assert_eq!(items, index_entries(&[0, 4, 2]));

        {
            let address = &entries[4].0;
            let items = registry.get_metadata_range(999, None, Some(address), 10)?;
            assert_eq!(items, index_entries(&[0, 4, 2, 5]));
            let items = registry.get_metadata_range(1000, None, Some(address), 10)?;
            assert_eq!(items, index_entries(&[4, 2, 5]));
            let items = registry.get_metadata_range(1001, None, Some(address), 10)?;
            assert_eq!(items, index_entries(&[2, 5]));
        }

        let items = registry.get_metadata_range(1001, Some(1002), None, 3)?;
        assert_eq!(items, index_entries(&[4, 2]));

        // Add stale timestamp for some pkh
        let cf_pkh_by_time = registry.db.cf(CF_PKH_BY_TIME)?;
        registry.db.rocksdb().put_cf(
            cf_pkh_by_time,
            TimePkh {
                timestamp: 1000,
                pkh: PubKeyHash::from_address(&entries[3].0, Net::Regtest)?,
            }
            .to_storage_bytes(),
            &[],
        )?;

        // Stale entry gets ignored
        let items = registry.get_metadata_range(0, None, None, 10)?;
        assert_eq!(items, index_entries(&[0, 4, 2, 5]));

        Ok(())
    }
}
