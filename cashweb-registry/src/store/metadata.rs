//! Contains `DbMetadata`, allowing access to keyserver metadata.

use std::fmt::Debug;

use bitcoinsuite_error::{ErrorMeta, Result, WrapErr};
use cashweb_payload::payload::SignedPayload;
use rocksdb::ColumnFamilyDescriptor;
use thiserror::Error;

use crate::{
    proto,
    store::{
        db::{Db, CF, CF_METADATA, CF_PKH_BY_TIME},
        pubkeyhash::{PubKeyHash, TimePkh},
    },
};

/// Allows access to registry metadata.
pub struct DbMetadata<'a> {
    db: &'a Db,
    cf_metadata: &'a CF,
    cf_pkh_by_time: &'a CF,
}

/// Errors indicating some registry metadata error.
#[derive(Debug, Error, ErrorMeta, PartialEq, Eq)]
pub enum DbMetadataError {
    /// Database contains an invalid protobuf MetadataEntry.
    #[critical()]
    #[error("Inconsistent db: Cannot decode MetadataEntry: {0}")]
    CannotDecodeMetadataEntry(String),

    /// Database contains an invalid protobuf MetadataEntry.
    #[critical()]
    #[error("Inconsistent db: Invalid SignedPayload in DB")]
    InvalidSignedPayloadInDb,
}

use self::DbMetadataError::*;

impl<'a> DbMetadata<'a> {
    /// Create a new [`DbMetadata`] instance.
    pub fn new(db: &'a Db) -> Self {
        let cf_metadata = db.cf(CF_METADATA).unwrap();
        let cf_pkh_by_time = db.cf(CF_PKH_BY_TIME).unwrap();
        DbMetadata {
            db,
            cf_metadata,
            cf_pkh_by_time,
        }
    }

    /// Store a [`cashweb_payload::proto::SignedPayload`] in the db.
    pub fn put(
        &self,
        pkh: &PubKeyHash,
        metadata_entry: &SignedPayload<proto::AddressMetadata>,
    ) -> Result<()> {
        use prost::Message;
        let mut batch = rocksdb::WriteBatch::default();
        if let Some(existing_entry) = self.get(pkh)? {
            // Note: This can sometimes result in a race condition, leaving a redundant and stale
            // entry in "pkh_by_time". We handle this by ignoring stale entries elsewhere.
            let time_pkh = TimePkh {
                timestamp: existing_entry.payload().timestamp,
                pkh: pkh.clone(),
            };
            batch.delete_cf(self.cf_pkh_by_time, &time_pkh.to_storage_bytes());
        }
        batch.put_cf(
            self.cf_metadata,
            &pkh.to_storage_bytes(),
            &metadata_entry.to_proto().encode_to_vec(),
        );
        let time_pkh = TimePkh {
            timestamp: metadata_entry.payload().timestamp,
            pkh: pkh.clone(),
        };
        batch.put_cf(self.cf_pkh_by_time, time_pkh.to_storage_bytes(), &[]);
        self.db.write_batch(batch)?;
        Ok(())
    }

    /// Retrieve a [`cashweb_payload::proto::SignedPayload`] from the db.
    pub fn get(&self, pkh: &PubKeyHash) -> Result<Option<SignedPayload<proto::AddressMetadata>>> {
        use prost::Message;
        let serialized_entry = match self.db.get(self.cf_metadata, &pkh.to_storage_bytes())? {
            Some(serialized_entry) => serialized_entry,
            None => return Ok(None),
        };
        let entry = cashweb_payload::proto::SignedPayload::decode(serialized_entry.as_ref())
            .wrap_err_with(|| CannotDecodeMetadataEntry(hex::encode(&serialized_entry)))?;
        let entry = SignedPayload::parse_proto(&entry).wrap_err(InvalidSignedPayloadInDb)?;
        Ok(Some(entry))
    }

    /// Iterate public key hashes by time ascendingly from a given `start_timestamp`.
    /// Note: This could return stale entries (due to a race condition in `put`), those should be
    /// ignored.
    pub fn iter_by_time(&self, start_timestamp: i64) -> impl Iterator<Item = Result<TimePkh>> + 'a {
        let start_timestamp = start_timestamp.to_be_bytes();
        let iter = self.db.rocksdb().iterator_cf(
            self.cf_pkh_by_time,
            rocksdb::IteratorMode::From(&start_timestamp, rocksdb::Direction::Forward),
        );
        iter.map(|(key, _)| TimePkh::from_storage_bytes(Vec::from(key).into()))
    }

    pub(crate) fn add_cfs(columns: &mut Vec<ColumnFamilyDescriptor>) {
        let options = rocksdb::Options::default();
        columns.push(ColumnFamilyDescriptor::new(CF_METADATA, options.clone()));
        columns.push(ColumnFamilyDescriptor::new(CF_PKH_BY_TIME, options));
    }
}

impl Debug for DbMetadata<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DbMetadata {{ .. }}")
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        proto,
        store::{
            db::{Db, CF_METADATA, CF_PKH_BY_TIME},
            metadata::DbMetadataError,
            pubkeyhash::{PkhAlgorithm, PkhError, PubKeyHash, TimePkh},
        },
    };
    use bitcoinsuite_core::{BitcoinCode, Hashed, Script, Sha256, TxOutput, UnhashedTx};
    use bitcoinsuite_error::Result;
    use cashweb_payload::payload::{SignatureScheme, SignedPayload};
    use pretty_assertions::assert_eq;
    use prost::Message;

    #[test]
    fn test_db_metadata() -> Result<()> {
        let _ = bitcoinsuite_error::install();
        let tempdir = tempdir::TempDir::new("cashweb-registry-store--metadata")?;
        let db = Db::open(tempdir.path().join("db.rocksdb"))?;
        let pkh = PubKeyHash::new(PkhAlgorithm::Sha256Ripemd160, [7; 20].into())?;

        // Entry doesn't exist yet
        assert_eq!(db.metadata().get(&pkh)?, None);
        // No by time entries yet
        assert_eq!(db.metadata().iter_by_time(0).count(), 0);

        let mut address_metadata = proto::AddressMetadata {
            timestamp: 1234,
            ttl: 10,
            entries: vec![],
        };
        // Add entry and check
        let mut entry_proto = cashweb_payload::proto::SignedPayload {
            pubkey: vec![2; 33],
            sig: vec![4, 5, 6, 7, 8],
            sig_scheme: SignatureScheme::Ecdsa.into(),
            payload: address_metadata.encode_to_vec(),
            payload_hash: Sha256::digest(address_metadata.encode_to_vec().into())
                .as_slice()
                .to_vec(),
            burn_amount: 1_337_000_000_000,
            burn_txs: vec![cashweb_payload::proto::BurnTx {
                tx: UnhashedTx {
                    version: 1,
                    inputs: vec![],
                    outputs: vec![TxOutput {
                        script: Script::default(),
                        value: 1_337_000_000_000,
                    }],
                    lock_time: 0,
                }
                .ser()
                .to_vec(),
                burn_idx: 0,
            }],
        };
        let entry = SignedPayload::parse_proto(&entry_proto)?;
        db.metadata().put(&pkh, &entry)?;
        assert_eq!(db.metadata().get(&pkh)?, Some(entry));
        assert_eq!(
            db.metadata()
                .iter_by_time(1234)
                .map(Result::unwrap)
                .collect::<Vec<_>>(),
            vec![TimePkh {
                timestamp: 1234,
                pkh: pkh.clone(),
            }],
        );
        assert_eq!(db.metadata().iter_by_time(1235).count(), 0);

        // Update entry
        address_metadata.timestamp = 1235;
        entry_proto.payload = address_metadata.encode_to_vec();
        entry_proto.payload_hash = Sha256::digest(entry_proto.payload.clone().into())
            .as_slice()
            .to_vec();
        let entry = SignedPayload::parse_proto(&entry_proto)?;
        db.metadata().put(&pkh, &entry)?;
        assert_eq!(db.metadata().get(&pkh)?, Some(entry));
        assert_eq!(
            db.metadata()
                .iter_by_time(1234)
                .map(Result::unwrap)
                .collect::<Vec<_>>(),
            vec![TimePkh {
                timestamp: 1235,
                pkh: pkh.clone(),
            }],
        );
        assert_eq!(db.metadata().iter_by_time(1235).count(), 1);
        assert_eq!(db.metadata().iter_by_time(1236).count(), 0);

        // Put data with invalid Protobuf encoding
        db.put(db.cf(CF_METADATA)?, &pkh.to_storage_bytes(), b"foobar")?;
        // Results in CannotDecodeMetadataEntry
        assert_eq!(
            db.metadata()
                .get(&pkh)
                .unwrap_err()
                .downcast::<DbMetadataError>()?,
            DbMetadataError::CannotDecodeMetadataEntry("666f6f626172".to_string()),
        );

        // Put data with invalid TimePkh encoding
        db.put(db.cf(CF_PKH_BY_TIME)?, b"foobar", b"")?;
        assert_eq!(
            db.metadata()
                .iter_by_time(0)
                .last()
                .unwrap()
                .unwrap_err()
                .downcast::<PkhError>()?,
            PkhError::InvalidTimePkhTimestamp,
        );

        Ok(())
    }

    #[test]
    fn test_iter_by_time() -> Result<()> {
        let _ = bitcoinsuite_error::install();
        let tempdir = tempdir::TempDir::new("cashweb-registry-store--metadata")?;
        let db = Db::open(tempdir.path().join("db.rocksdb"))?;

        let mut pkhs = Vec::new();
        for i in 0u8..50 {
            let pkh = PubKeyHash::new(PkhAlgorithm::Sha256Ripemd160, [i / 2; 20].into())?;
            let address_metadata = proto::AddressMetadata {
                timestamp: 1000 + i as i64,
                ttl: 10,
                entries: vec![],
            };
            let entry_proto = cashweb_payload::proto::SignedPayload {
                pubkey: vec![2; 33],
                sig: vec![4, 5, 6, 7, 8],
                sig_scheme: SignatureScheme::Ecdsa.into(),
                payload: address_metadata.encode_to_vec(),
                payload_hash: vec![],
                burn_amount: 0,
                burn_txs: vec![],
            };
            let entry = SignedPayload::parse_proto(&entry_proto)?;
            db.metadata().put(&pkh, &entry)?;
            // even gets overridden by odd
            if i % 2 == 1 {
                pkhs.push(pkh);
            }
        }

        // i = 0 got overridden by i = 1
        assert_eq!(
            db.metadata().iter_by_time(0).next().transpose()?,
            Some(TimePkh {
                timestamp: 1001,
                pkh: pkhs[0].clone(),
            }),
        );
        assert_eq!(
            db.metadata().iter_by_time(1001).next().transpose()?,
            Some(TimePkh {
                timestamp: 1001,
                pkh: pkhs[0].clone(),
            }),
        );

        // Get all odd timestamps after (including) 1020
        assert_eq!(
            db.metadata()
                .iter_by_time(1020)
                .map(Result::unwrap)
                .collect::<Vec<_>>(),
            pkhs[10..]
                .iter()
                .enumerate()
                .map(|(idx, pkh)| {
                    TimePkh {
                        timestamp: 1021 + idx as i64 * 2,
                        pkh: pkh.clone(),
                    }
                })
                .collect::<Vec<_>>(),
        );

        Ok(())
    }

    #[test]
    fn test_db_metadata_debug() -> Result<()> {
        let _ = bitcoinsuite_error::install();
        let tempdir = tempdir::TempDir::new("cashweb-registry-store--metadata-debug")?;
        let db = Db::open(tempdir.path().join("db.rocksdb"))?;
        assert_eq!(format!("{:?}", db.metadata()), "DbMetadata { .. }");
        Ok(())
    }
}
