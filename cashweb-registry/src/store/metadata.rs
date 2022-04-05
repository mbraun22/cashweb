//! Contains `DbMetadata`, allowing access to keyserver metadata.

use std::fmt::Debug;

use bitcoinsuite_error::{ErrorMeta, Result, WrapErr};
use cashweb_payload::proto::SignedPayload;
use rocksdb::ColumnFamilyDescriptor;
use thiserror::Error;

use crate::store::{
    db::{Db, CF, CF_METADATA},
    pubkeyhash::PubKeyHash,
};

/// Allows access to registry metadata.
pub struct DbMetadata<'a> {
    db: &'a Db,
    cf_metadata: &'a CF,
}

/// Errors indicating some registry metadata error.
#[derive(Debug, Error, ErrorMeta, PartialEq, Eq)]
pub enum DbMetadataError {
    /// Database contains an invalid protobuf MetadataEntry.
    #[critical()]
    #[error("Inconsistent db: Cannot decode MetadataEntry: {0}")]
    CannotDecodeMetadataEntry(String),
}

use self::DbMetadataError::*;

impl<'a> DbMetadata<'a> {
    /// Create a new [`DbMetadata`] instance.
    pub fn new(db: &'a Db) -> Self {
        let cf_metadata = db
            .cf(CF_METADATA)
            .expect("CF_METADATA column family doesn't exist");
        DbMetadata { db, cf_metadata }
    }

    /// Store a [`SignedPayload`] in the db.
    pub fn put(&self, pkh: &PubKeyHash, metadata_entry: &SignedPayload) -> Result<()> {
        use prost::Message;
        self.db.put(
            self.cf_metadata,
            pkh.to_storage_bytes(),
            &metadata_entry.encode_to_vec(),
        )
    }

    /// Retrieve a [`SignedPayload`] from the db.
    pub fn get(&self, pkh: &PubKeyHash) -> Result<Option<SignedPayload>> {
        use prost::Message;
        let serialized_entry = match self.db.get(self.cf_metadata, &pkh.to_storage_bytes())? {
            Some(serialized_entry) => serialized_entry,
            None => return Ok(None),
        };
        let entry = SignedPayload::decode(serialized_entry.as_ref())
            .wrap_err_with(|| CannotDecodeMetadataEntry(hex::encode(&serialized_entry)))?;
        Ok(Some(entry))
    }

    pub(crate) fn add_cfs(columns: &mut Vec<ColumnFamilyDescriptor>) {
        let options = rocksdb::Options::default();
        columns.push(ColumnFamilyDescriptor::new(CF_METADATA, options));
    }
}

impl Debug for DbMetadata<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DbMetadata {{ .. }}")
    }
}

#[cfg(test)]
mod tests {
    use crate::store::{
        db::{Db, CF_METADATA},
        metadata::DbMetadataError,
        pubkeyhash::{PkhAlgorithm, PubKeyHash},
    };
    use bitcoinsuite_error::Result;
    use cashweb_payload::proto::{signed_payload::SignatureScheme, BurnTx, SignedPayload};
    use pretty_assertions::assert_eq;

    #[test]
    fn test_db_metadata() -> Result<()> {
        let _ = bitcoinsuite_error::install();
        let tempdir = tempdir::TempDir::new("cashweb-registry-store--metadata")?;
        let db = Db::open(tempdir.path().join("db.rocksdb"))?;
        let pkh = PubKeyHash::new(PkhAlgorithm::Sha256Ripemd160, [7; 20].into())?;

        // Entry doesn't exist yet
        assert_eq!(db.metadata().get(&pkh)?, None);

        // Add entry and check
        let entry = SignedPayload {
            public_key: vec![1, 2, 3, 4],
            signature: vec![4, 5, 6, 7, 8],
            scheme: SignatureScheme::Ecdsa.into(),
            payload: vec![9, 10, 11, 12],
            payload_digest: vec![13, 14, 15, 16, 17],
            burn_amount: 1_337_000_000_000,
            burn_txs: vec![BurnTx {
                tx: vec![18, 19, 20, 21, 22, 23],
                burn_index: 24,
            }],
        };
        db.metadata().put(&pkh, &entry)?;
        assert_eq!(db.metadata().get(&pkh)?, Some(entry));

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
