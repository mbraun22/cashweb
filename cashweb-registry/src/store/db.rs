//! Module for `Db` and `DbError`.

use std::{fmt::Debug, path::Path};

use bitcoinsuite_error::{ErrorMeta, Result, WrapErr};
use rocksdb::ColumnFamilyDescriptor;
use thiserror::Error;

use crate::store::metadata::DbMetadata;
use crate::store::topics::DbTopics;

// We collect the column family constants here so we have a nice overview.
// This makes it easier to keep cf names consistent and non-conflicting.
pub(crate) const CF_METADATA: &str = "metadata";
pub(crate) const CF_PKH_BY_TIME: &str = "pkh_by_time";
pub(crate) const CF_MESSAGES: &str = "topic_messages";
pub(crate) const CF_PAYLOADS: &str = "message_payloads";

pub(crate) type CF = rocksdb::ColumnFamily;

/// Registry database.
/// Owns the underlying rocksdb::DB instance.
pub struct Db {
    db: rocksdb::DB,
}

/// Errors indicating something went wrong with the database itself.
#[derive(Debug, Error, ErrorMeta)]
pub enum DbError {
    /// Column family requested but not defined during `Db::open`.
    #[critical()]
    #[error("Column family {0} doesn't exist")]
    NoSuchColumnFamily(String),

    /// Error with RocksDB itself, e.g. db inconsistency.
    #[critical()]
    #[error("RocksDB error")]
    RocksDb,
}

use self::DbError::*;

impl Db {
    /// Opens the database under the specified path.
    /// Creates the database file and necessary column families if necessary.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut cfs = Vec::new();
        DbMetadata::add_cfs(&mut cfs);
        DbTopics::add_cfs(&mut cfs);
        Self::open_with_cfs(path, cfs)
    }

    /// Returns `DbMetadata`, allowing access to registry metadata.
    pub fn metadata(&self) -> DbMetadata<'_> {
        DbMetadata::new(self)
    }

    /// Returns `DbTopics`, allowing access to registry metadata.
    pub fn topics(&self) -> DbTopics<'_> {
        DbTopics::new(self)
    }

    pub(crate) fn open_with_cfs(
        path: impl AsRef<Path>,
        cfs: Vec<ColumnFamilyDescriptor>,
    ) -> Result<Self> {
        let mut db_options = rocksdb::Options::default();
        db_options.create_if_missing(true);
        db_options.create_missing_column_families(true);
        let db = rocksdb::DB::open_cf_descriptors(&db_options, path, cfs).wrap_err(RocksDb)?;
        Ok(Db { db })
    }

    pub(crate) fn cf(&self, name: &str) -> Result<&CF> {
        Ok(self
            .db
            .cf_handle(name)
            .ok_or_else(|| NoSuchColumnFamily(name.to_string()))?)
    }

    pub(crate) fn get(
        &self,
        cf: &CF,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<rocksdb::DBPinnableSlice<'_>>> {
        self.db.get_pinned_cf(cf, key).wrap_err(RocksDb)
    }

    #[cfg(test)]
    pub(crate) fn put(
        &self,
        cf: &CF,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<()> {
        self.db.put_cf(cf, key, value).wrap_err(RocksDb)
    }

    pub(crate) fn rocksdb(&self) -> &rocksdb::DB {
        &self.db
    }

    pub(crate) fn write_batch(&self, write_batch: rocksdb::WriteBatch) -> Result<()> {
        self.db.write(write_batch)?;
        Ok(())
    }
}

impl Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Db {{ .. }}")
    }
}

#[cfg(test)]
mod tests {
    use crate::store::db::Db;
    use bitcoinsuite_error::Result;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_db_debug() -> Result<()> {
        let _ = bitcoinsuite_error::install();
        let tempdir = tempdir::TempDir::new("cashweb-registry-store--db-debug")?;
        let db = Db::open(tempdir.path().join("db.rocksdb"))?;
        assert_eq!(format!("{:?}", db), "Db { .. }");
        Ok(())
    }
}
