//! Store provides structs for storing and retrieving registry data.
//! Database is RocksDB, keys for metadata are (compact) scripts, values are protobuf encoded.

pub mod db;
pub mod metadata;
pub mod pubkeyhash;
pub mod topics;
