//! Contains `DbTopics`, allowing access to topic data.

use crate::{
    proto,
    store::db::{Db, CF, CF_MESSAGES, CF_PAYLOADS},
};
use bitcoinsuite_core::{Hashed, Sha256};
use bitcoinsuite_error::{ErrorMeta, Result, WrapErr};
use cashweb_payload::payload::SignedPayload;
use prost::Message;
use rocksdb::{ColumnFamilyDescriptor, Direction, IteratorMode};
use std::fmt::Debug;
use thiserror::Error;

type TopicPayload = SignedPayload<proto::BroadcastMessage>;

/// Allows access to registry metadata.
pub struct DbTopics<'a> {
    db: &'a Db,
    cf_messages: &'a CF,
    cf_payloads: &'a CF,
}

/// Errors indicating some registry topic error.
#[derive(Debug, Error, ErrorMeta, PartialEq, Eq)]
pub enum DbTopicsError {
    /// Value not found in message
    #[critical()]
    #[error("Value not found in messages: {0}")]
    MissingValue(String),

    /// Topic has too many separators
    #[critical()]
    #[error("Topic has too many separators: {0} > 10")]
    TopicTooLong(usize),

    /// Topic contains invalid characters
    #[critical()]
    #[error("Topic contains invalid characters")]
    TopicInvalidCharacters(),

    /// Topic contains empty segments
    #[critical()]
    #[error("Topic contains empty segments")]
    TopicInvalidSegments(),

    /// Database contains an invalid protobuf MetadataEntry.
    #[critical()]
    #[error("Inconsistent db: Invalid SignedPayload in DB")]
    InvalidSignedPayloadInDb,

    /// Attempting to write message with no payload
    #[critical()]
    #[error("Attempting to write message with no payload")]
    MissingPayload(),
}
use self::DbTopicsError::*;

/// Allows access to registry topics.
impl<'a> DbTopics<'a> {
    /// Create a new [`DbTopic`] instance.
    pub fn new(db: &'a Db) -> Self {
        let cf_messages = db.cf(CF_MESSAGES).unwrap();
        let cf_payloads = db.cf(CF_PAYLOADS).unwrap();
        DbTopics {
            db,
            cf_messages,
            cf_payloads,
        }
    }

    /// Put a serialized `Message` to database.
    pub fn put_message(&self, timestamp: u64, message: &TopicPayload) -> Result<()> {
        let buf = message.to_proto().encode_to_vec();
        let payload = message.payload().as_ref().ok_or(MissingPayload())?;
        let topic = payload.topic.clone();

        let split_topic = topic.split('.').collect::<Vec<_>>();
        if split_topic.len() > 10 {
            return Err(TopicTooLong(split_topic.len()))?;
        }
        if split_topic.iter().any(|segment| segment.is_empty()) {
            return Err(TopicInvalidSegments())?;
        }

        let payload_hash = message.payload_hash().as_slice().to_vec();

        let mut batch = rocksdb::WriteBatch::default();

        batch.put_cf(self.cf_payloads, &payload_hash, &buf);

        for idx in 0..split_topic.len() + 1 {
            let base_topic_parts = split_topic[..idx].join(".");
            let topic_digest = Sha256::digest(base_topic_parts.as_bytes().into())
                .as_slice()
                .to_vec();
            let topical_key = [
                &topic_digest,
                timestamp.to_be_bytes().as_ref(),
                &payload_hash,
            ]
            .concat();
            batch.put_cf(self.cf_messages, &topical_key, &payload_hash);
        }
        self.db.write_batch(batch)?;
        Ok(())
    }

    /// Replace a serialized `Message` to database. No need to update
    /// indexes as they are all pointing to this entry.
    pub fn update_message(&self, message: &TopicPayload) -> Result<()> {
        let buf = message.to_proto().encode_to_vec();

        let payload_hash = message.payload_hash().as_slice().to_vec();

        self.db
            .rocksdb()
            .put_cf(self.cf_payloads, &payload_hash, &buf)?;
        Ok(())
    }

    /// Get serialized `messages` from database.
    pub fn get_messages_to(&self, topic: &str, from: i64, to: i64) -> Result<Vec<TopicPayload>> {
        let valid_topic = topic
            .chars()
            .all(|c| c.is_lowercase() || c.is_numeric() || c == '.' || c == '-');
        if !valid_topic {
            return Err(TopicInvalidCharacters())?;
        }

        let topic_digest = Sha256::digest(topic.as_bytes().into()).as_slice().to_vec();
        let start_prefix = [&topic_digest, from.to_be_bytes().as_ref()].concat();
        let end_prefix = [&topic_digest, to.to_be_bytes().as_ref()].concat();

        let iter = self.db.rocksdb().iterator_cf(
            self.cf_messages,
            IteratorMode::From(&start_prefix, Direction::Forward),
        );

        iter.take_while(|item| match item {
            Ok(item) => {
                let (key, _) = item;
                key.to_vec() <= end_prefix
            }
            Err(_) => false,
        })
        .map(|item| {
            let (_, payload_digest) = item?;
            self.get_message(&payload_digest)
        })
        .collect()
    }

    /// Get a vector of messages starting at some unix timestamp.
    /// TODO: actually use this
    #[allow(dead_code)]
    pub fn get_messages(&self, topic: &str, from: i64) -> Result<Vec<TopicPayload>> {
        self.get_messages_to(topic, from, i64::MAX)
    }

    /// Get a specific message by payload hash.
    pub fn get_message(&self, payload_digest: &[u8]) -> Result<TopicPayload> {
        let wrapper_bytes = self
            .db
            .rocksdb()
            .get_cf(self.cf_payloads, payload_digest)?
            .ok_or_else(|| MissingValue(hex::encode(payload_digest)))?;

        let proto = cashweb_payload::proto::SignedPayload::decode(wrapper_bytes.as_slice())?;
        Ok(TopicPayload::parse_proto(&proto).wrap_err(InvalidSignedPayloadInDb)?)
    }

    pub(crate) fn add_cfs(columns: &mut Vec<ColumnFamilyDescriptor>) {
        let options = rocksdb::Options::default();
        columns.push(ColumnFamilyDescriptor::new(CF_MESSAGES, options.clone()));
        columns.push(ColumnFamilyDescriptor::new(CF_PAYLOADS, options));
    }
}

impl Debug for DbTopics<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DbTopics {{ .. }}")
    }
}

#[cfg(test)]
mod tests {
    use bitcoinsuite_core::{BitcoinCode, Hashed, Script, Sha256, TxOutput, UnhashedTx};
    use bitcoinsuite_error::Result;
    use cashweb_payload::payload::{SignatureScheme, SignedPayload};
    use pretty_assertions::assert_eq;
    use prost::Message;

    use crate::{proto, store::db::Db};
    type TopicPayload = SignedPayload<proto::BroadcastMessage>;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn messages() -> Result<()> {
        let _ = bitcoinsuite_error::install();
        let tempdir = tempdir::TempDir::new("cashweb-registry-store--metadata")?;
        let db = Db::open(tempdir.path().join("db.rocksdb"))?;

        // Tx parses, but the output burn_index points to doesn't exist
        let broadcast_message_one = proto::BroadcastMessage {
            timestamp: 1234,
            entries: vec![],
            topic: "foo.bar.bob".to_owned(),
        };
        let payload_hash_one = Sha256::digest(broadcast_message_one.encode_to_vec().into())
            .as_slice()
            .to_vec();
        let tx1 = UnhashedTx {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput {
                value: 1_000_000,
                script: Script::default(),
            }],
            lock_time: 0,
        };
        let message_one = TopicPayload::parse_proto(&cashweb_payload::proto::SignedPayload {
            pubkey: vec![2; 33],
            sig: vec![], // invalid sig
            sig_scheme: SignatureScheme::Ecdsa.into(),
            payload: broadcast_message_one.encode_to_vec(), // invalid payload
            payload_hash: payload_hash_one.clone(),
            burn_amount: 1_000_000,
            burn_txs: vec![cashweb_payload::proto::BurnTx {
                tx: tx1.ser().to_vec(),
                burn_idx: 0,
            }],
        })?;

        // Tx parses, but the output burn_index points to doesn't exist
        let broadcast_message_two = proto::BroadcastMessage {
            timestamp: 1234,
            entries: vec![],
            topic: "foo.bar".to_owned(),
        };
        let payload_hash_two = Sha256::digest(broadcast_message_two.encode_to_vec().into())
            .as_slice()
            .to_vec();
        let tx2 = UnhashedTx {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput {
                value: 1_200_000,
                script: Script::default(),
            }],
            lock_time: 0,
        };
        let message_two = TopicPayload::parse_proto(&cashweb_payload::proto::SignedPayload {
            pubkey: vec![2; 33],
            sig: vec![], // invalid sig
            sig_scheme: SignatureScheme::Ecdsa.into(),
            payload: broadcast_message_two.encode_to_vec(), // invalid payload
            payload_hash: payload_hash_two.clone(),
            burn_amount: 1_200_000,
            burn_txs: vec![cashweb_payload::proto::BurnTx {
                tx: tx2.ser().to_vec(),
                burn_idx: 0,
            }],
        })?;

        let database = db.topics();

        let data_wrapper_out_0 = database.get_messages("foo.bar.bob", 0)?;
        assert_eq!(data_wrapper_out_0.len(), 0);

        // Put to database
        database.put_message(1, &message_one)?;

        // Get from database
        let data_wrapper_out = database.get_messages("foo.bar.bob", 0)?;
        assert_eq!(data_wrapper_out.len(), 1);
        assert_eq!(message_one, data_wrapper_out[0]);

        // Get from database
        let data_wrapper_out = database.get_messages("foo", 0)?;
        assert_eq!(data_wrapper_out.len(), 1);
        assert_eq!(message_one, data_wrapper_out[0]);

        // Put to database
        database.put_message(1, &message_two)?;

        // Get from database and ensure original topic wasn't changed
        let data_wrapper_out_two = database.get_messages("foo.bar.bob", 0)?;
        assert_eq!(data_wrapper_out_two.len(), 1);
        assert_eq!(message_one, data_wrapper_out_two[0]);

        // Get from database
        let data_wrapper_three = database.get_messages("foo", 0)?;
        assert_eq!(data_wrapper_three.len(), 2);
        assert_eq!(message_one, data_wrapper_three[0]);
        assert_eq!(message_two, data_wrapper_three[1]);

        let data_wrapper_four = database.get_messages("", 0)?;
        assert_eq!(data_wrapper_four.len(), 2);
        assert_eq!(message_one, data_wrapper_four[0]);
        assert_eq!(message_two, data_wrapper_four[1]);

        // Destroy database
        Ok(())
    }
}
