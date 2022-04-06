//! Module for [`SignedPayload`] and [`BurnTx`].

use bitcoinsuite_core::{
    ecc::PUBKEY_LENGTH, BitcoinCode, Bytes, Hashed, Sha256, Tx, TxOutput, UnhashedTx,
};
use bitcoinsuite_error::{ErrorMeta, Result, WrapErr};
use thiserror::Error;

use crate::proto;
pub use crate::proto::signed_payload::SignatureScheme;

/// A payload signed with for a public key, which also provides a proof-of-burn to avoid spam.
///
/// SignedPayload provides integrity, authentication, and non-repuditation by
/// providing a standard structure for covering a payload with a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPayload {
    pub(crate) pubkey: [u8; PUBKEY_LENGTH],
    pub(crate) sig: Bytes,
    pub(crate) sig_scheme: SignatureScheme,
    pub(crate) payload: Bytes,
    pub(crate) payload_hash: Sha256,
    pub(crate) burn_amount: i64,
    pub(crate) burn_txs: Vec<BurnTx>,
}

/// A single burn transaction, commiting to a [`SignedPayload`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurnTx {
    pub(crate) tx: Tx,
    pub(crate) burn_idx: u32,
    pub(crate) burn_output: TxOutput,
}

/// Errors indicating that parsing a [`proto::SignedPayload`] failed.
#[derive(Debug, Error, ErrorMeta, PartialEq, Eq)]
pub enum ParseSignedPayloadError {
    /// `pubkey` is not 33 bytes long.
    #[invalid_client_input()]
    #[error("Public key len should be {}, but got {0}", PUBKEY_LENGTH)]
    InvalidPubKeyLen(usize),

    /// Both `payload` and `payload_hash` are empty.
    #[invalid_client_input()]
    #[error("Both payload and payload hash are empty")]
    PayloadHashAndPayloadEmpty,

    /// `payload_hash` len is not 32 or empty.
    #[invalid_client_input()]
    #[error("Payload hash len should be 32 or empty, but got {0}")]
    InvalidPayloadHashLen(usize),

    /// Claimed `payload_hash` does not match actual hash of `payload`.
    #[invalid_client_input()]
    #[error("Payload hash does not match payload")]
    IncorrectPayloadHash {
        /// Expected hash claimed in the protobuf.
        expected: Sha256,
        /// Actual hash by hashing `payload` with SHA-256.
        actual: Sha256,
    },

    /// Parsing `tx` in [`proto::BurnTx`] failed.
    #[invalid_client_input()]
    #[error("Parsing burn tx failed: {0}")]
    ParsingBurnTxFailed(String),

    /// Tx doesn't have `burn_idx` in [`proto::BurnTx`].
    #[invalid_client_input()]
    #[error("Burn tx doesn't have output index {0}")]
    NoSuchOutput(usize),

    /// `burn_amount` claimed in [`proto::SignedPayload`] doesn't match the actual burned amount.
    #[invalid_client_input()]
    #[error("Total burn amount mismatch: expected {expected}, but got {actual}")]
    TotalBurnAmountMismatch {
        /// Expected amount claimed in the protobuf.
        expected: i64,
        /// Actual sum of burned coins.
        actual: i64,
    },

    /// Invalid `sig_scheme`, expected ECDSA or Schnorr.
    #[invalid_client_input()]
    #[error("Unknown signature scheme ID: {0}")]
    UnknownSignatureScheme(i32),
}

use self::ParseSignedPayloadError::*;

impl SignedPayload {
    /// Parse and validate a [`proto::SignedPayload`].
    ///
    /// * `payload_hash` has to be empty or set to the hash of `payload`.
    /// * `burn_txs` has to contain parsable txs.
    /// * `burn_idx` has to point to an actually existing output in the tx.
    /// * `burn_amount` has to be 0 or set to the sum of burned coins.
    pub fn from_proto(signed_payload: proto::SignedPayload) -> Result<Self> {
        let pubkey: [u8; PUBKEY_LENGTH] = signed_payload
            .pubkey
            .as_slice()
            .try_into()
            .map_err(|_| InvalidPubKeyLen(signed_payload.pubkey.len()))?;
        let payload = Bytes::from(signed_payload.payload);
        let expected_payload_hash = Sha256::digest(payload.clone());

        // Assign or check the payload_hash
        let payload_hash = match signed_payload.payload_hash.len() {
            // If it's unset, set it to the expected hash
            0 => {
                if payload.is_empty() {
                    return Err(PayloadHashAndPayloadEmpty.into());
                }
                expected_payload_hash
            }
            // If it's set, verify length and compare
            _ => {
                let actual_payload_hash = Sha256::from_slice(&signed_payload.payload_hash)
                    .wrap_err(InvalidPayloadHashLen(signed_payload.payload_hash.len()))?;
                if expected_payload_hash != actual_payload_hash {
                    return Err(IncorrectPayloadHash {
                        expected: expected_payload_hash,
                        actual: actual_payload_hash,
                    }
                    .into());
                }
                expected_payload_hash
            }
        };

        // Parse `BurnTx`s
        let burn_txs = signed_payload
            .burn_txs
            .into_iter()
            .map(|burn_tx| {
                let tx = UnhashedTx::deser(&mut burn_tx.tx.clone().into())
                    .wrap_err_with(|| ParsingBurnTxFailed(hex::encode(&burn_tx.tx)))?
                    .hashed();
                let burn_idx = burn_tx.burn_idx as usize;
                let burn_output = tx
                    .outputs()
                    .get(burn_idx)
                    .ok_or(NoSuchOutput(burn_idx))?
                    .clone();
                Ok(BurnTx {
                    tx,
                    burn_idx: burn_tx.burn_idx,
                    burn_output,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // Calculate and verify the total burn amount
        let actual_burn_amount = burn_txs
            .iter()
            .map(|burn_tx| burn_tx.burn_output.value)
            .sum::<i64>();
        if signed_payload.burn_amount > 0 && signed_payload.burn_amount != actual_burn_amount {
            return Err(TotalBurnAmountMismatch {
                expected: signed_payload.burn_amount,
                actual: actual_burn_amount,
            }
            .into());
        }

        Ok(SignedPayload {
            pubkey,
            sig: signed_payload.sig.into(),
            sig_scheme: SignatureScheme::from_i32(signed_payload.sig_scheme)
                .ok_or(UnknownSignatureScheme(signed_payload.sig_scheme))?,
            payload,
            payload_hash,
            burn_amount: actual_burn_amount,
            burn_txs,
        })
    }

    /// Converts the [`SignedPayload`] to a Protobuf [`proto::SignedPayload`].
    pub fn to_proto(&self) -> proto::SignedPayload {
        proto::SignedPayload {
            pubkey: self.pubkey.to_vec(),
            sig: self.sig.to_vec(),
            sig_scheme: self.sig_scheme.into(),
            payload: self.payload.to_vec(),
            payload_hash: self.payload_hash.as_slice().to_vec(),
            burn_amount: self.burn_amount,
            burn_txs: self
                .burn_txs
                .iter()
                .map(|burn_tx| proto::BurnTx {
                    tx: burn_tx.tx.ser().to_vec(),
                    burn_idx: burn_tx.burn_idx,
                })
                .collect(),
        }
    }

    /// Public key signing for this payload.
    pub fn pubkey(&self) -> &[u8; PUBKEY_LENGTH] {
        &self.pubkey
    }

    /// Signature signing this payload.
    pub fn sig(&self) -> &Bytes {
        &self.sig
    }

    /// Signature scheme used by this `SignedPayload`, e.g. ECDSA or Schnorr
    pub fn sig_scheme(&self) -> SignatureScheme {
        self.sig_scheme
    }

    /// Payload that's being signed.
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    /// Hash of `payload`.
    pub fn payload_hash(&self) -> &Sha256 {
        &self.payload_hash
    }

    /// Number of coins (in sats) being burned for this payload.
    pub fn burn_amount(&self) -> i64 {
        self.burn_amount
    }

    /// List of transactions burning coins for this payload.
    pub fn txs(&self) -> &[BurnTx] {
        &self.burn_txs
    }
}

impl BurnTx {
    /// Transaction burning coins for some payload.
    pub fn tx(&self) -> &Tx {
        &self.tx
    }

    /// Output index that burns the coins.
    pub fn burn_idx(&self) -> u32 {
        self.burn_idx
    }

    /// Output of `tx` that burns the coins.
    pub fn burn_output(&self) -> &TxOutput {
        &self.burn_output
    }
}

#[cfg(test)]
mod tests {
    use bitcoinsuite_core::{BitcoinCode, Bytes, Hashed, Script, Sha256, TxOutput, UnhashedTx};
    use bitcoinsuite_error::Result;
    use pretty_assertions::assert_eq;

    use crate::{
        payload::ParseSignedPayloadError,
        payload::{BurnTx, SignatureScheme, SignedPayload},
        proto,
    };

    #[test]
    fn test_parse_signed_payload() -> Result<()> {
        let payload_err = |payload_proto: proto::SignedPayload| -> Result<ParseSignedPayloadError> {
            SignedPayload::from_proto(payload_proto)
                .unwrap_err()
                .downcast()
        };
        let pubkey = [2; 33];
        let payload = Bytes::from([1, 2, 3, 4]);
        let payload_hash = Sha256::digest(payload.clone());

        let mut signed_payload = proto::SignedPayload::default();
        assert_eq!(
            payload_err(signed_payload.clone())?,
            ParseSignedPayloadError::InvalidPubKeyLen(0),
        );

        // Set to valid pubkey, but payload and payload hash empty
        signed_payload.pubkey = pubkey.to_vec();
        assert_eq!(
            payload_err(signed_payload.clone())?,
            ParseSignedPayloadError::PayloadHashAndPayloadEmpty,
        );

        // With non-empty payload but empty payload_hash, we get the payload_hash prepared for us
        signed_payload.payload = payload.to_vec();
        assert_eq!(
            SignedPayload::from_proto(signed_payload.clone())?,
            SignedPayload {
                pubkey,
                sig: Bytes::new(),
                sig_scheme: SignatureScheme::Schnorr,
                payload: payload.clone(),
                payload_hash: payload_hash.clone(),
                burn_amount: 0,
                burn_txs: vec![],
            },
        );

        // Payload hash not 32 bytes (or empty)
        signed_payload.payload_hash = vec![1, 2, 3];
        assert_eq!(
            payload_err(signed_payload.clone())?,
            ParseSignedPayloadError::InvalidPayloadHashLen(3),
        );

        // Payload hash incorrect
        signed_payload.payload_hash = vec![7; 32];
        assert_eq!(
            payload_err(signed_payload.clone())?,
            ParseSignedPayloadError::IncorrectPayloadHash {
                expected: payload_hash.clone(),
                actual: Sha256::new([7; 32]),
            },
        );

        {
            // With correct payload_hash, we get the a valid SignedPayload
            signed_payload.payload_hash = payload_hash.as_slice().to_vec();
            let result = SignedPayload::from_proto(signed_payload.clone())?;
            assert_eq!(
                result,
                SignedPayload {
                    pubkey,
                    sig: Bytes::new(),
                    sig_scheme: SignatureScheme::Schnorr,
                    payload: payload.clone(),
                    payload_hash: payload_hash.clone(),
                    burn_amount: 0,
                    burn_txs: vec![],
                },
            );
            // Check if going back to Protobuf works
            assert_eq!(result.to_proto(), signed_payload);
        }

        // Tx fails to parse
        signed_payload.burn_txs = vec![proto::BurnTx {
            tx: b"invalid tx".to_vec(),
            burn_idx: 0,
        }];
        assert_eq!(
            payload_err(signed_payload.clone())?,
            ParseSignedPayloadError::ParsingBurnTxFailed("696e76616c6964207478".to_string()),
        );

        // Tx parses, but the output burn_index points to doesn't exist
        let tx = UnhashedTx {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput {
                value: 1_000_000,
                script: Script::default(),
            }],
            lock_time: 0,
        };
        signed_payload.burn_txs = vec![proto::BurnTx {
            tx: tx.ser().to_vec(),
            burn_idx: 10,
        }];
        assert_eq!(
            payload_err(signed_payload.clone())?,
            ParseSignedPayloadError::NoSuchOutput(10),
        );

        // If burn_amount is 0, it computes the burn_amount for us
        signed_payload.burn_txs[0].burn_idx = 0;
        assert_eq!(
            SignedPayload::from_proto(signed_payload.clone())?,
            SignedPayload {
                pubkey,
                sig: Bytes::new(),
                sig_scheme: SignatureScheme::Schnorr,
                payload: payload.clone(),
                payload_hash: payload_hash.clone(),
                burn_amount: 1_000_000,
                burn_txs: vec![BurnTx {
                    tx: tx.clone().hashed(),
                    burn_output: tx.outputs[0].clone(),
                    burn_idx: 0,
                }],
            },
        );

        // Otherwise, if burn_amount doesn't match exactly, it fails
        signed_payload.burn_amount = 1234;
        assert_eq!(
            payload_err(signed_payload.clone())?,
            ParseSignedPayloadError::TotalBurnAmountMismatch {
                expected: 1234,
                actual: 1_000_000,
            },
        );

        // If set to the correct value, it works
        signed_payload.burn_amount = 1_000_000;
        assert_eq!(
            SignedPayload::from_proto(signed_payload.clone())?,
            SignedPayload {
                pubkey,
                sig: Bytes::new(),
                sig_scheme: SignatureScheme::Schnorr,
                payload: payload.clone(),
                payload_hash: payload_hash.clone(),
                burn_amount: 1_000_000,
                burn_txs: vec![BurnTx {
                    tx: tx.clone().hashed(),
                    burn_output: tx.outputs[0].clone(),
                    burn_idx: 0,
                }],
            },
        );

        // Adding second tx will make it mismatch again
        signed_payload.burn_txs[0].tx = tx.ser().to_vec();
        let tx2 = UnhashedTx {
            version: 1,
            inputs: vec![],
            outputs: vec![
                Default::default(),
                Default::default(),
                TxOutput {
                    value: 234_567,
                    script: Script::default(),
                },
            ],
            lock_time: 0,
        };
        signed_payload.burn_txs.push(proto::BurnTx {
            tx: tx2.ser().to_vec(),
            burn_idx: 2,
        });
        assert_eq!(
            payload_err(signed_payload.clone())?,
            ParseSignedPayloadError::TotalBurnAmountMismatch {
                expected: 1_000_000,
                actual: 1_234_567,
            },
        );

        {
            // If we set the correct value, it works again
            signed_payload.burn_amount = 1_234_567;
            let result = SignedPayload::from_proto(signed_payload.clone())?;
            assert_eq!(
                result,
                SignedPayload {
                    pubkey,
                    sig: Bytes::new(),
                    sig_scheme: SignatureScheme::Schnorr,
                    payload,
                    payload_hash,
                    burn_amount: 1_234_567,
                    burn_txs: vec![
                        BurnTx {
                            tx: tx.clone().hashed(),
                            burn_output: tx.outputs[0].clone(),
                            burn_idx: 0,
                        },
                        BurnTx {
                            tx: tx2.clone().hashed(),
                            burn_output: tx2.outputs[2].clone(),
                            burn_idx: 2,
                        },
                    ],
                },
            );
            // Check if going back to Protobuf works
            assert_eq!(result.to_proto(), signed_payload);
        }

        Ok(())
    }
}
