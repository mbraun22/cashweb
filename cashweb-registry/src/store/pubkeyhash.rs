//! Contains `PubKeyHash`, abstracting different public key hashes.

use std::fmt::Display;

use bitcoinsuite_core::{
    Bytes, Hashed, LotusAddress, Net, Script, ScriptVariant, ShaRmd160, LOTUS_PREFIX,
};
use bitcoinsuite_error::{ErrorMeta, Result, WrapErr};
use thiserror::Error;

/// Hash algorithm supported by the keyserver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PkhAlgorithm {
    /// SHA-256 of the pkh followed by RIPEMD-160.
    /// This is the normal pkh hashing algorithm used by Bitcoin chains.
    Sha256Ripemd160,
}

/// Struct containing a public key hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PubKeyHash {
    algorithm: PkhAlgorithm,
    hash: Bytes,
}

/// Struct containing a timestamp and a public key hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TimePkh {
    /// Timestamp of the pair.
    pub timestamp: i64,
    /// Public key hash of the pair.
    pub pkh: PubKeyHash,
}

/// Errors relating to `PubKeyHash`.
#[derive(Debug, Error, ErrorMeta, Clone, PartialEq)]
pub enum PkhError {
    /// Invalid hash length given the algorithm.
    #[invalid_client_input()]
    #[error("Algorithm {algorithm} expects length {expected}, but hash has length {actual}")]
    InvalidAlgorithmHashLength {
        /// Algorithm used hashing.
        algorithm: PkhAlgorithm,
        /// Expected length of the hash, determined by the algorithm.
        expected: usize,
        /// Actual length of the given hash.
        actual: usize,
    },

    /// Invalid lotus address in request.
    #[invalid_user_input()]
    #[error("Invalid address prefix, expected {expected:?} but got {actual:?}")]
    InvalidAddressPrefix {
        /// Prefix expected by the server.
        expected: String,
        /// Prefix encoded in the address.
        actual: String,
    },

    /// Invalid lotus address in request.
    #[invalid_user_input()]
    #[error("Invalid address net, expected {expected:?} but got {actual:?}")]
    InvalidAddressNet {
        /// Net expected by the server.
        expected: Net,
        /// Net encoded in the address.
        actual: Net,
    },

    /// Invalid lotus address in request.
    #[invalid_client_input()]
    #[error("Unsupported address script variant: {0:?}")]
    UnsupportedScriptVariant(ScriptVariant),

    /// Invalid byte for [`PkhAlgorithm`].
    #[critical()]
    #[error("Invalid byte for PkhAlgorithm: {0}")]
    InvalidPkhAlgorithmByte(u8),

    /// Timestamp in [`TimePkh`] failed to decode.
    #[critical()]
    #[error("TimePkh timestamp failed to decode")]
    InvalidTimePkhTimestamp,

    /// [`PkhAlgorithm`] in [`TimePkh`] failed to decode.
    #[critical()]
    #[error("TimePkh PkhAlgorithm failed to decode")]
    InvalidTimePkhAlgorithm,
}

use self::PkhError::*;

impl PkhAlgorithm {
    pub(crate) fn to_storage_byte(self) -> u8 {
        match self {
            PkhAlgorithm::Sha256Ripemd160 => 1,
        }
    }

    pub(crate) fn from_storage_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(PkhAlgorithm::Sha256Ripemd160),
            _ => None,
        }
    }

    /// Length of this hashing algorithm.
    pub fn hash_len(&self) -> usize {
        match self {
            PkhAlgorithm::Sha256Ripemd160 => ShaRmd160::size(),
        }
    }

    /// Create a [`PubKeyHash`] by hashing `pubkey` with this hashing algorithm.
    pub fn hash_pubkey(self, pubkey: [u8; 33]) -> PubKeyHash {
        match self {
            PkhAlgorithm::Sha256Ripemd160 => PubKeyHash {
                algorithm: self,
                hash: ShaRmd160::digest(pubkey.into())
                    .byte_array()
                    .to_vec()
                    .into(),
            },
        }
    }
}

impl PubKeyHash {
    /// Constructs a new `PubKeyHash`.
    /// Returns `InvalidAlgorithmHashLength` if hash's length doesn't match algorithm's hash length.
    pub fn new(algorithm: PkhAlgorithm, hash: Bytes) -> Result<Self> {
        if algorithm.hash_len() != hash.len() {
            return Err(InvalidAlgorithmHashLength {
                algorithm,
                expected: algorithm.hash_len(),
                actual: hash.len(),
            }
            .into());
        }
        Ok(PubKeyHash { algorithm, hash })
    }

    /// Validate and extract a [`PubKeyHash`] from a [`LotusAddress`].
    pub fn from_address(address: &LotusAddress, expected_net: Net) -> Result<Self> {
        if address.prefix() != LOTUS_PREFIX {
            return Err(InvalidAddressPrefix {
                expected: LOTUS_PREFIX.to_string(),
                actual: address.prefix().to_string(),
            }
            .into());
        }
        if address.net() != expected_net {
            return Err(InvalidAddressNet {
                expected: expected_net,
                actual: address.net(),
            }
            .into());
        }
        match address.script().parse_variant() {
            ScriptVariant::P2PKH(hash) => {
                PubKeyHash::new(PkhAlgorithm::Sha256Ripemd160, hash.as_slice().into())
            }
            variant => Err(UnsupportedScriptVariant(variant).into()),
        }
    }

    /// Map the PubKeyHash to the corresponding Lotus address.
    pub fn to_address(&self, net: Net) -> LotusAddress {
        match self.algorithm {
            PkhAlgorithm::Sha256Ripemd160 => LotusAddress::new(
                LOTUS_PREFIX,
                net,
                Script::p2pkh(&ShaRmd160::from_slice(&self.hash).expect("Impossible hash length")),
            ),
        }
    }

    /// Hashing algorithm used by this [`PubKeyHash`].
    pub fn algorithm(&self) -> PkhAlgorithm {
        self.algorithm
    }

    /// Bytes of the hash of this [`PubKeyHash`].
    pub fn hash(&self) -> &Bytes {
        &self.hash
    }

    pub(crate) fn to_storage_bytes(&self) -> Bytes {
        let mut bytes = Vec::with_capacity(self.hash.len() + 1);
        bytes.push(self.algorithm.to_storage_byte());
        bytes.extend_from_slice(&self.hash);
        bytes.into()
    }
}

impl Display for PkhAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl TimePkh {
    pub(crate) fn to_storage_bytes(&self) -> Bytes {
        let mut bytes = Vec::with_capacity(self.pkh.hash().len() + 9);
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.push(self.pkh.algorithm().to_storage_byte());
        bytes.extend_from_slice(self.pkh.hash());
        bytes.into()
    }

    pub(crate) fn from_storage_bytes(mut bytes: Bytes) -> Result<Self> {
        let timestamp: [u8; 8] = bytes
            .split_to(8)
            .wrap_err(InvalidTimePkhTimestamp)?
            .as_ref()
            .try_into()
            .unwrap();
        let timestamp = i64::from_be_bytes(timestamp);
        let pkh_algorithm = bytes.split_to(1).wrap_err(InvalidTimePkhAlgorithm)?[0];
        let pkh_algorithm = PkhAlgorithm::from_storage_byte(pkh_algorithm)
            .ok_or(InvalidPkhAlgorithmByte(pkh_algorithm))?;
        let pkh = PubKeyHash::new(pkh_algorithm, bytes)?;
        Ok(TimePkh { timestamp, pkh })
    }
}

#[cfg(test)]
mod tests {
    use bitcoinsuite_error::Result;

    use crate::store::pubkeyhash::{PkhAlgorithm, PkhError, PubKeyHash};

    #[test]
    fn test_pkh_algorithm() -> Result<()> {
        let _ = bitcoinsuite_error::install();
        assert_eq!(PkhAlgorithm::Sha256Ripemd160.hash_len(), 20);
        assert_eq!(PkhAlgorithm::Sha256Ripemd160.to_storage_byte(), 1);
        assert_eq!(
            PkhAlgorithm::from_storage_byte(1),
            Some(PkhAlgorithm::Sha256Ripemd160),
        );
        assert_eq!(PkhAlgorithm::from_storage_byte(0), None);
        Ok(())
    }

    #[test]
    fn test_pub_key_hash_new() -> Result<()> {
        let _ = bitcoinsuite_error::install();
        assert_eq!(
            PubKeyHash::new(PkhAlgorithm::Sha256Ripemd160, [7; 20].into())?,
            PubKeyHash {
                algorithm: PkhAlgorithm::Sha256Ripemd160,
                hash: [7; 20].into(),
            },
        );
        assert_eq!(
            PubKeyHash::new(PkhAlgorithm::Sha256Ripemd160, [7; 19].into())
                .unwrap_err()
                .downcast::<PkhError>()?,
            PkhError::InvalidAlgorithmHashLength {
                algorithm: PkhAlgorithm::Sha256Ripemd160,
                expected: 20,
                actual: 19,
            },
        );
        Ok(())
    }

    #[test]
    fn test_pub_key_hash_storage() -> Result<()> {
        let _ = bitcoinsuite_error::install();
        assert_eq!(
            PubKeyHash {
                algorithm: PkhAlgorithm::Sha256Ripemd160,
                hash: [7; 20].into(),
            }
            .to_storage_bytes()
            .as_ref(),
            [[1].as_ref(), &[7; 20]].concat(),
        );
        Ok(())
    }
}
