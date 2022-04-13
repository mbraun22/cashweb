//! Contains `PubKeyHash`, abstracting different public key hashes.

use std::fmt::Display;

use bitcoinsuite_core::{Bytes, Hashed, LotusAddress, Net, ScriptVariant, ShaRmd160, LOTUS_PREFIX};
use bitcoinsuite_error::{ErrorMeta, Result};
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

    /// Provided string doesn't name a known [`PkhAlgorithm`].
    #[invalid_client_input()]
    #[error("Invalid public key hash algorithm {0:?}, expected \"p2pkh\"")]
    InvalidPkhAlgorithm(String),

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
}

use self::PkhError::*;

impl PkhAlgorithm {
    pub(crate) fn to_storage_byte(self) -> u8 {
        match self {
            PkhAlgorithm::Sha256Ripemd160 => 1,
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

#[cfg(test)]
mod tests {
    use bitcoinsuite_error::Result;

    use crate::store::pubkeyhash::{PkhAlgorithm, PkhError, PubKeyHash};

    #[test]
    fn test_pkh_algorithm() -> Result<()> {
        let _ = bitcoinsuite_error::install();
        assert_eq!(PkhAlgorithm::Sha256Ripemd160.hash_len(), 20);
        assert_eq!(PkhAlgorithm::Sha256Ripemd160.to_storage_byte(), 1);
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
