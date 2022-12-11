//! Module for verifying a [`crate::payload::SignedPayload`] is valid.

use bitcoinsuite_core::{
    ecc::{Ecc, VerifySignatureError, PUBKEY_LENGTH},
    Bytes, BytesMut, Hashed, Op, Script, Sha256,
};
use bitcoinsuite_error::{ErrorMeta, Result, WrapErr};
use thiserror::Error;

use crate::payload::{SignatureScheme, SignedPayload};

/// LOKAD ID of commitment burns for address metadata
pub const ADDRESS_METADATA_LOKAD_ID: [u8; 4] = *b"STMP";

/// Opcode that indicates the version of the commitment.
pub const COMMITMENT_VERSION_OPCODE: u8 = 0x51;
/// Required length of the commitment.
pub const COMMITMENT_LEN: u8 = 32;

/// Error indicating why a [`crate::payload::SignedPayload`] is invalid.
#[derive(Debug, Error, ErrorMeta, PartialEq, Eq)]
pub enum ValidateSignedPayloadError {
    /// Burn output is not OP_RETURN.
    #[invalid_client_input()]
    #[error("Burn tx output script is not OP_RETURN: {0}")]
    BurnOutputNotOpReturn(String),

    /// Parsing burn output script failed.
    #[invalid_client_input()]
    #[error("Parsing burn tx output script failed: {0}")]
    ParsingBurnOutputScriptFailed(String),

    /// Burn output has to have 4 ops.
    #[invalid_client_input()]
    #[error("Burn tx output expected 4 ops, but got {0} ops.")]
    BurnOutputTooFewOps(usize),

    /// LOKAD prefix is not STMP.
    #[invalid_client_input()]
    #[error(
        "Burn tx output script expected LOKAD ID {:?} but got op {0:?}",
        Bytes::from(ADDRESS_METADATA_LOKAD_ID)
    )]
    BurnOutputInvalidLokadId(Op),

    /// Version opcode is not OP_1.
    #[invalid_client_input()]
    #[error(
        "Burn tx output script expected version opcode {:02x} but got op {0:?}",
        COMMITMENT_VERSION_OPCODE
    )]
    BurnOutputInvalidVersion(Op),

    /// Burn output commitment is not 32 bytes long.
    #[invalid_client_input()]
    #[error(
        "Burn tx output script expected commitment length {} but got op {0:?}",
        COMMITMENT_LEN
    )]
    BurnOutputInvalidCommitmentLength(Op),

    /// Burn output commitment is incorrect.
    #[invalid_client_input()]
    #[error("Burn tx {burn_tx_idx} commitment mismatch: expected {expected}, but got {actual}")]
    BurnOutputCommitmentMismatch {
        /// Expected commitment in the burn output.
        expected: Sha256,
        /// Actual commitment from the `pubkey` and `payload_hash`.
        actual: Sha256,
        /// Index of the invalid tx.
        burn_tx_idx: usize,
    },

    /// `pubkey` is not valid.
    #[invalid_client_input()]
    #[error("Invalid secp256k1 pubkey: {0}")]
    InvalidPubKey(String),

    /// `sig` is not a valid/correct Schnorr signature.
    #[invalid_client_input()]
    #[error("Invalid payload Schnorr signature: {0}")]
    InvalidSchnorrSignature(VerifySignatureError),

    /// `sig` is not a valid/correct ECDSA signature.
    #[invalid_client_input()]
    #[error("Invalid payload ECDSA signature: {0}")]
    InvalidEcdsaSignature(VerifySignatureError),
}

use self::ValidateSignedPayloadError::*;

impl<T> SignedPayload<T> {
    /// Validates that the [`crate::proto::SignedPayload`] burns the claimed amount to the corrent commitments.
    ///
    /// Burn output script must look like this:
    /// `OP_RETURN <lokad_id: STMP> <version: 1> <commitment: 32 bytes>`
    pub fn verify(&self, ecc: &impl Ecc, commitment_id: [u8; 4]) -> Result<()> {
        // Verify OP_RETURN commitments
        let expected_commitment = calc_commitment(self.pubkey, &self.payload_hash);
        for (idx, burn_tx) in self.burn_txs.iter().enumerate() {
            let parsed_commitment = parse_commitment(commitment_id, &burn_tx.burn_output.script)?;
            if expected_commitment != parsed_commitment {
                return Err(BurnOutputCommitmentMismatch {
                    expected: expected_commitment,
                    actual: parsed_commitment,
                    burn_tx_idx: idx,
                }
                .into());
            }
        }

        // Verify signature signs payload hash
        let pubkey = ecc
            .pubkey_from_array(self.pubkey)
            .wrap_err_with(|| InvalidPubKey(hex::encode(&self.pubkey)))?;
        let msg = self.payload_hash.byte_array().clone();
        match self.sig_scheme {
            SignatureScheme::Schnorr => ecc
                .schnorr_verify(&pubkey, msg, &self.sig)
                .map_err(InvalidSchnorrSignature)?,
            SignatureScheme::Ecdsa => ecc
                .verify(&pubkey, msg, &self.sig)
                .map_err(InvalidEcdsaSignature)?,
        }

        Ok(())
    }
}

/// Build the burn [`bitcoinsuite_core::Script`] for the given pubkey and payload hash.
pub fn build_commitment_script(
    commitment_id: [u8; 4],
    pubkey_raw: [u8; PUBKEY_LENGTH],
    payload_hash: &Sha256,
) -> Script {
    let commitment = calc_commitment(pubkey_raw, payload_hash);
    Script::from_ops(
        vec![
            Op::Code(0x6a),
            Op::Push(4, commitment_id.into()),
            Op::Code(COMMITMENT_VERSION_OPCODE),
            Op::Push(COMMITMENT_LEN, commitment.as_slice().into()),
        ]
        .into_iter(),
    )
    .unwrap()
}

fn parse_commitment(commitment_id: [u8; 4], script: &Script) -> Result<Sha256> {
    // Must be OP_RETURN
    if !script.is_opreturn() {
        return Err(BurnOutputNotOpReturn(script.hex()).into());
    }
    let script_ops = script
        .ops()
        .map(|op| op.map_err(Into::into))
        .collect::<Result<Vec<_>>>()
        .wrap_err_with(|| ParsingBurnOutputScriptFailed(script.hex()))?;

    // OP_RETURN <lokad_id: STMP> <version: 1> <commitment: 32 bytes>
    if script_ops.len() != 4 {
        return Err(BurnOutputTooFewOps(script_ops.len()).into());
    }

    // Check LOKAD ID
    if script_ops[1] != Op::Push(4, commitment_id.into()) {
        return Err(BurnOutputInvalidLokadId(script_ops[1].clone()).into());
    }

    // Check version (must be OP_1)
    if script_ops[2] != Op::Code(COMMITMENT_VERSION_OPCODE) {
        return Err(BurnOutputInvalidVersion(script_ops[2].clone()).into());
    }

    // Extract commitment
    let commitment = match &script_ops[3] {
        Op::Push(COMMITMENT_LEN, commitment) => commitment,
        _ => return Err(BurnOutputInvalidCommitmentLength(script_ops[3].clone()).into()),
    };

    Ok(Sha256::new(commitment.as_ref().try_into().unwrap()))
}

fn calc_commitment(pubkey_raw: [u8; PUBKEY_LENGTH], payload_hash: &Sha256) -> Sha256 {
    let pubkey_hash = Sha256::digest(pubkey_raw.into());
    let mut commitment_preimage = BytesMut::new();
    commitment_preimage.put_byte_array(pubkey_hash.byte_array().clone());
    commitment_preimage.put_byte_array(payload_hash.byte_array().clone());
    Sha256::digest(commitment_preimage.freeze())
}

#[cfg(test)]
mod tests {
    use bitcoinsuite_core::{
        ecc::{Ecc, VerifySignatureError, PUBKEY_LENGTH},
        ByteArray, Bytes, Hashed, Op, Script, Sha256, TxOutput, UnhashedTx,
    };
    use bitcoinsuite_ecc_secp256k1::EccSecp256k1;
    use bitcoinsuite_error::Result;
    use pretty_assertions::assert_eq;

    use crate::{
        payload::{BurnTx, SignatureScheme, SignedPayload},
        verify::{
            calc_commitment,
            ValidateSignedPayloadError::{self, *},
            ADDRESS_METADATA_LOKAD_ID,
        },
    };

    #[test]
    fn test_verify_signed_payload() -> Result<()> {
        let ecc = EccSecp256k1::default();
        let verify_err = |payload: &SignedPayload<()>| -> Result<ValidateSignedPayloadError> {
            payload
                .verify(&ecc, ADDRESS_METADATA_LOKAD_ID)
                .unwrap_err()
                .downcast()
        };
        let payload_raw = Bytes::from([1, 2, 3, 4]);
        let payload_hash = Sha256::digest(payload_raw.clone());
        let pubkey = [0x77; PUBKEY_LENGTH];
        let commitment_hash = Sha256::digest(
            [
                Sha256::digest(pubkey.as_slice().into()).as_slice(),
                payload_hash.as_slice(),
            ]
            .concat()
            .into(),
        );
        let commitment_hash_raw = Bytes::from_slice(commitment_hash.as_slice());
        let commitment_script = Script::from_ops(
            vec![
                Op::Code(0x6a),
                Op::Push(4, Bytes::from(*b"STMP")),
                Op::Code(0x51),
                Op::Push(32, commitment_hash_raw),
            ]
            .into_iter(),
        )?;

        let mut signed_payload = SignedPayload {
            payload: None,
            pubkey,
            sig: Bytes::new(),
            sig_scheme: SignatureScheme::Schnorr,
            payload_raw: Some(payload_raw),
            payload_hash: payload_hash.clone(),
            burn_amount: 0,
            burn_txs: vec![],
        };

        let tx = UnhashedTx {
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput {
                value: 0,
                script: Script::default(),
            }],
            lock_time: 0,
        };

        // Burn output not OP_RETURN
        signed_payload.burn_txs = vec![BurnTx {
            tx: tx.clone().hashed(),
            burn_idx: 0,
            burn_output: tx.outputs[0].clone(),
        }];
        assert_eq!(
            verify_err(&signed_payload)?,
            BurnOutputNotOpReturn("".to_string()),
        );

        // Burn script fails to parse
        signed_payload.burn_txs[0].burn_output.script = Script::from_hex("6a0f")?;
        assert_eq!(
            verify_err(&signed_payload)?,
            ParsingBurnOutputScriptFailed("6a0f".to_string()),
        );

        // Too few ops, expected 4 but got 2
        signed_payload.burn_txs[0].burn_output.script = Script::from_hex("6a00")?;
        assert_eq!(verify_err(&signed_payload)?, BurnOutputTooFewOps(2),);

        // Invalid LOKAD ID, should be STMP
        signed_payload.burn_txs[0].burn_output.script = Script::from_hex("6a515253")?;
        assert_eq!(
            verify_err(&signed_payload)?,
            BurnOutputInvalidLokadId(Op::Code(0x51)),
        );

        // Invalid version, should be OP_1
        signed_payload.burn_txs[0].burn_output.script = Script::from_ops(
            vec![
                Op::Code(0x6a),
                Op::Push(4, Bytes::from(*b"STMP")),
                Op::Code(0x52),
                Op::Code(0x53),
            ]
            .into_iter(),
        )?;
        assert_eq!(
            verify_err(&signed_payload)?,
            BurnOutputInvalidVersion(Op::Code(0x52)),
        );

        // Invalid commitment length, must be 32
        signed_payload.burn_txs[0].burn_output.script = Script::from_ops(
            vec![
                Op::Code(0x6a),
                Op::Push(4, Bytes::from(*b"STMP")),
                Op::Code(0x51),
                Op::Code(0x53),
            ]
            .into_iter(),
        )?;
        assert_eq!(
            verify_err(&signed_payload)?,
            BurnOutputInvalidCommitmentLength(Op::Code(0x53)),
        );

        // Invalid commitment
        signed_payload.burn_txs[0].burn_output.script = Script::from_ops(
            vec![
                Op::Code(0x6a),
                Op::Push(4, Bytes::from(*b"STMP")),
                Op::Code(0x51),
                Op::Push(32, vec![4; 32].into()),
            ]
            .into_iter(),
        )?;
        assert_eq!(
            verify_err(&signed_payload)?,
            BurnOutputCommitmentMismatch {
                expected: commitment_hash.clone(),
                actual: Sha256::new([4; 32]),
                burn_tx_idx: 0,
            },
        );

        // First commitment valid, second invalid
        signed_payload.burn_txs[0].burn_output.script = commitment_script.clone();
        let tx2 = UnhashedTx {
            version: 1,
            inputs: vec![],
            outputs: vec![
                Default::default(),
                Default::default(),
                TxOutput {
                    value: 234_567,
                    script: Script::from_ops(
                        vec![
                            Op::Code(0x6a),
                            Op::Push(4, Bytes::from(*b"STMP")),
                            Op::Code(0x51),
                            Op::Push(32, vec![5; 32].into()),
                        ]
                        .into_iter(),
                    )?,
                },
            ],
            lock_time: 0,
        };
        signed_payload.burn_txs.push(BurnTx {
            burn_output: tx2.outputs[2].clone(),
            tx: tx2.hashed(),
            burn_idx: 2,
        });
        assert_eq!(
            verify_err(&signed_payload)?,
            BurnOutputCommitmentMismatch {
                expected: commitment_hash,
                actual: Sha256::new([5; 32]),
                burn_tx_idx: 1,
            },
        );

        // Fix the commitment, pubkey invalid now
        signed_payload.burn_txs[1].burn_output.script = commitment_script;
        assert_eq!(
            verify_err(&signed_payload)?,
            InvalidPubKey(
                "777777777777777777777777777777777777777777777777777777777777777777".to_string()
            ),
        );

        // Fix pubkey (and commitment)
        let seckey = ecc.seckey_from_array([0x44; 32])?;
        let pubkey = ecc.derive_pubkey(&seckey).array();
        let commitment_hash = calc_commitment(pubkey, &payload_hash);
        let commitment_hash_raw = Bytes::from_slice(commitment_hash.as_slice());
        let commitment_script = Script::from_ops(
            vec![
                Op::Code(0x6a),
                Op::Push(4, Bytes::from(*b"STMP")),
                Op::Code(0x51),
                Op::Push(32, commitment_hash_raw),
            ]
            .into_iter(),
        )?;
        signed_payload.pubkey = pubkey;
        signed_payload.burn_txs[0].burn_output.script = commitment_script.clone();
        signed_payload.burn_txs[1].burn_output.script = commitment_script;
        // Now, Schnorr signature is invalid format (is empty)
        assert_eq!(
            verify_err(&signed_payload)?,
            InvalidSchnorrSignature(VerifySignatureError::InvalidFormat),
        );

        // Same for ECDSA
        signed_payload.sig_scheme = SignatureScheme::Ecdsa;
        assert_eq!(
            verify_err(&signed_payload)?,
            InvalidEcdsaSignature(VerifySignatureError::InvalidFormat),
        );

        // Valid Schnorr format (64 bytes), but incorrect signature
        signed_payload.sig_scheme = SignatureScheme::Schnorr;
        signed_payload.sig = Bytes::from([0x88; 64]);
        assert_eq!(
            verify_err(&signed_payload)?,
            InvalidSchnorrSignature(VerifySignatureError::IncorrectSignature),
        );

        // Valid Schnorr format (64 bytes), but signing incorrect data
        signed_payload.sig = ecc.schnorr_sign(&seckey, ByteArray::new([54; 32]));
        assert_eq!(
            verify_err(&signed_payload)?,
            InvalidSchnorrSignature(VerifySignatureError::IncorrectSignature),
        );

        // Valid ECDSA format, but signing incorrect data
        signed_payload.sig_scheme = SignatureScheme::Ecdsa;
        signed_payload.sig = ecc.sign(&seckey, ByteArray::new([54; 32]));
        assert_eq!(
            verify_err(&signed_payload)?,
            InvalidEcdsaSignature(VerifySignatureError::IncorrectSignature),
        );

        // Correct signatures
        let ecdsa_sig = ecc.sign(&seckey, signed_payload.payload_hash.byte_array().clone());
        let schnorr_sig =
            ecc.schnorr_sign(&seckey, signed_payload.payload_hash.byte_array().clone());

        // Provide ECDSA sig but Schorr requested
        signed_payload.sig_scheme = SignatureScheme::Schnorr;
        signed_payload.sig = ecdsa_sig.clone();
        assert_eq!(
            verify_err(&signed_payload)?,
            InvalidSchnorrSignature(VerifySignatureError::InvalidFormat),
        );

        // Provide Schnorr sig but ECDSA requested
        signed_payload.sig_scheme = SignatureScheme::Ecdsa;
        signed_payload.sig = schnorr_sig.clone();
        assert_eq!(
            verify_err(&signed_payload)?,
            InvalidEcdsaSignature(VerifySignatureError::InvalidFormat),
        );

        // Correct sig: Schnorr
        signed_payload.sig_scheme = SignatureScheme::Schnorr;
        signed_payload.sig = schnorr_sig;
        signed_payload.verify(&ecc, ADDRESS_METADATA_LOKAD_ID)?;

        // Correct sig: ECDSA
        signed_payload.sig_scheme = SignatureScheme::Ecdsa;
        signed_payload.sig = ecdsa_sig;
        signed_payload.verify(&ecc, ADDRESS_METADATA_LOKAD_ID)?;

        Ok(())
    }
}
