use crate::protocol::{PrivateCoin, PrivateSpendBundle, ProtocolError};
use crate::ProgramParameter;
use clvm_zk_core::coin_commitment::{CoinCommitment, CoinSecrets};

pub struct Spender;

impl Spender {
    /// spend a coin by proving knowledge of secrets and merkle membership
    pub fn create_spend_with_serial(
        coin: &PrivateCoin,
        puzzle_code: &str,
        solution_params: &[ProgramParameter],
        secrets: &CoinSecrets,
        merkle_path: Vec<[u8; 32]>,
        merkle_root: [u8; 32],
    ) -> Result<PrivateSpendBundle, ProtocolError> {
        coin.validate()
            .map_err(|e| ProtocolError::ProofGenerationFailed(format!("invalid coin: {e}")))?;

        let coin_commitment = CoinCommitment::compute(
            coin.amount,
            &coin.puzzle_hash,
            &coin.serial_commitment,
            crate::crypto_utils::hash_data_default,
        );

        let expected_nullifier = secrets.serial_number;

        let zkvm_result = crate::ClvmZkProver::prove_with_serial_commitment(
            puzzle_code,
            solution_params,
            secrets,
            merkle_path,
            coin_commitment.0,
            coin.serial_commitment.0,
            merkle_root,
            coin.puzzle_hash,
        )
        .map_err(|e| ProtocolError::ProofGenerationFailed(format!("zk proof failed: {e}")))?;

        let actual_nullifier = zkvm_result
            .proof_output
            .nullifier
            .ok_or_else(|| ProtocolError::InvalidNullifier("no nullifier in proof".to_string()))?;

        if actual_nullifier != expected_nullifier {
            return Err(ProtocolError::InvalidNullifier(format!(
                "nullifier mismatch: expected {}, got {}",
                hex::encode(expected_nullifier),
                hex::encode(actual_nullifier)
            )));
        }

        let spend_bundle = PrivateSpendBundle::new(
            zkvm_result.proof_bytes,
            actual_nullifier,
            zkvm_result.proof_output.clvm_res.output.clone(),
        );

        spend_bundle
            .validate()
            .map_err(|e| ProtocolError::ProofGenerationFailed(format!("invalid bundle: {e}")))?;

        Ok(spend_bundle)
    }

    /// verify that a spend bundle contains the expected nullifier
    pub fn verify_nullifier(
        bundle: &PrivateSpendBundle,
        expected_nullifier: &[u8; 32],
    ) -> Result<bool, ProtocolError> {
        bundle
            .validate()
            .map_err(|e| ProtocolError::SerializationError(format!("Invalid bundle: {e}")))?;

        Ok(bundle.nullifier == *expected_nullifier)
    }
}
