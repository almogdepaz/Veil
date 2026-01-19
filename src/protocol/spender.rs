use crate::protocol::{PrivateCoin, PrivateSpendBundle, ProtocolError};
use crate::ProgramParameter;
use clvm_zk_core::coin_commitment::{CoinCommitment, CoinSecrets, XCH_TAIL};
use clvm_zk_core::{AdditionalCoinInput, SerialCommitmentData};

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
        leaf_index: usize,
    ) -> Result<PrivateSpendBundle, ProtocolError> {
        coin.validate()
            .map_err(|e| ProtocolError::ProofGenerationFailed(format!("invalid coin: {e}")))?;

        let coin_commitment = CoinCommitment::compute(
            &coin.tail_hash,
            coin.amount,
            &coin.puzzle_hash,
            &coin.serial_commitment,
            crate::crypto_utils::hash_data_default,
        );

        // pass tail_hash: None for XCH, Some for CATs
        let tail_hash = if coin.tail_hash == XCH_TAIL {
            None
        } else {
            Some(coin.tail_hash)
        };

        let zkvm_result = crate::ClvmZkProver::prove_with_serial_commitment(
            puzzle_code,
            solution_params,
            secrets,
            merkle_path,
            coin_commitment.0,
            coin.serial_commitment.0,
            merkle_root,
            leaf_index,
            coin.puzzle_hash,
            coin.amount,
            tail_hash,
        )
        .map_err(|e| ProtocolError::ProofGenerationFailed(format!("zk proof failed: {e}")))?;

        // single-coin spend should have exactly one nullifier
        if zkvm_result.proof_output.nullifiers.is_empty() {
            return Err(ProtocolError::InvalidNullifier(
                "no nullifier in proof".to_string(),
            ));
        }

        let spend_bundle = PrivateSpendBundle::new(
            zkvm_result.proof_bytes,
            zkvm_result.proof_output.nullifiers,
            zkvm_result.proof_output.clvm_res.output.clone(),
        );

        spend_bundle
            .validate()
            .map_err(|e| ProtocolError::ProofGenerationFailed(format!("invalid bundle: {e}")))?;

        Ok(spend_bundle)
    }

    /// spend multiple coins in a ring (for CAT multi-coin transactions)
    ///
    /// all coins must have the same tail_hash
    /// returns a single spend bundle with multiple nullifiers
    #[allow(clippy::type_complexity)]
    pub fn create_ring_spend(
        coins: Vec<(
            &PrivateCoin,
            &str,                // puzzle_code
            &[ProgramParameter], // solution_params
            &CoinSecrets,
            Vec<[u8; 32]>, // merkle_path
            usize,         // leaf_index
        )>,
        merkle_root: [u8; 32],
    ) -> Result<PrivateSpendBundle, ProtocolError> {
        eprintln!("\n=== SPENDER: CREATE_RING_SPEND ===");
        eprintln!("  num_coins: {}", coins.len());
        eprintln!("  merkle_root: {}", hex::encode(merkle_root));

        if coins.is_empty() {
            return Err(ProtocolError::ProofGenerationFailed(
                "no coins to spend".to_string(),
            ));
        }

        // verify all coins have the same tail_hash
        let primary_tail = coins[0].0.tail_hash;
        for (coin, _, _, _, _, _) in &coins {
            if coin.tail_hash != primary_tail {
                return Err(ProtocolError::ProofGenerationFailed(
                    "all coins in ring must have same tail_hash".to_string(),
                ));
            }
        }

        // primary coin (first one)
        let (
            primary_coin,
            primary_puzzle,
            primary_params,
            primary_secrets,
            primary_path,
            primary_leaf_idx,
        ) = &coins[0];

        primary_coin.validate().map_err(|e| {
            ProtocolError::ProofGenerationFailed(format!("invalid primary coin: {e}"))
        })?;

        let primary_coin_commitment = CoinCommitment::compute(
            &primary_coin.tail_hash,
            primary_coin.amount,
            &primary_coin.puzzle_hash,
            &primary_coin.serial_commitment,
            crate::crypto_utils::hash_data_default,
        );

        eprintln!("\n  --- PRIMARY COIN (idx 0) ---");
        eprintln!("    tail_hash: {}", hex::encode(primary_coin.tail_hash));
        eprintln!("    amount: {}", primary_coin.amount);
        eprintln!("    puzzle_hash: {}", hex::encode(primary_coin.puzzle_hash));
        eprintln!(
            "    serial_commitment: {}",
            hex::encode(primary_coin.serial_commitment.as_bytes())
        );
        eprintln!(
            "    coin_commitment: {}",
            hex::encode(primary_coin_commitment.0)
        );
        eprintln!("    leaf_index: {}", primary_leaf_idx);
        eprintln!("    merkle_path length: {}", primary_path.len());

        // pass tail_hash: None for XCH, Some for CATs
        let tail_hash = if primary_tail == XCH_TAIL {
            None
        } else {
            Some(primary_tail)
        };

        // construct additional_coins for ring
        let mut additional_coins = Vec::new();
        for (i, (coin, puzzle_code, params, secrets, merkle_path, leaf_index)) in
            coins.iter().skip(1).enumerate()
        {
            coin.validate().map_err(|e| {
                ProtocolError::ProofGenerationFailed(format!("invalid coin in ring: {e}"))
            })?;

            let coin_commitment = CoinCommitment::compute(
                &coin.tail_hash,
                coin.amount,
                &coin.puzzle_hash,
                &coin.serial_commitment,
                crate::crypto_utils::hash_data_default,
            );

            eprintln!("\n  --- ADDITIONAL COIN (idx {}) ---", i + 1);
            eprintln!("    tail_hash: {}", hex::encode(coin.tail_hash));
            eprintln!("    amount: {}", coin.amount);
            eprintln!("    puzzle_hash: {}", hex::encode(coin.puzzle_hash));
            eprintln!(
                "    serial_commitment: {}",
                hex::encode(coin.serial_commitment.as_bytes())
            );
            eprintln!("    coin_commitment: {}", hex::encode(coin_commitment.0));
            eprintln!("    leaf_index: {}", leaf_index);
            eprintln!("    merkle_path length: {}", merkle_path.len());
            eprintln!(
                "    secrets.serial_number: {}",
                hex::encode(secrets.serial_number)
            );

            additional_coins.push(AdditionalCoinInput {
                chialisp_source: puzzle_code.to_string(),
                program_parameters: params.to_vec(),
                serial_commitment_data: SerialCommitmentData {
                    serial_number: secrets.serial_number,
                    serial_randomness: secrets.serial_randomness,
                    merkle_path: merkle_path.clone(),
                    coin_commitment: coin_commitment.0,
                    serial_commitment: coin.serial_commitment.0,
                    merkle_root,
                    leaf_index: *leaf_index,
                    program_hash: coin.puzzle_hash,
                    amount: coin.amount,
                },
                tail_hash: coin.tail_hash,
            });
        }

        let primary_serial_data = SerialCommitmentData {
            serial_number: primary_secrets.serial_number,
            serial_randomness: primary_secrets.serial_randomness,
            merkle_path: primary_path.clone(),
            coin_commitment: primary_coin_commitment.0,
            serial_commitment: primary_coin.serial_commitment.0,
            merkle_root,
            leaf_index: *primary_leaf_idx,
            program_hash: primary_coin.puzzle_hash,
            amount: primary_coin.amount,
        };

        let zkvm_result = crate::ClvmZkProver::prove_ring_spend(
            primary_puzzle,
            primary_params,
            primary_serial_data,
            tail_hash,
            additional_coins,
        )
        .map_err(|e| ProtocolError::ProofGenerationFailed(format!("zk ring proof failed: {e}")))?;

        // for ring spends, we should have N nullifiers (one per coin)
        if zkvm_result.proof_output.nullifiers.len() != coins.len() {
            return Err(ProtocolError::InvalidNullifier(format!(
                "ring proof should have {} nullifiers but has {}",
                coins.len(),
                zkvm_result.proof_output.nullifiers.len()
            )));
        }

        let spend_bundle = PrivateSpendBundle::new(
            zkvm_result.proof_bytes,
            zkvm_result.proof_output.nullifiers,
            zkvm_result.proof_output.clvm_res.output.clone(),
        );

        spend_bundle.validate().map_err(|e| {
            ProtocolError::ProofGenerationFailed(format!("invalid ring bundle: {e}"))
        })?;

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

        Ok(bundle.nullifiers.contains(expected_nullifier))
    }
}
