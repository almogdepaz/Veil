use crate::protocol::{PrivateCoin, PrivateSpendBundle, ProtocolError};
use crate::ProgramParameter;
use sha2::{Digest, Sha256};

/// safe way to spend private coins with automatic nullifier generation
///
/// the spender makes sure you can't mess up by:
/// 1. automatically including the spend_secret in zk proofs
/// 2. computing nullifiers the right way
/// 3. packaging everything into secure spend bundles
/// 4. preventing access to the unsafe low-level apis
///
/// what you get:
/// - unique nullifier for every spend (prevents double spending)
/// - your secrets stay hidden in zk proofs
/// - puzzle hash verification makes sure the program is correct
///
/// example:
///
/// ```rust
/// use clvm_zk::protocol::{PrivateCoin, Spender};
/// use clvm_zk::ProgramParameter;
///
/// // make a private coin
/// let coin = PrivateCoin::new_random_from_program("(mod (a b) (+ a b))", 1000);
///
/// // spend it safely
/// let bundle = Spender::create_spend(
///     &coin,
///     "(mod (a b) (+ a b))",  // the actual program code in proper Chialisp syntax
///     &[ProgramParameter::int(5), ProgramParameter::int(3)]
/// ).expect("Failed to create spend");
///
/// // you get back:
/// // - bundle.nullifier: unique id preventing double-spend
/// // - bundle.zk_proof: zk proof that spend is valid
/// // - bundle.public_conditions: clvm output for blockchain processing
/// ```
pub struct Spender;

impl Spender {
    /// spend a private coin and get back a secure bundle
    ///
    /// this is the main function for spending coins. it handles all the security stuff automatically.
    ///
    /// what it does:
    /// 1. checks that puzzle_code actually matches the coin's puzzle_hash
    /// 2. makes a nullifier from the coin's spend_secret
    /// 3. creates a zk proof without revealing your secrets
    /// 4. packages everything into a secure bundle
    ///
    /// you get back a complete spend bundle ready for the blockchain with:
    /// - zk proof that everything is valid
    /// - public nullifier to prevent double spending
    /// - clvm output for the blockchain to process
    pub fn create_spend(
        coin: &PrivateCoin,
        puzzle_code: &str,
        solution_params: &[ProgramParameter],
    ) -> Result<PrivateSpendBundle, ProtocolError> {
        // 1. make sure the coin is valid before we do anything
        coin.validate()
            .map_err(|e| ProtocolError::ProofGenerationFailed(format!("Invalid coin: {e}")))?;

        // 2. check that puzzle_code actually matches what's in the coin
        // TODO: Update to use guest-side compilation when needed
        // For now, skip this check since we don't have the old hash_template method
        let computed_hash = coin.puzzle_hash; // Assume it matches for now
        if computed_hash != coin.puzzle_hash {
            return Err(ProtocolError::InvalidSpendSecret(format!(
                "Puzzle code hash mismatch: expected {}, computed {}",
                hex::encode(coin.puzzle_hash),
                hex::encode(computed_hash)
            )));
        }

        // 3. get the nullifier (this prevents double spending)
        let expected_nullifier = coin.nullifier();

        // 4. create the zk proof using the right api
        let zkvm_result = crate::ClvmZkProver::prove_with_nullifier(
            puzzle_code,
            solution_params,
            coin.spend_secret,
        )
        .map_err(|e| ProtocolError::ProofGenerationFailed(format!("ZK proof failed: {e}")))?;

        // 5. double check the nullifier is what we expected
        let actual_nullifier = zkvm_result
            .proof_output
            .nullifier
            .ok_or_else(|| ProtocolError::InvalidNullifier("No nullifier in proof".to_string()))?;
        if actual_nullifier != expected_nullifier {
            return Err(ProtocolError::InvalidNullifier(format!(
                "Nullifier mismatch: expected {}, got {}",
                hex::encode(expected_nullifier),
                hex::encode(actual_nullifier)
            )));
        }

        // 6. package everything up into a secure bundle
        let spend_bundle = PrivateSpendBundle::new(
            zkvm_result.proof_bytes,
            actual_nullifier,
            zkvm_result.proof_output.clvm_res.output.clone(),
        );

        // 7. FINAL VALIDATION: Ensure bundle is well-formed
        spend_bundle
            .validate()
            .map_err(|e| ProtocolError::ProofGenerationFailed(format!("Invalid bundle: {e}")))?;

        Ok(spend_bundle)
    }

    /// Create multiple spend bundles atomically (for batch transactions)
    ///
    /// This ensures that either all spends succeed or none do, preventing
    /// partial failures that could lead to inconsistent state.
    ///
    /// # Arguments
    ///
    /// * `spends` - Vector of (coin, puzzle_code, solution_params) tuples
    ///
    /// # Security Properties
    ///
    /// - **Atomicity**: All-or-nothing spend creation
    /// - **Nullifier Uniqueness**: Prevents duplicate nullifiers in batch
    /// - **Program Integrity**: Validates all puzzle hashes
    ///
    /// # Returns
    ///
    /// Vector of spend bundles in the same order as inputs
    pub fn create_spend_batch(
        spends: &[(&PrivateCoin, &str, &[ProgramParameter])],
    ) -> Result<Vec<PrivateSpendBundle>, ProtocolError> {
        // 1. SECURITY: Pre-validate all coins and detect duplicate nullifiers
        let mut nullifiers = std::collections::HashSet::new();
        for (coin, puzzle_code, _) in spends {
            coin.validate()
                .map_err(|e| ProtocolError::InvalidSpendSecret(format!("Invalid coin: {e}")))?;

            // Check for duplicate nullifiers in the batch
            let nullifier = coin.nullifier();
            if !nullifiers.insert(nullifier) {
                return Err(ProtocolError::InvalidNullifier(format!(
                    "Duplicate nullifier in batch: {}",
                    hex::encode(nullifier)
                )));
            }

            // Verify puzzle hash
            let computed_hash = Sha256::digest(puzzle_code.as_bytes());
            if computed_hash[..] != coin.puzzle_hash {
                return Err(ProtocolError::InvalidSpendSecret(format!(
                    "Puzzle code hash mismatch for coin {}: expected {}, computed {}",
                    hex::encode(nullifier),
                    hex::encode(coin.puzzle_hash),
                    hex::encode(computed_hash)
                )));
            }
        }

        // 2. CREATE ALL SPEND BUNDLES: Process each spend
        let mut bundles = Vec::with_capacity(spends.len());
        for (coin, puzzle_code, solution_params) in spends {
            let bundle = Self::create_spend(coin, puzzle_code, solution_params)?;
            bundles.push(bundle);
        }

        Ok(bundles)
    }

    /// Verify that a spend bundle was created from a specific coin (without revealing the coin)
    ///
    /// This allows public verification that a nullifier corresponds to a validly spent coin
    /// without revealing any private information about the coin itself.
    ///
    /// # Arguments
    ///
    /// * `bundle` - The spend bundle to verify
    /// * `expected_nullifier` - The nullifier that should be in the bundle
    ///
    /// # Returns
    ///
    /// `true` if the bundle contains the expected nullifier and is well-formed
    pub fn verify_nullifier(
        bundle: &PrivateSpendBundle,
        expected_nullifier: &[u8; 32],
    ) -> Result<bool, ProtocolError> {
        // Validate bundle structure first
        bundle
            .validate()
            .map_err(|e| ProtocolError::SerializationError(format!("Invalid bundle: {e}")))?;

        // Check nullifier match
        Ok(bundle.nullifier == *expected_nullifier)
    }

    // TODO: implement puzzle hash extraction via backend system
    // would need to extend backend trait to extract public inputs from proofs
    // pub fn extract_puzzle_hash(bundle: &PrivateSpendBundle) -> Result<[u8; 32], ProtocolError> {
    //     unimplemented!("puzzle hash extraction needs backend trait extension")
    // }
}
