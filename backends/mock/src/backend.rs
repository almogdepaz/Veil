use clvm_zk_core::coin_commitment::{build_coin_commitment_preimage, XCH_TAIL};
use clvm_zk_core::verify_ecdsa_signature_with_hasher;
use clvm_zk_core::{
    compile_chialisp_to_bytecode_with_table, ClvmEvaluator, ClvmResult, ClvmZkError,
    ProgramParameter, ProofOutput, ZKClvmResult, BLS_DST,
};
use sha2::{Digest, Sha256};

use blst::min_sig as blst_core;
use blst::BLST_ERROR;

pub struct MockBackend;

impl MockBackend {}

pub fn default_bls_verifier(
    public_key_bytes: &[u8],
    message_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, &'static str> {
    // using min_sig variant: pk in G2 (96 bytes), sig in G1 (48 bytes)
    let pk = blst_core::PublicKey::from_bytes(public_key_bytes)
        .map_err(|_| "invalid public key bytes")?;

    let sig =
        blst_core::Signature::from_bytes(signature_bytes).map_err(|_| "invalid signature bytes")?;

    let res: BLST_ERROR = sig.verify(true, message_bytes, BLS_DST, &[], &pk, true);

    Ok(res == BLST_ERROR::BLST_SUCCESS)
}

pub fn hash_data(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn ecdsa_verifier(
    public_key_bytes: &[u8],
    message_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, &'static str> {
    verify_ecdsa_signature_with_hasher(hash_data, public_key_bytes, message_bytes, signature_bytes)
}

pub use ecdsa_verifier as default_ecdsa_verifier;

impl MockBackend {
    pub fn new() -> Result<Self, ClvmZkError> {
        Ok(Self)
    }

    pub fn prove_chialisp_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
    ) -> Result<ZKClvmResult, ClvmZkError> {
        let (instance_bytecode, program_hash, function_table) =
            compile_chialisp_to_bytecode_with_table(hash_data, chialisp_source, program_parameters)
                .map_err(|e| {
                    ClvmZkError::ProofGenerationFailed(format!(
                        "chialisp compilation failed: {:?}",
                        e
                    ))
                })?;

        let mut evaluator = ClvmEvaluator::new(hash_data, default_bls_verifier, ecdsa_verifier);
        evaluator.function_table = function_table;

        let (output_bytes, _runtime_conditions) = evaluator
            .evaluate_clvm_program(&instance_bytecode)
            .map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("clvm execution failed: {:?}", e))
            })?;

        // Parse conditions from output (list-based programs return condition structures)
        let mut conditions = clvm_zk_core::deserialize_clvm_output_to_conditions(&output_bytes)
            .unwrap_or(_runtime_conditions); // fallback to runtime conditions if parsing fails

        // Transform CREATE_COIN conditions for output privacy
        let mut has_transformations = false;
        for condition in conditions.iter_mut() {
            if condition.opcode == 51 {
                // CREATE_COIN opcode
                match condition.args.len() {
                    2 => {
                        // Transparent mode: CREATE_COIN(puzzle_hash, amount)
                        // Leave as-is for testing/debugging
                    }
                    4 => {
                        // Private mode: CREATE_COIN(puzzle_hash, amount, serial_num, serial_rand)
                        let puzzle_hash = &condition.args[0];
                        let amount_bytes = &condition.args[1];
                        let serial_number = &condition.args[2];
                        let serial_randomness = &condition.args[3];

                        // Validate sizes
                        if puzzle_hash.len() != 32 {
                            return Err(ClvmZkError::ProofGenerationFailed(
                                "puzzle_hash must be 32 bytes".to_string(),
                            ));
                        }
                        if amount_bytes.len() > 8 {
                            return Err(ClvmZkError::ProofGenerationFailed(
                                "amount too large (max 8 bytes)".to_string(),
                            ));
                        }
                        if serial_number.len() != 32 {
                            return Err(ClvmZkError::ProofGenerationFailed(
                                "serial_number must be 32 bytes".to_string(),
                            ));
                        }
                        if serial_randomness.len() != 32 {
                            return Err(ClvmZkError::ProofGenerationFailed(
                                "serial_randomness must be 32 bytes".to_string(),
                            ));
                        }

                        // Parse amount from variable-length big-endian bytes (CLVM compact encoding)
                        let mut amount = 0u64;
                        for &byte in amount_bytes {
                            amount = (amount << 8) | (byte as u64);
                        }

                        // Compute serial_commitment
                        let serial_domain = b"clvm_zk_serial_v1.0";
                        let mut serial_data = [0u8; 83];
                        serial_data[..19].copy_from_slice(serial_domain);
                        serial_data[19..51].copy_from_slice(serial_number);
                        serial_data[51..83].copy_from_slice(serial_randomness);
                        let serial_commitment = hash_data(&serial_data);

                        // compute coin_commitment v2
                        let mut puzzle_hash_arr = [0u8; 32];
                        puzzle_hash_arr.copy_from_slice(puzzle_hash);
                        let coin_data = build_coin_commitment_preimage(
                            &XCH_TAIL, // simple API only supports XCH
                            amount,
                            &puzzle_hash_arr,
                            &serial_commitment,
                        );
                        let coin_commitment = hash_data(&coin_data);

                        // Replace args: [puzzle, amount, serial, rand] → [commitment]
                        condition.args = vec![coin_commitment.to_vec()];
                        has_transformations = true;
                    }
                    n => {
                        return Err(ClvmZkError::ProofGenerationFailed(format!(
                        "CREATE_COIN must have 2 args (transparent) or 4 args (private), got {}",
                        n
                    )))
                    }
                }
            }
        }

        // Only re-serialize if we actually transformed something
        let final_output = if has_transformations {
            clvm_zk_core::serialize_conditions_to_bytes(&conditions)
        } else {
            output_bytes
        };

        let clvm_output = ClvmResult {
            output: final_output,
            cost: 0,
        };

        let proof_output = ProofOutput {
            program_hash,
            nullifiers: vec![], // simple API has no serial commitment data
            clvm_res: clvm_output.clone(),
        };

        let proof_bytes = borsh::to_vec(&proof_output).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize mock proof: {e}"))
        })?;

        Ok(ZKClvmResult {
            proof_output,
            proof_bytes,
        })
    }

    pub fn verify_mock_proof(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        expected_result: &[u8],
    ) -> Result<bool, ClvmZkError> {
        let result = self.prove_chialisp_program(chialisp_source, program_parameters)?;
        Ok(result.proof_output.clvm_res.output == expected_result)
    }

    pub fn prove_with_input(
        &self,
        inputs: clvm_zk_core::Input,
    ) -> Result<ZKClvmResult, ClvmZkError> {
        let tail_hash = inputs.tail_hash.unwrap_or(XCH_TAIL);

        // Process primary coin
        let (
            primary_conditions,
            primary_program_hash,
            primary_nullifier,
            primary_puzzle_announcements,
            primary_coin_announcements,
        ) = self.process_single_coin(
            &inputs.chialisp_source,
            &inputs.program_parameters,
            inputs.serial_commitment_data.as_ref(),
            &tail_hash,
        )?;

        let mut all_conditions = primary_conditions;
        let mut all_nullifiers = Vec::new();
        let mut all_puzzle_announcement_hashes = primary_puzzle_announcements;
        let mut all_coin_announcement_hashes = primary_coin_announcements;

        if let Some(n) = primary_nullifier {
            all_nullifiers.push(n);
        }

        // Process additional coins (ring spend support)
        if let Some(additional_coins) = &inputs.additional_coins {
            for additional_coin in additional_coins {
                // Verify all coins in ring share same tail_hash
                if additional_coin.tail_hash != tail_hash {
                    return Err(ClvmZkError::ProofGenerationFailed(
                        "all coins in ring must have same tail_hash".to_string(),
                    ));
                }

                let (
                    coin_conditions,
                    _coin_program_hash,
                    coin_nullifier,
                    coin_puzzle_announcements,
                    coin_coin_announcements,
                ) = self.process_single_coin(
                    &additional_coin.chialisp_source,
                    &additional_coin.program_parameters,
                    Some(&additional_coin.serial_commitment_data),
                    &additional_coin.tail_hash,
                )?;

                all_conditions.extend(coin_conditions);
                all_puzzle_announcement_hashes.extend(coin_puzzle_announcements);
                all_coin_announcement_hashes.extend(coin_coin_announcements);

                if let Some(n) = coin_nullifier {
                    all_nullifiers.push(n);
                }
            }
        }

        // Collect assertion hashes from all conditions
        let mut puzzle_assertion_hashes: Vec<[u8; 32]> = Vec::new();
        let mut coin_assertion_hashes: Vec<[u8; 32]> = Vec::new();
        for condition in &all_conditions {
            match condition.opcode {
                63 => {
                    // ASSERT_PUZZLE_ANNOUNCEMENT
                    if !condition.args.is_empty() && condition.args[0].len() == 32 {
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&condition.args[0]);
                        puzzle_assertion_hashes.push(hash);
                    }
                }
                61 => {
                    // ASSERT_COIN_ANNOUNCEMENT
                    if !condition.args.is_empty() && condition.args[0].len() == 32 {
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&condition.args[0]);
                        coin_assertion_hashes.push(hash);
                    }
                }
                _ => {}
            }
        }

        // Verify all puzzle assertions are satisfied
        for assertion in &puzzle_assertion_hashes {
            if !all_puzzle_announcement_hashes.contains(assertion) {
                return Err(ClvmZkError::ProofGenerationFailed(
                    "puzzle announcement assertion not satisfied".to_string(),
                ));
            }
        }

        // Verify all coin assertions are satisfied
        for assertion in &coin_assertion_hashes {
            if !all_coin_announcement_hashes.contains(assertion) {
                return Err(ClvmZkError::ProofGenerationFailed(
                    "coin announcement assertion not satisfied".to_string(),
                ));
            }
        }

        // Filter out announcement conditions (opcodes 60, 61, 62, 63)
        let filtered_conditions: Vec<clvm_zk_core::Condition> = all_conditions
            .into_iter()
            .filter(|c| !matches!(c.opcode, 60..=63))
            .collect();

        let final_output = clvm_zk_core::serialize_conditions_to_bytes(&filtered_conditions);

        let clvm_output = ClvmResult {
            output: final_output,
            cost: 0,
        };

        let proof_output = ProofOutput {
            program_hash: primary_program_hash,
            nullifiers: all_nullifiers,
            clvm_res: clvm_output,
        };

        let proof_bytes = borsh::to_vec(&proof_output).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize mock proof: {e}"))
        })?;

        Ok(ZKClvmResult {
            proof_output,
            proof_bytes,
        })
    }

    /// Process a single coin: compile, execute, transform CREATE_COIN, verify commitment, compute nullifier
    /// Returns (conditions, program_hash, optional_nullifier, puzzle_announcement_hashes, coin_announcement_hashes)
    #[allow(clippy::type_complexity)]
    fn process_single_coin(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        serial_commitment_data: Option<&clvm_zk_core::SerialCommitmentData>,
        tail_hash: &[u8; 32],
    ) -> Result<
        (
            Vec<clvm_zk_core::Condition>,
            [u8; 32],
            Option<[u8; 32]>,
            Vec<[u8; 32]>,
            Vec<[u8; 32]>,
        ),
        ClvmZkError,
    > {
        let (instance_bytecode, program_hash, function_table) =
            compile_chialisp_to_bytecode_with_table(hash_data, chialisp_source, program_parameters)
                .map_err(|e| {
                    ClvmZkError::ProofGenerationFailed(format!(
                        "chialisp compilation failed: {:?}",
                        e
                    ))
                })?;

        let mut evaluator = ClvmEvaluator::new(hash_data, default_bls_verifier, ecdsa_verifier);
        evaluator.function_table = function_table;

        let (output_bytes, _runtime_conditions) = evaluator
            .evaluate_clvm_program(&instance_bytecode)
            .map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("clvm execution failed: {:?}", e))
            })?;

        let mut conditions = clvm_zk_core::deserialize_clvm_output_to_conditions(&output_bytes)
            .unwrap_or(_runtime_conditions);

        // Transform CREATE_COIN conditions for output privacy
        for condition in conditions.iter_mut() {
            if condition.opcode == 51 && condition.args.len() == 4 {
                let puzzle_hash = &condition.args[0];
                let amount_bytes = &condition.args[1];
                let serial_number = &condition.args[2];
                let serial_randomness = &condition.args[3];

                if puzzle_hash.len() != 32 {
                    return Err(ClvmZkError::ProofGenerationFailed(
                        "puzzle_hash must be 32 bytes".to_string(),
                    ));
                }
                if amount_bytes.len() > 8 {
                    return Err(ClvmZkError::ProofGenerationFailed(
                        "amount too large (max 8 bytes)".to_string(),
                    ));
                }
                if serial_number.len() != 32 {
                    return Err(ClvmZkError::ProofGenerationFailed(
                        "serial_number must be 32 bytes".to_string(),
                    ));
                }
                if serial_randomness.len() != 32 {
                    return Err(ClvmZkError::ProofGenerationFailed(
                        "serial_randomness must be 32 bytes".to_string(),
                    ));
                }

                let mut amount = 0u64;
                for &byte in amount_bytes {
                    amount = (amount << 8) | (byte as u64);
                }

                let serial_domain = b"clvm_zk_serial_v1.0";
                let mut serial_data = [0u8; 83];
                serial_data[..19].copy_from_slice(serial_domain);
                serial_data[19..51].copy_from_slice(serial_number);
                serial_data[51..83].copy_from_slice(serial_randomness);
                let serial_commitment = hash_data(&serial_data);

                let mut puzzle_hash_arr = [0u8; 32];
                puzzle_hash_arr.copy_from_slice(puzzle_hash);
                let coin_data = build_coin_commitment_preimage(
                    tail_hash,
                    amount,
                    &puzzle_hash_arr,
                    &serial_commitment,
                );
                let coin_commitment = hash_data(&coin_data);

                condition.args = vec![coin_commitment.to_vec()];
            }
        }

        // Compute coin_commitment early (needed for coin announcements)
        let coin_commitment = serial_commitment_data.map(|cd| {
            let domain = b"clvm_zk_serial_v1.0";
            let mut serial_commit_data = [0u8; 83];
            serial_commit_data[..19].copy_from_slice(domain);
            serial_commit_data[19..51].copy_from_slice(&cd.serial_number);
            serial_commit_data[51..83].copy_from_slice(&cd.serial_randomness);
            let computed_serial_commitment = hash_data(&serial_commit_data);

            let coin_data = build_coin_commitment_preimage(
                tail_hash,
                cd.amount,
                &cd.program_hash,
                &computed_serial_commitment,
            );
            hash_data(&coin_data)
        });

        // Compute announcement hashes using THIS coin's identifiers
        let mut puzzle_announcement_hashes = Vec::new();
        let mut coin_announcement_hashes = Vec::new();
        for condition in &conditions {
            match condition.opcode {
                62 => {
                    // CREATE_PUZZLE_ANNOUNCEMENT(message)
                    if !condition.args.is_empty() {
                        let message = &condition.args[0];
                        let mut data = Vec::with_capacity(32 + message.len());
                        data.extend_from_slice(&program_hash);
                        data.extend_from_slice(message);
                        puzzle_announcement_hashes.push(hash_data(&data));
                    }
                }
                60 => {
                    // CREATE_COIN_ANNOUNCEMENT(message)
                    if !condition.args.is_empty() {
                        if let Some(cc) = coin_commitment {
                            let message = &condition.args[0];
                            let mut data = Vec::with_capacity(32 + message.len());
                            data.extend_from_slice(&cc);
                            data.extend_from_slice(message);
                            coin_announcement_hashes.push(hash_data(&data));
                        }
                    }
                }
                _ => {}
            }
        }

        // Compute nullifier if serial commitment data provided
        let nullifier = match serial_commitment_data {
            Some(commitment_data) => {
                let serial_randomness = commitment_data.serial_randomness;
                let serial_number = commitment_data.serial_number;
                let expected_program_hash = commitment_data.program_hash;

                if program_hash != expected_program_hash {
                    return Err(ClvmZkError::ProofGenerationFailed(
                        "program_hash mismatch: cannot spend coin with different puzzle"
                            .to_string(),
                    ));
                }

                let domain = b"clvm_zk_serial_v1.0";
                let mut serial_commit_data = [0u8; 83];
                serial_commit_data[..19].copy_from_slice(domain);
                serial_commit_data[19..51].copy_from_slice(&serial_number);
                serial_commit_data[51..83].copy_from_slice(&serial_randomness);
                let computed_serial_commitment = hash_data(&serial_commit_data);

                if computed_serial_commitment != commitment_data.serial_commitment {
                    return Err(ClvmZkError::ProofGenerationFailed(
                        "serial commitment verification failed".to_string(),
                    ));
                }

                let amount = commitment_data.amount;

                let coin_data = build_coin_commitment_preimage(
                    tail_hash,
                    amount,
                    &program_hash,
                    &computed_serial_commitment,
                );
                let computed_coin_commitment = hash_data(&coin_data);

                if computed_coin_commitment != commitment_data.coin_commitment {
                    return Err(ClvmZkError::ProofGenerationFailed(
                        "coin commitment verification failed".to_string(),
                    ));
                }

                // Verify merkle path
                let merkle_path = &commitment_data.merkle_path;
                let expected_root = commitment_data.merkle_root;
                let leaf_index = commitment_data.leaf_index;

                let mut current_hash = computed_coin_commitment;
                let mut current_index = leaf_index;
                for sibling in merkle_path.iter() {
                    let mut combined = [0u8; 64];
                    if current_index % 2 == 0 {
                        combined[..32].copy_from_slice(&current_hash);
                        combined[32..].copy_from_slice(sibling);
                    } else {
                        combined[..32].copy_from_slice(sibling);
                        combined[32..].copy_from_slice(&current_hash);
                    }
                    current_hash = hash_data(&combined);
                    current_index /= 2;
                }

                if current_hash != expected_root {
                    return Err(ClvmZkError::ProofGenerationFailed(
                        "merkle root mismatch: coin not in current tree state".to_string(),
                    ));
                }

                let mut nullifier_data = Vec::with_capacity(72);
                nullifier_data.extend_from_slice(&serial_number);
                nullifier_data.extend_from_slice(&program_hash);
                nullifier_data.extend_from_slice(&amount.to_be_bytes());
                Some(hash_data(&nullifier_data))
            }
            None => None,
        };

        Ok((
            conditions,
            program_hash,
            nullifier,
            puzzle_announcement_hashes,
            coin_announcement_hashes,
        ))
    }

    pub fn verify_proof_and_extract(
        &self,
        proof: &[u8],
    ) -> Result<(bool, [u8; 32], Vec<u8>), ClvmZkError> {
        let output: ProofOutput = borsh::from_slice(proof).map_err(|e| {
            ClvmZkError::InvalidProofFormat(format!("failed to deserialize mock proof: {e}"))
        })?;

        Ok((true, output.program_hash, output.clvm_res.output))
    }

    pub fn backend_name(&self) -> &'static str {
        "mock"
    }

    pub fn is_available(&self) -> bool {
        true // mock backend is always available
    }
}
