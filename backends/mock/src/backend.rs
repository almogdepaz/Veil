use clvm_zk_core::verify_ecdsa_signature_with_hasher;
use clvm_zk_core::{
    compile_chialisp_to_bytecode, create_veil_evaluator, run_clvm_with_conditions,
    serialize_params_to_clvm, ClvmResult, ClvmZkError, Condition, ProgramParameter, ProofOutput,
    ZKClvmResult, BLS_DST,
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

/// validate AGG_SIG conditions (opcode 49/50) by verifying ECDSA signatures
fn validate_signature_conditions(conditions: &[Condition]) -> Result<(), ClvmZkError> {
    for condition in conditions {
        if condition.opcode == 49 || condition.opcode == 50 {
            if condition.args.len() != 3 {
                return Err(ClvmZkError::ProofGenerationFailed(format!(
                    "AGG_SIG condition requires 3 args, got {}",
                    condition.args.len()
                )));
            }
            let pubkey = &condition.args[0];
            let message = &condition.args[1];
            let signature = &condition.args[2];

            match ecdsa_verifier(pubkey, message, signature) {
                Ok(true) => {}
                Ok(false) => {
                    return Err(ClvmZkError::ProofGenerationFailed(
                        "AGG_SIG condition: signature verification failed".to_string(),
                    ));
                }
                Err(e) => {
                    return Err(ClvmZkError::ProofGenerationFailed(format!(
                        "AGG_SIG condition: verification error: {}",
                        e
                    )));
                }
            }
        }
    }
    Ok(())
}

/// transform CREATE_COIN conditions for output privacy
/// returns (final_output_bytes, had_transformations)
fn transform_create_coin_conditions(
    conditions: &mut [Condition],
    output_bytes: Vec<u8>,
    tail_hash: [u8; 32],
) -> Result<Vec<u8>, ClvmZkError> {
    let mut has_transformations = false;

    for condition in conditions.iter_mut() {
        if condition.opcode == 51 {
            match condition.args.len() {
                2 => {
                    // Transparent mode: leave as-is
                }
                4 => {
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

                    // Parse amount from variable-length big-endian bytes
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

                    // Compute coin_commitment (v2.0 format with tail_hash)
                    let coin_domain = b"clvm_zk_coin_v2.0";
                    let mut coin_data = [0u8; 121];
                    coin_data[..17].copy_from_slice(coin_domain);
                    coin_data[17..49].copy_from_slice(&tail_hash);
                    coin_data[49..57].copy_from_slice(&amount.to_be_bytes());
                    coin_data[57..89].copy_from_slice(puzzle_hash);
                    coin_data[89..121].copy_from_slice(&serial_commitment);
                    let coin_commitment = hash_data(&coin_data);

                    condition.args = vec![coin_commitment.to_vec()];
                    has_transformations = true;
                }
                n => {
                    return Err(ClvmZkError::ProofGenerationFailed(format!(
                        "CREATE_COIN must have 2 args (transparent) or 4 args (private), got {}",
                        n
                    )));
                }
            }
        }
    }

    if has_transformations {
        Ok(clvm_zk_core::serialize_conditions_to_bytes(conditions))
    } else {
        Ok(output_bytes)
    }
}

impl MockBackend {
    pub fn new() -> Result<Self, ClvmZkError> {
        Ok(Self)
    }

    pub fn prove_chialisp_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
    ) -> Result<ZKClvmResult, ClvmZkError> {
        let (instance_bytecode, program_hash) =
            compile_chialisp_to_bytecode(hash_data, chialisp_source).map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("chialisp compilation failed: {:?}", e))
            })?;

        let evaluator = create_veil_evaluator(hash_data, default_bls_verifier, ecdsa_verifier);
        let args = serialize_params_to_clvm(program_parameters);

        let max_cost = 1_000_000_000;
        let (output_bytes, mut conditions) =
            run_clvm_with_conditions(&evaluator, &instance_bytecode, &args, max_cost).map_err(
                |e| ClvmZkError::ProofGenerationFailed(format!("clvm execution failed: {:?}", e)),
            )?;

        validate_signature_conditions(&conditions)?;
        let tail_hash = [0u8; 32]; // default XCH for simple proving API
        let final_output = transform_create_coin_conditions(&mut conditions, output_bytes, tail_hash)?;

        let clvm_output = ClvmResult {
            output: final_output,
            cost: 0,
        };

        let proof_output = ProofOutput {
            program_hash,
            nullifiers: vec![],
            clvm_res: clvm_output,
            proof_type: 0,
            public_values: vec![],
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
        let (instance_bytecode, program_hash) =
            compile_chialisp_to_bytecode(hash_data, &inputs.chialisp_source).map_err(|e| {
                ClvmZkError::ProofGenerationFailed(format!("chialisp compilation failed: {:?}", e))
            })?;

        let evaluator = create_veil_evaluator(hash_data, default_bls_verifier, ecdsa_verifier);
        let args = serialize_params_to_clvm(&inputs.program_parameters);

        let max_cost = 1_000_000_000;
        let (output_bytes, mut conditions) =
            run_clvm_with_conditions(&evaluator, &instance_bytecode, &args, max_cost).map_err(
                |e| ClvmZkError::ProofGenerationFailed(format!("clvm execution failed: {:?}", e)),
            )?;

        validate_signature_conditions(&conditions)?;
        let tail_hash = inputs.tail_hash.unwrap_or([0u8; 32]);
        let final_output = transform_create_coin_conditions(&mut conditions, output_bytes, tail_hash)?;

        let clvm_output = ClvmResult {
            output: final_output,
            cost: 0,
        };

        let nullifier = match inputs.serial_commitment_data {
            Some(commitment_data) => {
                let serial_randomness = commitment_data.serial_randomness;
                let serial_number = commitment_data.serial_number;
                let puzzle_hash = commitment_data.program_hash;

                if program_hash != puzzle_hash {
                    return Err(ClvmZkError::ProofGenerationFailed(
                        "program_hash mismatch: cannot spend coin with different puzzle"
                            .to_string(),
                    ));
                }

                let domain = b"clvm_zk_serial_v1.0";
                let mut serial_commit_data = Vec::with_capacity(19 + 64);
                serial_commit_data.extend_from_slice(domain);
                serial_commit_data.extend_from_slice(&serial_number);
                serial_commit_data.extend_from_slice(&serial_randomness);
                let computed_serial_commitment = hash_data(&serial_commit_data);

                let serial_commitment_expected = commitment_data.serial_commitment;
                if computed_serial_commitment != serial_commitment_expected {
                    return Err(ClvmZkError::ProofGenerationFailed(
                        "serial commitment verification failed".to_string(),
                    ));
                }

                // v2.0 format: domain(17) || tail_hash(32) || amount_be(8) || puzzle_hash(32) || serial_commitment(32) = 121 bytes
                let coin_domain = b"clvm_zk_coin_v2.0";
                let tail_hash = inputs.tail_hash.unwrap_or([0u8; 32]);
                let amount = commitment_data.amount;
                let mut coin_data = [0u8; 121];
                coin_data[..17].copy_from_slice(coin_domain);
                coin_data[17..49].copy_from_slice(&tail_hash);
                coin_data[49..57].copy_from_slice(&amount.to_be_bytes());
                coin_data[57..89].copy_from_slice(&program_hash);
                coin_data[89..121].copy_from_slice(&computed_serial_commitment);
                let computed_coin_commitment = hash_data(&coin_data);

                let coin_commitment_provided = commitment_data.coin_commitment;
                if computed_coin_commitment != coin_commitment_provided {
                    return Err(ClvmZkError::ProofGenerationFailed(
                        "coin commitment verification failed".to_string(),
                    ));
                }

                let merkle_path = commitment_data.merkle_path;
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

                let computed_root = current_hash;
                if computed_root != expected_root {
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

        // collect nullifiers: primary coin + additional coins
        let mut nullifiers = nullifier.map(|n| vec![n]).unwrap_or_default();

        // process additional coins for ring spends
        if let Some(additional_coins) = &inputs.additional_coins {
            for coin in additional_coins {
                let coin_data = &coin.serial_commitment_data;

                // compute nullifier for additional coin
                // nullifier = hash(serial_number || program_hash || amount)
                let (_, coin_program_hash) =
                    compile_chialisp_to_bytecode(hash_data, &coin.chialisp_source).map_err(|e| {
                        ClvmZkError::ProofGenerationFailed(format!(
                            "additional coin compilation failed: {:?}",
                            e
                        ))
                    })?;

                let mut nullifier_data = Vec::with_capacity(72);
                nullifier_data.extend_from_slice(&coin_data.serial_number);
                nullifier_data.extend_from_slice(&coin_program_hash);
                nullifier_data.extend_from_slice(&coin_data.amount.to_be_bytes());
                nullifiers.push(hash_data(&nullifier_data));
            }
        }

        let proof_output = ProofOutput {
            program_hash,
            nullifiers,
            clvm_res: clvm_output,
            proof_type: 0,
            public_values: vec![],
        };

        let proof_bytes = borsh::to_vec(&proof_output).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize mock proof: {e}"))
        })?;

        Ok(ZKClvmResult {
            proof_output,
            proof_bytes,
        })
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
        true
    }
}
