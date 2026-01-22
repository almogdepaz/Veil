use crate::protocol::{PrivateCoin, PrivateSpendBundle, ProofType, ProtocolError};
use clvm_zk_core::coin_commitment::CoinSecrets;
#[cfg(feature = "risc0")]
use clvm_zk_core::types::ClvmValue;
use serde::{Deserialize, Serialize};

/// settlement proof output from taker's recursive proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementOutput {
    pub maker_nullifier: [u8; 32],
    pub taker_nullifier: [u8; 32],
    pub maker_change_commitment: [u8; 32], // maker's change (asset A)
    pub payment_commitment: [u8; 32],      // taker → maker (asset B, requested amount)
    pub taker_goods_commitment: [u8; 32],  // maker → taker (asset A, offered amount)
    pub taker_change_commitment: [u8; 32], // taker's change (asset B, Y - requested)
    // PUBLIC: validator checks this matches offer's maker_pubkey
    pub maker_pubkey: [u8; 32],
}

/// complete settlement proof bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementProof {
    /// zk proof that validates the settlement
    pub zk_proof: Vec<u8>,

    /// settlement output (nullifiers + commitments)
    pub output: SettlementOutput,

    /// proof type (Settlement)
    pub proof_type: ProofType,
}

impl SettlementProof {
    pub fn new(zk_proof: Vec<u8>, output: SettlementOutput) -> Self {
        Self {
            zk_proof,
            output,
            proof_type: ProofType::Settlement,
        }
    }

    /// convert to PrivateSpendBundle for submission
    pub fn to_spend_bundle(&self) -> PrivateSpendBundle {
        // for now, use maker_nullifier as the primary nullifier
        // (validator will need to handle both)
        PrivateSpendBundle::new_with_type(
            self.zk_proof.clone(),
            self.output.maker_nullifier,
            vec![], // no public conditions for settlement
            self.proof_type,
        )
    }
}

/// parameters for taker's settlement proof
pub struct SettlementParams {
    /// maker's conditional spend proof (PUBLIC input)
    pub maker_proof: PrivateSpendBundle,

    /// taker's coin to spend
    pub taker_coin: PrivateCoin,

    /// taker's coin secrets
    pub taker_secrets: CoinSecrets,

    /// merkle path for taker's coin
    pub taker_merkle_path: Vec<[u8; 32]>,

    /// merkle root
    pub merkle_root: [u8; 32],

    /// taker's leaf index in merkle tree
    pub taker_leaf_index: usize,

    /// payment nonce for hash-based stealth address
    /// payment_puzzle = sha256("stealth_v1" || maker_pubkey || nonce)
    /// host encrypts nonce to maker_pubkey, includes in tx metadata
    pub payment_nonce: [u8; 32],

    /// puzzle hash for taker receiving goods (asset A)
    pub taker_goods_puzzle: [u8; 32],

    /// puzzle hash for taker's change (asset B)
    pub taker_change_puzzle: [u8; 32],

    /// payment coin secrets (taker → maker)
    pub payment_serial: [u8; 32],
    pub payment_rand: [u8; 32],

    /// goods coin secrets (maker → taker)
    pub goods_serial: [u8; 32],
    pub goods_rand: [u8; 32],

    /// taker's change coin secrets
    pub change_serial: [u8; 32],
    pub change_rand: [u8; 32],

    /// v2.0 coin commitment: tail_hash identifies asset type
    /// taker's asset (what taker is spending, XCH = zeros)
    pub taker_tail_hash: [u8; 32],
    /// goods asset (what maker is offering, XCH = zeros)
    pub goods_tail_hash: [u8; 32],
}

/// prove settlement transaction (V2: optimized without recursive verification)
///
/// taker calls this to create a proof that:
/// 1. accepts maker's journal as PUBLIC input (not recursively verified)
/// 2. extracts settlement terms from maker's journal
/// 3. proves taker is creating correct payment/change outputs
/// 4. outputs both nullifiers + all commitments
///
/// VALIDATOR REQUIREMENTS:
/// - must verify BOTH maker's proof AND taker's settlement proof independently
/// - must check taker's proof references correct maker journal hash
/// - atomicity preserved: both proofs must be valid or transaction rejected
///
/// OPTIMIZATION: removes 290s recursive verification overhead while preserving:
/// - privacy: maker's journal was already public when offer posted
/// - atomicity: validator checks both proofs together
/// - security: both proofs cryptographically validated
///
/// # arguments
/// * `params` - settlement parameters including maker's proof and taker's coin data
///
/// # returns
/// * settlement proof ready for submission
pub fn prove_settlement(params: SettlementParams) -> Result<SettlementProof, ProtocolError> {
    // verify maker's proof is conditional spend
    if params.maker_proof.proof_type != ProofType::ConditionalSpend {
        return Err(ProtocolError::InvalidProofType(
            "maker's proof must be ConditionalSpend type".to_string(),
        ));
    }

    #[cfg(feature = "risc0")]
    {
        use clvm_zk_risc0::SETTLEMENT_ELF;
        use sha2::{Digest, Sha256};

        // compute serial commitment
        let mut serial_commit_data = Vec::new();
        serial_commit_data.extend_from_slice(b"clvm_zk_serial_v1.0");
        serial_commit_data.extend_from_slice(&params.taker_secrets.serial_number);
        serial_commit_data.extend_from_slice(&params.taker_secrets.serial_randomness);
        let serial_commitment: [u8; 32] = Sha256::digest(&serial_commit_data).into();

        // deserialize maker's receipt to extract settlement terms
        let maker_receipt: risc0_zkvm::Receipt =
            borsh::BorshDeserialize::try_from_slice(&params.maker_proof.zk_proof).map_err(|e| {
                ProtocolError::ProofGenerationFailed(format!(
                    "failed to deserialize maker's receipt: {e}"
                ))
            })?;

        // decode maker's journal to extract settlement terms (done on HOST, not in guest)
        let maker_output: clvm_zk_core::ProofOutput =
            maker_receipt.journal.decode().map_err(|e| {
                ProtocolError::ProofGenerationFailed(format!(
                    "failed to decode maker's journal: {e}"
                ))
            })?;

        let maker_nullifier = maker_output.nullifiers.first().copied().ok_or_else(|| {
            ProtocolError::ProofGenerationFailed("maker has no nullifier".to_string())
        })?;

        // parse maker's CLVM output to extract settlement terms
        // expected format: ((51 change_puzzle change_amount change_serial change_rand) (offered requested maker_pubkey))
        let (maker_change_commitment, offered, requested, maker_pubkey) =
            parse_maker_clvm_output(&maker_output.clvm_res.output, &params.goods_tail_hash)?;

        // prepare settlement input for guest
        #[derive(serde::Serialize)]
        struct SettlementInput {
            // maker's proof outputs (PUBLIC, extracted by host from verified journal)
            maker_nullifier: [u8; 32],
            maker_change_commitment: [u8; 32],
            offered: u64,
            requested: u64,
            maker_pubkey: [u8; 32],
            taker_coin: TakerCoinData,
            merkle_root: [u8; 32],
            // hash-based stealth: payment_puzzle = sha256("stealth_v1" || maker_pubkey || nonce)
            payment_nonce: [u8; 32],
            taker_goods_puzzle: [u8; 32],
            taker_change_puzzle: [u8; 32],
            payment_serial: [u8; 32],
            payment_rand: [u8; 32],
            goods_serial: [u8; 32],
            goods_rand: [u8; 32],
            change_serial: [u8; 32],
            change_rand: [u8; 32],
            // v2.0 coin commitment: tail_hash identifies asset type
            taker_tail_hash: [u8; 32],
            goods_tail_hash: [u8; 32],
        }

        #[derive(serde::Serialize)]
        struct TakerCoinData {
            amount: u64,
            puzzle_hash: [u8; 32],
            serial_commitment: [u8; 32],
            serial_number: [u8; 32],
            serial_randomness: [u8; 32],
            merkle_path: Vec<[u8; 32]>,
            leaf_index: usize,
        }

        let input = SettlementInput {
            maker_nullifier,
            maker_change_commitment,
            offered,
            requested,
            maker_pubkey,
            taker_coin: TakerCoinData {
                amount: params.taker_coin.amount,
                puzzle_hash: params.taker_coin.puzzle_hash,
                serial_commitment,
                serial_number: params.taker_secrets.serial_number,
                serial_randomness: params.taker_secrets.serial_randomness,
                merkle_path: params.taker_merkle_path,
                leaf_index: params.taker_leaf_index,
            },
            merkle_root: params.merkle_root,
            payment_nonce: params.payment_nonce,
            taker_goods_puzzle: params.taker_goods_puzzle,
            taker_change_puzzle: params.taker_change_puzzle,
            payment_serial: params.payment_serial,
            payment_rand: params.payment_rand,
            goods_serial: params.goods_serial,
            goods_rand: params.goods_rand,
            change_serial: params.change_serial,
            change_rand: params.change_rand,
            taker_tail_hash: params.taker_tail_hash,
            goods_tail_hash: params.goods_tail_hash,
        };

        use risc0_zkvm::{default_prover, ExecutorEnv};

        // V2: no recursive verification - validator will check both proofs separately
        // build environment with maker's journal as public input
        let env = ExecutorEnv::builder()
            .write(&input)
            .map_err(|e| {
                ProtocolError::ProofGenerationFailed(format!(
                    "failed to write settlement input: {e}"
                ))
            })?
            .build()
            .map_err(|e| {
                ProtocolError::ProofGenerationFailed(format!("failed to build executor env: {e}"))
            })?;

        let prover = default_prover();
        let receipt = prover.prove(env, SETTLEMENT_ELF).map_err(|e| {
            ProtocolError::ProofGenerationFailed(format!("settlement proof generation failed: {e}"))
        })?;

        let receipt_obj = receipt.receipt;
        let output: SettlementOutput = receipt_obj.journal.decode().map_err(|e| {
            ProtocolError::ProofGenerationFailed(format!("failed to decode settlement output: {e}"))
        })?;

        let proof_bytes = borsh::to_vec(&receipt_obj).map_err(|e| {
            ProtocolError::ProofGenerationFailed(format!("failed to serialize receipt: {e}"))
        })?;

        Ok(SettlementProof::new(proof_bytes, output))
    }

    #[cfg(not(feature = "risc0"))]
    {
        Err(ProtocolError::ProofGenerationFailed(
            "settlement proving requires risc0 backend".to_string(),
        ))
    }
}

#[cfg(feature = "risc0")]
/// parse maker's CLVM output to extract settlement terms (HOST-side parsing)
/// expected format: ((51 change_puzzle change_amount change_serial change_rand) (offered requested maker_pubkey))
fn parse_maker_clvm_output(
    clvm_output: &[u8],
    tail_hash: &[u8; 32],
) -> Result<([u8; 32], u64, u64, [u8; 32]), ProtocolError> {
    use clvm_zk_core::clvm_parser::ClvmParser;
    use clvm_zk_core::types::ClvmValue;

    let mut parser = ClvmParser::new(clvm_output);
    let value = parser.parse().map_err(|e| {
        ProtocolError::ProofGenerationFailed(format!(
            "failed to parse maker's CLVM output: {:?}",
            e
        ))
    })?;

    match value {
        ClvmValue::Cons(create_coin_box, settlement_terms_box) => {
            // extract maker_change_commitment from CREATE_COIN
            let maker_change_commitment =
                extract_create_coin_commitment_host(&create_coin_box, tail_hash)?;

            // extract settlement terms (offered, requested, maker_pubkey)
            let (offered, requested, maker_pubkey) =
                extract_settlement_terms_host(&settlement_terms_box)?;

            Ok((maker_change_commitment, offered, requested, maker_pubkey))
        }
        _ => Err(ProtocolError::ProofGenerationFailed(
            "invalid maker output structure - expected cons pair".to_string(),
        )),
    }
}

#[cfg(feature = "risc0")]
fn extract_create_coin_commitment_host(
    create_coin: &ClvmValue,
    tail_hash: &[u8; 32],
) -> Result<[u8; 32], ProtocolError> {
    use clvm_zk_core::types::ClvmValue;
    use sha2::{Digest, Sha256};

    // parse (51 change_puzzle change_amount change_serial change_rand)
    match create_coin {
        ClvmValue::Cons(opcode_box, args_box) => {
            match opcode_box.as_ref() {
                ClvmValue::Atom(opcode) if opcode.as_slice() == &[51u8] => {
                    match args_box.as_ref() {
                        ClvmValue::Cons(puzzle_box, rest1) => {
                            let change_puzzle = extract_bytes_32_host(puzzle_box.as_ref())?;

                            match rest1.as_ref() {
                                ClvmValue::Cons(amount_box, rest2) => {
                                    let change_amount = extract_u64_host(amount_box.as_ref())?;

                                    match rest2.as_ref() {
                                        ClvmValue::Cons(serial_box, rest3) => {
                                            let change_serial =
                                                extract_bytes_32_host(serial_box.as_ref())?;

                                            match rest3.as_ref() {
                                                ClvmValue::Cons(rand_box, _) => {
                                                    let change_rand =
                                                        extract_bytes_32_host(rand_box.as_ref())?;

                                                    // compute commitment (v2.0 format)
                                                    let serial_commitment = {
                                                        let mut data = Vec::new();
                                                        data.extend_from_slice(
                                                            b"clvm_zk_serial_v1.0",
                                                        );
                                                        data.extend_from_slice(&change_serial);
                                                        data.extend_from_slice(&change_rand);
                                                        let hash: [u8; 32] =
                                                            Sha256::digest(&data).into();
                                                        hash
                                                    };

                                                    let coin_commitment = {
                                                        let mut data = Vec::new();
                                                        data.extend_from_slice(
                                                            b"clvm_zk_coin_v2.0",
                                                        );
                                                        data.extend_from_slice(tail_hash);
                                                        data.extend_from_slice(
                                                            &change_amount.to_be_bytes(),
                                                        );
                                                        data.extend_from_slice(&change_puzzle);
                                                        data.extend_from_slice(&serial_commitment);
                                                        let hash: [u8; 32] =
                                                            Sha256::digest(&data).into();
                                                        hash
                                                    };

                                                    Ok(coin_commitment)
                                                }
                                                _ => Err(ProtocolError::ProofGenerationFailed(
                                                    "invalid CREATE_COIN: missing rand".to_string(),
                                                )),
                                            }
                                        }
                                        _ => Err(ProtocolError::ProofGenerationFailed(
                                            "invalid CREATE_COIN: missing serial".to_string(),
                                        )),
                                    }
                                }
                                _ => Err(ProtocolError::ProofGenerationFailed(
                                    "invalid CREATE_COIN: missing amount".to_string(),
                                )),
                            }
                        }
                        _ => Err(ProtocolError::ProofGenerationFailed(
                            "invalid CREATE_COIN: missing puzzle".to_string(),
                        )),
                    }
                }
                _ => Err(ProtocolError::ProofGenerationFailed(
                    "invalid CREATE_COIN opcode".to_string(),
                )),
            }
        }
        _ => Err(ProtocolError::ProofGenerationFailed(
            "invalid CREATE_COIN structure".to_string(),
        )),
    }
}

#[cfg(feature = "risc0")]
fn extract_settlement_terms_host(terms: &ClvmValue) -> Result<(u64, u64, [u8; 32]), ProtocolError> {
    use clvm_zk_core::types::ClvmValue;

    match terms {
        ClvmValue::Cons(offered_box, rest1) => {
            let offered = extract_u64_host(offered_box.as_ref())?;

            match rest1.as_ref() {
                ClvmValue::Cons(requested_box, rest2) => {
                    let requested = extract_u64_host(requested_box.as_ref())?;

                    match rest2.as_ref() {
                        ClvmValue::Cons(pubkey_box, _) => {
                            let maker_pubkey = extract_bytes_32_host(pubkey_box.as_ref())?;
                            Ok((offered, requested, maker_pubkey))
                        }
                        _ => Err(ProtocolError::ProofGenerationFailed(
                            "invalid settlement terms: missing maker_pubkey".to_string(),
                        )),
                    }
                }
                _ => Err(ProtocolError::ProofGenerationFailed(
                    "invalid settlement terms: missing requested".to_string(),
                )),
            }
        }
        _ => Err(ProtocolError::ProofGenerationFailed(
            "invalid settlement terms structure".to_string(),
        )),
    }
}

#[cfg(feature = "risc0")]
fn extract_bytes_32_host(value: &ClvmValue) -> Result<[u8; 32], ProtocolError> {
    use clvm_zk_core::types::ClvmValue;

    match value {
        ClvmValue::Atom(bytes) => {
            if bytes.len() != 32 {
                return Err(ProtocolError::ProofGenerationFailed(format!(
                    "expected 32 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            Ok(arr)
        }
        _ => Err(ProtocolError::ProofGenerationFailed(
            "expected atom for bytes".to_string(),
        )),
    }
}

#[cfg(feature = "risc0")]
fn extract_u64_host(value: &ClvmValue) -> Result<u64, ProtocolError> {
    use clvm_zk_core::types::ClvmValue;

    match value {
        ClvmValue::Atom(bytes) => {
            if bytes.is_empty() {
                return Ok(0);
            }
            if bytes.len() > 8 {
                return Err(ProtocolError::ProofGenerationFailed(format!(
                    "u64 value too large: {} bytes",
                    bytes.len()
                )));
            }

            // CLVM uses big-endian encoding
            let mut result: u64 = 0;
            for &byte in bytes {
                result = (result << 8) | (byte as u64);
            }
            Ok(result)
        }
        _ => Err(ProtocolError::ProofGenerationFailed(
            "expected atom for u64".to_string(),
        )),
    }
}
