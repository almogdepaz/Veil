use crate::protocol::{PrivateCoin, PrivateSpendBundle, ProtocolError, ProofType};
use clvm_zk_core::coin_commitment::CoinSecrets;
use serde::{Deserialize, Serialize};

#[cfg(feature = "risc0")]
use clvm_zk_risc0::CLVM_RISC0_GUEST_ID;

/// settlement proof output from taker's recursive proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementOutput {
    pub maker_nullifier: [u8; 32],
    pub taker_nullifier: [u8; 32],
    pub maker_change_commitment: [u8; 32],     // maker's change (asset A)
    pub payment_commitment: [u8; 32],          // taker → maker (asset B, requested amount)
    pub taker_goods_commitment: [u8; 32],      // maker → taker (asset A, offered amount)
    pub taker_change_commitment: [u8; 32],     // taker's change (asset B, Y - requested)
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

    /// taker's ephemeral private key for ECDH
    pub taker_ephemeral_privkey: [u8; 32],

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
}

/// prove settlement transaction
///
/// taker calls this to create a recursive proof that:
/// 1. verifies maker's conditional spend proof
/// 2. extracts settlement terms from maker's proof
/// 3. proves taker is creating correct payment/change outputs
/// 4. outputs both nullifiers + all commitments
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
        use sha2::{Sha256, Digest};

        // compute serial commitment
        let mut serial_commit_data = Vec::new();
        serial_commit_data.extend_from_slice(b"clvm_zk_serial_v1.0");
        serial_commit_data.extend_from_slice(&params.taker_secrets.serial_number);
        serial_commit_data.extend_from_slice(&params.taker_secrets.serial_randomness);
        let serial_commitment: [u8; 32] = Sha256::digest(&serial_commit_data).into();

        // deserialize maker's receipt (needed for add_assumption AND journal extraction)
        let maker_receipt: risc0_zkvm::Receipt =
            borsh::BorshDeserialize::try_from_slice(&params.maker_proof.zk_proof)
                .map_err(|e| ProtocolError::ProofGenerationFailed(format!("failed to deserialize maker's receipt: {e}")))?;

        // extract journal bytes for guest to verify (risc0 composition pattern)
        let maker_journal_bytes = maker_receipt.journal.bytes.clone();

        // prepare settlement input for guest
        #[derive(serde::Serialize)]
        struct SettlementInput {
            // IMAGE_ID of standard guest (passed to avoid hardcoding in guest)
            standard_guest_image_id: [u8; 32],
            // journal bytes for env::verify() call (risc0 composition pattern)
            maker_journal_bytes: Vec<u8>,
            taker_coin: TakerCoinData,
            merkle_root: [u8; 32],
            taker_ephemeral_privkey: [u8; 32],
            taker_goods_puzzle: [u8; 32],
            taker_change_puzzle: [u8; 32],
            payment_serial: [u8; 32],
            payment_rand: [u8; 32],
            goods_serial: [u8; 32],
            goods_rand: [u8; 32],
            change_serial: [u8; 32],
            change_rand: [u8; 32],
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

        // convert IMAGE_ID from [u32; 8] to [u8; 32] for guest
        #[cfg(feature = "risc0")]
        fn image_id_to_bytes(id: [u32; 8]) -> [u8; 32] {
            let mut bytes = [0u8; 32];
            for (i, word) in id.iter().enumerate() {
                bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
            }
            bytes
        }

        let input = SettlementInput {
            #[cfg(feature = "risc0")]
            standard_guest_image_id: image_id_to_bytes(CLVM_RISC0_GUEST_ID),
            #[cfg(not(feature = "risc0"))]
            standard_guest_image_id: [0u8; 32],  // placeholder for non-risc0 backends
            maker_journal_bytes,
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
            taker_ephemeral_privkey: params.taker_ephemeral_privkey,
            taker_goods_puzzle: params.taker_goods_puzzle,
            taker_change_puzzle: params.taker_change_puzzle,
            payment_serial: params.payment_serial,
            payment_rand: params.payment_rand,
            goods_serial: params.goods_serial,
            goods_rand: params.goods_rand,
            change_serial: params.change_serial,
            change_rand: params.change_rand,
        };

        use risc0_zkvm::{default_prover, ExecutorEnv};

        // build environment with add_assumption pattern (like recursive aggregator)
        let mut env_builder = ExecutorEnv::builder();
        env_builder.write(&input).map_err(|e| {
            ProtocolError::ProofGenerationFailed(format!("failed to write settlement input: {e}"))
        })?;

        // add maker's receipt as assumption (risc0 automatically verifies it)
        env_builder.add_assumption(maker_receipt);

        let env = env_builder.build().map_err(|e| {
            ProtocolError::ProofGenerationFailed(format!("failed to build executor env: {e}"))
        })?;

        let prover = default_prover();
        let receipt = prover
            .prove(env, SETTLEMENT_ELF)
            .map_err(|e| {
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
