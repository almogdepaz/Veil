//! Canonical, storage-independent validation for the Veil alpha ledger.

use clvm_zk_core::{NetworkProofOutputV1, NetworkTransitionV1, NETWORK_PROTOCOL_V1};
use sha2::{Digest, Sha256};

const NOTES_HASH_DOMAIN_V1: &[u8] = b"veil_notes_v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum BackendIdV1 {
    Sp1,
    Risc0,
}

pub trait ProofVerifier {
    fn backend_id(&self) -> BackendIdV1;
    fn program_id(&self) -> [u8; 32];
    fn verify_and_decode(&self, proof: &[u8]) -> Result<NetworkProofOutputV1, ValidationError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalRootV1 {
    pub height: u64,
    pub commitment_root: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationPolicyV1 {
    pub accepted_root_window: u16,
    pub max_proof_lifetime: u16,
    pub max_nullifiers: u16,
    pub max_outputs: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionLimitsV1 {
    pub max_nullifiers: u16,
    pub max_outputs: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("wrong network")]
    WrongNetwork,
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("unknown anchor height")]
    UnknownAnchorHeight,
    #[error("ledger root mismatch")]
    LedgerRootMismatch,
    #[error("proof anchor is outside the accepted root window")]
    AnchorOutsideWindow,
    #[error("proof expired")]
    ExpiredProof,
    #[error("proof lifetime exceeds the configured maximum")]
    LifetimeTooLong,
    #[error("encrypted-note metadata does not match the proof")]
    MetadataMismatch,
    #[error("invalid proof output encoding")]
    InvalidProofEncoding,
    #[error("encrypted-note count does not match output commitment count")]
    OutputNoteCountMismatch,
    #[error("faucet proof uses the wrong asset TAIL")]
    WrongFaucetAsset,
    #[error("proof exceeds configured byte limit")]
    ProofTooLarge,
    #[error("proof backend is not allowed")]
    UnsupportedBackend,
    #[error("proof verifier program does not match genesis")]
    WrongProgram,
    #[error("private transfer has no nullifiers")]
    MissingNullifier,
    #[error("private transfer has no outputs")]
    MissingOutput,
    #[error("nullifier is zero")]
    InvalidNullifier,
    #[error("output commitment is zero")]
    InvalidOutput,
    #[error("nullifier occurs more than once")]
    DuplicateNullifier,
    #[error("output commitment occurs more than once")]
    DuplicateOutput,
    #[error("faucet request ID is zero")]
    InvalidFaucetRequest,
    #[error("faucet amount is zero")]
    InvalidFaucetAmount,
    #[error("transition exceeds configured limits")]
    LimitExceeded,
}

pub fn verify_network_proof_v1(
    verifier: &(impl ProofVerifier + ?Sized),
    proof: &[u8],
    max_proof_bytes: usize,
    expected_backend: BackendIdV1,
    expected_program_id: [u8; 32],
) -> Result<NetworkProofOutputV1, ValidationError> {
    if proof.len() > max_proof_bytes {
        return Err(ValidationError::ProofTooLarge);
    }
    if verifier.backend_id() != expected_backend {
        return Err(ValidationError::UnsupportedBackend);
    }
    if verifier.program_id() != expected_program_id {
        return Err(ValidationError::WrongProgram);
    }
    verifier.verify_and_decode(proof)
}

pub fn hash_encrypted_notes_v1(notes: &[Vec<u8>]) -> [u8; 32] {
    let encoded = borsh::to_vec(notes).expect("serializing a vector into memory cannot fail");
    let mut hasher = Sha256::new();
    hasher.update(NOTES_HASH_DOMAIN_V1);
    hasher.update(encoded);
    hasher.finalize().into()
}

pub fn decode_network_output_v1(bytes: &[u8]) -> Result<NetworkProofOutputV1, ValidationError> {
    borsh::from_slice(bytes).map_err(|_| ValidationError::InvalidProofEncoding)
}

pub fn validate_transition_limits_v1(
    output: &NetworkProofOutputV1,
    limits: &TransitionLimitsV1,
) -> Result<(), ValidationError> {
    let (nullifier_count, output_count) = match &output.transition {
        NetworkTransitionV1::FaucetMint { .. } => (0, 1),
        NetworkTransitionV1::PrivateTransfer {
            nullifiers,
            output_commitments,
        } => (nullifiers.len(), output_commitments.len()),
    };
    if nullifier_count > usize::from(limits.max_nullifiers)
        || output_count > usize::from(limits.max_outputs)
    {
        return Err(ValidationError::LimitExceeded);
    }
    Ok(())
}

pub fn validate_transition_v1(
    output: &NetworkProofOutputV1,
    faucet_asset_tail_hash: [u8; 32],
    encrypted_notes: &[Vec<u8>],
    limits: &TransitionLimitsV1,
) -> Result<(), ValidationError> {
    validate_transition_limits_v1(output, limits)?;
    match &output.transition {
        NetworkTransitionV1::FaucetMint {
            request_id,
            asset_tail_hash,
            public_amount,
            output_commitment,
        } => {
            if *request_id == [0; 32] {
                return Err(ValidationError::InvalidFaucetRequest);
            }
            if *asset_tail_hash != faucet_asset_tail_hash {
                return Err(ValidationError::WrongFaucetAsset);
            }
            if *public_amount == 0 {
                return Err(ValidationError::InvalidFaucetAmount);
            }
            if *output_commitment == [0; 32] {
                return Err(ValidationError::InvalidOutput);
            }
            if encrypted_notes.len() != 1 {
                return Err(ValidationError::OutputNoteCountMismatch);
            }
        }
        NetworkTransitionV1::PrivateTransfer {
            nullifiers,
            output_commitments,
        } => {
            if nullifiers.is_empty() {
                return Err(ValidationError::MissingNullifier);
            }
            if output_commitments.is_empty() {
                return Err(ValidationError::MissingOutput);
            }
            for (index, nullifier) in nullifiers.iter().enumerate() {
                if *nullifier == [0; 32] {
                    return Err(ValidationError::InvalidNullifier);
                }
                if nullifiers[..index].contains(nullifier) {
                    return Err(ValidationError::DuplicateNullifier);
                }
            }
            for (index, output) in output_commitments.iter().enumerate() {
                if *output == [0; 32] {
                    return Err(ValidationError::InvalidOutput);
                }
                if output_commitments[..index].contains(output) {
                    return Err(ValidationError::DuplicateOutput);
                }
            }
            if encrypted_notes.len() != output_commitments.len() {
                return Err(ValidationError::OutputNoteCountMismatch);
            }
        }
    }
    Ok(())
}

pub fn validate_network_output_v1(
    output: &NetworkProofOutputV1,
    expected_network_id: [u8; 32],
    current_height: u64,
    canonical_root: Option<CanonicalRootV1>,
    faucet_asset_tail_hash: [u8; 32],
    policy: &ValidationPolicyV1,
    encrypted_notes: &[Vec<u8>],
) -> Result<(), ValidationError> {
    if output.context.network_id != expected_network_id {
        return Err(ValidationError::WrongNetwork);
    }
    if output.context.protocol_version != NETWORK_PROTOCOL_V1 {
        return Err(ValidationError::UnsupportedVersion);
    }
    let canonical_root = canonical_root.ok_or(ValidationError::UnknownAnchorHeight)?;
    if canonical_root.height != output.context.anchor_height {
        return Err(ValidationError::UnknownAnchorHeight);
    }
    if canonical_root.commitment_root != output.context.ledger_root {
        return Err(ValidationError::LedgerRootMismatch);
    }
    let anchor_age = current_height
        .checked_sub(output.context.anchor_height)
        .ok_or(ValidationError::UnknownAnchorHeight)?;
    if anchor_age >= u64::from(policy.accepted_root_window) {
        return Err(ValidationError::AnchorOutsideWindow);
    }
    if current_height > output.context.expiry_height {
        return Err(ValidationError::ExpiredProof);
    }
    let maximum_expiry = output
        .context
        .anchor_height
        .checked_add(u64::from(policy.max_proof_lifetime))
        .ok_or(ValidationError::LifetimeTooLong)?;
    if output.context.expiry_height > maximum_expiry {
        return Err(ValidationError::LifetimeTooLong);
    }
    validate_transition_v1(
        output,
        faucet_asset_tail_hash,
        encrypted_notes,
        &TransitionLimitsV1 {
            max_nullifiers: policy.max_nullifiers,
            max_outputs: policy.max_outputs,
        },
    )?;
    if output.context.metadata_hash != hash_encrypted_notes_v1(encrypted_notes) {
        return Err(ValidationError::MetadataMismatch);
    }
    Ok(())
}
