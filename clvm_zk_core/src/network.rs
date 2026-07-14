//! Versioned network proof contract validation shared by every backend.

use crate::{
    CoinMode, Input, NetworkExecutionResultV1, NetworkProofIntentV1, NetworkProofOutputV1,
    NetworkProofRequestV1, NetworkTransitionV1, NETWORK_PROTOCOL_V1,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NetworkProofErrorV1 {
    #[error("network proof request is required")]
    MissingRequest,
    #[error("unsupported network protocol version")]
    UnsupportedVersion,
    #[error("anchor height exceeds expiry height")]
    InvalidHeightRange,
    #[error("network proof intent does not match coin mode")]
    IntentModeMismatch,
    #[error("network proof membership root does not match context root")]
    LedgerRootMismatch,
    #[error("faucet mint requires an explicit non-zero asset TAIL hash")]
    MissingAssetTailHash,
    #[error("faucet mint execution did not produce an output commitment")]
    MissingMintOutputCommitment,
    #[error("faucet mint cannot consume a genesis coin")]
    UnsupportedFaucetGenesis,
}

pub fn validate_network_request_v1(
    input: &Input,
) -> Result<&NetworkProofRequestV1, NetworkProofErrorV1> {
    let request = input
        .network
        .as_ref()
        .ok_or(NetworkProofErrorV1::MissingRequest)?;

    if request.context.protocol_version != NETWORK_PROTOCOL_V1 {
        return Err(NetworkProofErrorV1::UnsupportedVersion);
    }
    if request.context.anchor_height > request.context.expiry_height {
        return Err(NetworkProofErrorV1::InvalidHeightRange);
    }

    match (&request.intent, &input.coin_mode) {
        (NetworkProofIntentV1::FaucetMint { .. }, CoinMode::Mint(mint)) => {
            if input.tail_hash.is_none_or(|tail_hash| tail_hash == [0; 32]) {
                return Err(NetworkProofErrorV1::MissingAssetTailHash);
            }
            if mint.genesis_coin.is_some() {
                return Err(NetworkProofErrorV1::UnsupportedFaucetGenesis);
            }
        }
        (NetworkProofIntentV1::PrivateTransfer, CoinMode::Spend(primary)) => {
            if primary.merkle_root != request.context.ledger_root {
                return Err(NetworkProofErrorV1::LedgerRootMismatch);
            }
            if input.additional_coins.as_ref().is_some_and(|coins| {
                coins.iter().any(|coin| {
                    coin.serial_commitment_data.merkle_root != request.context.ledger_root
                })
            }) {
                return Err(NetworkProofErrorV1::LedgerRootMismatch);
            }
        }
        _ => return Err(NetworkProofErrorV1::IntentModeMismatch),
    }

    Ok(request)
}

pub fn build_network_proof_output_v1(
    input: &Input,
    execution: NetworkExecutionResultV1,
) -> Result<NetworkProofOutputV1, NetworkProofErrorV1> {
    let request = validate_network_request_v1(input)?;

    let transition = match (&request.intent, &input.coin_mode) {
        (NetworkProofIntentV1::FaucetMint { request_id }, CoinMode::Mint(mint)) => {
            let output_commitment = execution
                .mint_output_commitment
                .ok_or(NetworkProofErrorV1::MissingMintOutputCommitment)?;
            let asset_tail_hash = input
                .tail_hash
                .ok_or(NetworkProofErrorV1::MissingAssetTailHash)?;
            NetworkTransitionV1::FaucetMint {
                request_id: *request_id,
                asset_tail_hash,
                public_amount: mint.output_amount,
                output_commitment,
            }
        }
        (NetworkProofIntentV1::PrivateTransfer, CoinMode::Spend(_)) => {
            NetworkTransitionV1::PrivateTransfer {
                nullifiers: execution.nullifiers,
                output_commitments: execution.output_commitments,
            }
        }
        _ => return Err(NetworkProofErrorV1::IntentModeMismatch),
    };

    Ok(NetworkProofOutputV1 {
        context: request.context.clone(),
        program_hash: execution.program_hash,
        transition,
        public_conditions: execution.public_conditions,
        execution_cost: execution.execution_cost,
    })
}
