use clvm_zk_core::{
    NetworkContextV1, NetworkProofOutputV1, NetworkTransitionV1, NETWORK_PROTOCOL_V1,
};
use veil_ledger::{
    decode_network_output_v1, hash_encrypted_notes_v1, validate_network_output_v1,
    validate_transition_limits_v1, validate_transition_v1, CanonicalRootV1, TransitionLimitsV1,
    ValidationError, ValidationPolicyV1,
};

fn output() -> NetworkProofOutputV1 {
    NetworkProofOutputV1 {
        context: NetworkContextV1 {
            network_id: [1; 32],
            protocol_version: NETWORK_PROTOCOL_V1,
            ledger_root: [2; 32],
            anchor_height: 10,
            expiry_height: 15,
            metadata_hash: hash_encrypted_notes_v1(&[vec![3, 4]]),
        },
        program_hash: [5; 32],
        transition: NetworkTransitionV1::PrivateTransfer {
            nullifiers: vec![[6; 32]],
            output_commitments: vec![[7; 32]],
        },
        public_conditions: vec![8],
        execution_cost: 9,
    }
}

fn canonical(root: [u8; 32]) -> CanonicalRootV1 {
    CanonicalRootV1 {
        height: 10,
        commitment_root: root,
    }
}

fn policy() -> ValidationPolicyV1 {
    ValidationPolicyV1 {
        accepted_root_window: 32,
        max_proof_lifetime: 32,
        max_nullifiers: 4,
        max_outputs: 4,
    }
}

fn limits() -> TransitionLimitsV1 {
    TransitionLimitsV1 {
        max_nullifiers: 4,
        max_outputs: 4,
    }
}

#[test]
fn accepts_exact_known_root_inside_window_and_lifetime() {
    assert_eq!(
        validate_network_output_v1(
            &output(),
            [1; 32],
            12,
            Some(canonical([2; 32])),
            [10; 32],
            &policy(),
            &[vec![3, 4]],
        ),
        Ok(())
    );
}

#[test]
fn rejects_unknown_wrong_expired_and_overlong_roots() {
    assert_eq!(
        validate_network_output_v1(
            &output(),
            [1; 32],
            12,
            None,
            [10; 32],
            &policy(),
            &[vec![3, 4]],
        ),
        Err(ValidationError::UnknownAnchorHeight)
    );
    assert_eq!(
        validate_network_output_v1(
            &output(),
            [1; 32],
            12,
            Some(CanonicalRootV1 {
                height: 11,
                commitment_root: [2; 32],
            }),
            [10; 32],
            &policy(),
            &[vec![3, 4]],
        ),
        Err(ValidationError::UnknownAnchorHeight)
    );
    assert_eq!(
        validate_network_output_v1(
            &output(),
            [1; 32],
            12,
            Some(canonical([9; 32])),
            [10; 32],
            &policy(),
            &[vec![3, 4]],
        ),
        Err(ValidationError::LedgerRootMismatch)
    );

    let mut expired = output();
    expired.context.expiry_height = 11;
    assert_eq!(
        validate_network_output_v1(
            &expired,
            [1; 32],
            12,
            Some(canonical([2; 32])),
            [10; 32],
            &policy(),
            &[vec![3, 4]],
        ),
        Err(ValidationError::ExpiredProof)
    );

    let mut overlong = output();
    overlong.context.expiry_height = 43;
    assert_eq!(
        validate_network_output_v1(
            &overlong,
            [1; 32],
            12,
            Some(canonical([2; 32])),
            [10; 32],
            &policy(),
            &[vec![3, 4]],
        ),
        Err(ValidationError::LifetimeTooLong)
    );
}

#[test]
fn changing_notes_after_proving_is_rejected() {
    assert_eq!(
        validate_network_output_v1(
            &output(),
            [1; 32],
            12,
            Some(canonical([2; 32])),
            [10; 32],
            &policy(),
            &[vec![3, 5]],
        ),
        Err(ValidationError::MetadataMismatch)
    );
}

#[test]
fn strict_decode_rejects_trailing_bytes() {
    let mut bytes = borsh::to_vec(&output()).unwrap();
    bytes.push(0);

    assert_eq!(
        decode_network_output_v1(&bytes),
        Err(ValidationError::InvalidProofEncoding)
    );
}

#[test]
fn transition_validation_enforces_note_count_and_faucet_asset() {
    let mut transfer = output();
    transfer.context.metadata_hash = hash_encrypted_notes_v1(&[]);
    assert_eq!(
        validate_transition_v1(&transfer, [8; 32], &[], &limits()),
        Err(ValidationError::OutputNoteCountMismatch)
    );

    let mut faucet = output();
    faucet.transition = NetworkTransitionV1::FaucetMint {
        request_id: [9; 32],
        asset_tail_hash: [10; 32],
        public_amount: 100,
        output_commitment: [11; 32],
    };
    assert_eq!(
        validate_transition_v1(&faucet, [12; 32], &[vec![3, 4]], &limits()),
        Err(ValidationError::WrongFaucetAsset)
    );
    assert_eq!(
        validate_transition_v1(&faucet, [10; 32], &[vec![3, 4]], &limits()),
        Ok(())
    );
}

#[test]
fn transition_validation_rejects_empty_zero_and_duplicate_values() {
    let mut transfer = output();
    transfer.transition = NetworkTransitionV1::PrivateTransfer {
        nullifiers: vec![[6; 32], [6; 32]],
        output_commitments: vec![[7; 32]],
    };
    assert_eq!(
        validate_transition_v1(&transfer, [8; 32], &[vec![3, 4]], &limits()),
        Err(ValidationError::DuplicateNullifier)
    );

    transfer.transition = NetworkTransitionV1::PrivateTransfer {
        nullifiers: vec![[6; 32]],
        output_commitments: vec![[7; 32], [7; 32]],
    };
    assert_eq!(
        validate_transition_v1(&transfer, [8; 32], &[vec![3, 4], vec![5, 6]], &limits(),),
        Err(ValidationError::DuplicateOutput)
    );

    transfer.transition = NetworkTransitionV1::PrivateTransfer {
        nullifiers: vec![[0; 32]],
        output_commitments: vec![[7; 32]],
    };
    assert_eq!(
        validate_transition_v1(&transfer, [8; 32], &[vec![3, 4]], &limits()),
        Err(ValidationError::InvalidNullifier)
    );
}

#[test]
fn transition_limits_are_checked_before_duplicate_scans() {
    let mut transfer = output();
    transfer.transition = NetworkTransitionV1::PrivateTransfer {
        nullifiers: vec![[6; 32]; 5],
        output_commitments: vec![[7; 32]],
    };
    let limits = TransitionLimitsV1 {
        max_nullifiers: 4,
        max_outputs: 4,
    };

    assert_eq!(
        validate_transition_limits_v1(&transfer, &limits),
        Err(ValidationError::LimitExceeded)
    );
}
