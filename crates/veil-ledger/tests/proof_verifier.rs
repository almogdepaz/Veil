use clvm_zk_core::{
    NetworkContextV1, NetworkProofOutputV1, NetworkTransitionV1, NETWORK_PROTOCOL_V1,
};
use veil_ledger::{
    decode_network_output_v1, verify_network_proof_v1, BackendIdV1, ProofVerifier, ValidationError,
};

struct FixtureVerifier {
    program_id: [u8; 32],
}

impl ProofVerifier for FixtureVerifier {
    fn backend_id(&self) -> BackendIdV1 {
        BackendIdV1::Sp1
    }

    fn program_id(&self) -> [u8; 32] {
        self.program_id
    }

    fn verify_and_decode(&self, proof: &[u8]) -> Result<NetworkProofOutputV1, ValidationError> {
        decode_network_output_v1(proof)
    }
}

fn proof_bytes() -> Vec<u8> {
    borsh::to_vec(&NetworkProofOutputV1 {
        context: NetworkContextV1 {
            network_id: [1; 32],
            protocol_version: NETWORK_PROTOCOL_V1,
            ledger_root: [2; 32],
            anchor_height: 3,
            expiry_height: 4,
            metadata_hash: [5; 32],
        },
        program_hash: [6; 32],
        transition: NetworkTransitionV1::PrivateTransfer {
            nullifiers: vec![[7; 32]],
            output_commitments: vec![[8; 32]],
        },
        public_conditions: vec![9],
        execution_cost: 10,
    })
    .unwrap()
}

#[test]
fn verifies_only_with_pinned_backend_program_and_size_limit() {
    let verifier = FixtureVerifier {
        program_id: [11; 32],
    };
    let proof = proof_bytes();

    assert!(
        verify_network_proof_v1(&verifier, &proof, proof.len(), BackendIdV1::Sp1, [11; 32],)
            .is_ok()
    );
    assert_eq!(
        verify_network_proof_v1(
            &verifier,
            &proof,
            proof.len() - 1,
            BackendIdV1::Sp1,
            [11; 32],
        ),
        Err(ValidationError::ProofTooLarge)
    );
    assert_eq!(
        verify_network_proof_v1(&verifier, &proof, proof.len(), BackendIdV1::Risc0, [11; 32],),
        Err(ValidationError::UnsupportedBackend)
    );
    assert_eq!(
        verify_network_proof_v1(&verifier, &proof, proof.len(), BackendIdV1::Sp1, [12; 32],),
        Err(ValidationError::WrongProgram)
    );
}
