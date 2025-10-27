use serde::{Deserialize, Serialize};

#[cfg(all(not(feature = "risc0"), not(feature = "sp1"), not(feature = "mock")))]
compile_error!("At least one backend feature must be enabled: risc0, sp1, or mock");

// ensure backends are mutually exclusive
#[cfg(all(feature = "risc0", feature = "sp1"))]
compile_error!("cannot enable both risc0 and sp1 backends simultaneously");

#[cfg(all(feature = "risc0", feature = "mock"))]
compile_error!("cannot enable both risc0 and mock backends simultaneously");

#[cfg(all(feature = "sp1", feature = "mock"))]
compile_error!("cannot enable both sp1 and mock backends simultaneously");

pub mod backends;
pub mod cli;
pub mod crypto_utils;
pub mod internal;
pub mod protocol;
pub mod simulator;
#[cfg(any(test, feature = "testing"))]
pub mod testing_helpers;
pub mod wallet;
pub use clvm_zk_core::{
    ClvmResult, ClvmZkError, Input, ProgramParameter, SerialCommitmentData, ZKClvmResult,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct OperandInput {
    pub operation: String,
    pub operands: Vec<i64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Condition {
    pub opcode: u8,
    pub args: Vec<Vec<u8>>,
}

impl Condition {
    pub fn new(opcode: u8, args: Vec<Vec<u8>>) -> Self {
        Self { opcode, args }
    }

    pub fn create_coin(puzzle_hash: Vec<u8>, amount: u64) -> Self {
        Self::new(
            condition_opcodes::CREATE_COIN,
            vec![puzzle_hash, amount.to_be_bytes().to_vec()],
        )
    }

    pub fn assert_my_coin_id(coin_id: Vec<u8>) -> Self {
        Self::new(condition_opcodes::ASSERT_MY_COIN_ID, vec![coin_id])
    }

    pub fn assert_my_amount(amount: u64) -> Self {
        Self::new(
            condition_opcodes::ASSERT_MY_AMOUNT,
            vec![amount.to_be_bytes().to_vec()],
        )
    }

    pub fn assert_concurrent_spend(coin_id: Vec<u8>) -> Self {
        Self::new(condition_opcodes::ASSERT_CONCURRENT_SPEND, vec![coin_id])
    }

    pub fn assert_concurrent_puzzle(puzzle_hash: Vec<u8>) -> Self {
        Self::new(
            condition_opcodes::ASSERT_CONCURRENT_PUZZLE,
            vec![puzzle_hash],
        )
    }
}

pub mod condition_opcodes {
    pub const AGG_SIG_UNSAFE: u8 = 49;
    pub const AGG_SIG_ME: u8 = 50;
    pub const CREATE_COIN: u8 = 51;
    pub const RESERVE_FEE: u8 = 52;
    pub const ASSERT_CONCURRENT_SPEND: u8 = 64;
    pub const ASSERT_CONCURRENT_PUZZLE: u8 = 65;
    pub const ASSERT_MY_COIN_ID: u8 = 70;
    pub const ASSERT_MY_PARENT_ID: u8 = 71;
    pub const ASSERT_MY_PUZZLEHASH: u8 = 72;
    pub const ASSERT_MY_AMOUNT: u8 = 73;
    pub const CREATE_COIN_ANNOUNCEMENT: u8 = 74;
    pub const ASSERT_COIN_ANNOUNCEMENT: u8 = 75;
    pub const CREATE_PUZZLE_ANNOUNCEMENT: u8 = 76;
    pub const ASSERT_PUZZLE_ANNOUNCEMENT: u8 = 77;
    pub const DIVMOD: u8 = 80;
    pub const MODPOW: u8 = 81;
}

pub struct ClvmZkProver;

impl ClvmZkProver {
    fn validate_chialisp_syntax(expression: &str) -> Result<(), ClvmZkError> {
        use clvm_zk_core::chialisp::parse_chialisp;
        parse_chialisp(expression)
            .map_err(|e| ClvmZkError::InvalidProgram(format!("Syntax error: {:?}", e)))?;
        Ok(())
    }

    pub fn verify_proof(
        expected_program_hash: [u8; 32],
        proof: &[u8],
        expected_output: Option<&[u8]>,
    ) -> Result<(bool, Vec<u8>), ClvmZkError> {
        let backend = crate::backends::backend()?;
        let (proof_valid, extracted_program_hash, extracted_output) =
            backend.verify_proof(proof)?;

        if !proof_valid {
            return Ok((false, vec![]));
        }

        if extracted_program_hash != expected_program_hash {
            return Ok((false, extracted_output));
        }

        if let Some(expected) = expected_output {
            if extracted_output != expected {
                return Ok((false, extracted_output));
            }
        }

        Ok((true, extracted_output))
    }

    pub fn prove(
        expression: &str,
        parameters: &[ProgramParameter],
    ) -> Result<ZKClvmResult, ClvmZkError> {
        if parameters.len() > 10 {
            return Err(ClvmZkError::InvalidProgram(
                "Too many parameters (maximum 10: a-j)".to_string(),
            ));
        }

        Self::validate_chialisp_syntax(expression)?;
        let backend = crate::backends::backend()?;
        backend.prove_program(expression, parameters)
    }

    /// prove spending with serial commitment verification and merkle membership
    #[allow(clippy::too_many_arguments)]
    pub fn prove_with_serial_commitment(
        expression: &str,
        parameters: &[ProgramParameter],
        coin_secrets: &clvm_zk_core::coin_commitment::CoinSecrets,
        merkle_path: Vec<[u8; 32]>,
        coin_commitment: [u8; 32],
        serial_commitment: [u8; 32],
        merkle_root: [u8; 32],
        leaf_index: usize,
        program_hash: [u8; 32],
        amount: u64,
    ) -> Result<ZKClvmResult, ClvmZkError> {
        if parameters.len() > 10 {
            return Err(ClvmZkError::InvalidProgram(
                "Too many parameters (maximum 10: a-j)".to_string(),
            ));
        }

        Self::validate_chialisp_syntax(expression)?;

        let input = Input {
            chialisp_source: expression.to_string(),
            program_parameters: parameters.to_vec(),
            serial_commitment_data: Some(SerialCommitmentData {
                serial_number: coin_secrets.serial_number,
                serial_randomness: coin_secrets.serial_randomness,
                merkle_path,
                coin_commitment,
                serial_commitment,
                merkle_root,
                leaf_index,
                program_hash,
                amount,
            }),
        };

        #[cfg(feature = "risc0")]
        {
            let backend = clvm_zk_risc0::Risc0Backend::new()?;
            return backend.prove_with_input(input);
        }

        #[cfg(feature = "sp1")]
        {
            let backend = clvm_zk_sp1::Sp1Backend::new()?;
            return backend.prove_with_input(input);
        }

        #[cfg(feature = "mock")]
        {
            let backend = clvm_zk_mock::MockBackend::new()?;
            backend.prove_with_input(input)
        }
    }

    /// aggregate multiple proofs into a single recursive proof
    ///
    /// this compresses N transaction proofs into 1 proof while preserving
    /// all nullifiers and conditions.
    ///
    /// returns an error if the backend doesn't support recursion (e.g., mock backend)
    pub fn aggregate_proofs(proofs: &[&[u8]]) -> Result<Vec<u8>, ClvmZkError> {
        let backend = crate::backends::backend()?;
        backend.aggregate_proofs(proofs)
    }
}
