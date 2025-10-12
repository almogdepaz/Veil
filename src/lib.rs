use serde::{Deserialize, Serialize};

// Using guest-side compilation now

// ensure at least one backend is enabled
#[cfg(all(not(feature = "risc0"), not(feature = "sp1"), not(feature = "mock")))]
compile_error!("At least one backend feature must be enabled: risc0, sp1, or mock");

// ensure backends are mutually exclusive
#[cfg(all(feature = "risc0", feature = "sp1"))]
compile_error!("cannot enable both risc0 and sp1 backends simultaneously");

#[cfg(all(feature = "risc0", feature = "mock"))]
compile_error!("cannot enable both risc0 and mock backends simultaneously");

#[cfg(all(feature = "sp1", feature = "mock"))]
compile_error!("cannot enable both sp1 and mock backends simultaneously");

// Module declarations
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
    ClvmOutput, ClvmZkError, Input, ProgramParameter, PublicInputs, ZKClvmNullifierResult,
    ZKClvmResult,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct OperandInput {
    pub operation: String,
    pub operands: Vec<i64>,
}

/// a chialisp condition - basically an instruction with some data
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Condition {
    pub opcode: u8,
    pub args: Vec<Vec<u8>>,
}

impl Condition {
    /// make a new condition
    pub fn new(opcode: u8, args: Vec<Vec<u8>>) -> Self {
        Self { opcode, args }
    }

    /// make a "create coin" condition
    pub fn create_coin(puzzle_hash: Vec<u8>, amount: u64) -> Self {
        Self::new(
            condition_opcodes::CREATE_COIN,
            vec![puzzle_hash, amount.to_be_bytes().to_vec()],
        )
    }

    /// make an "assert my coin id" condition
    pub fn assert_my_coin_id(coin_id: Vec<u8>) -> Self {
        Self::new(condition_opcodes::ASSERT_MY_COIN_ID, vec![coin_id])
    }

    /// make an "assert my amount" condition
    pub fn assert_my_amount(amount: u64) -> Self {
        Self::new(
            condition_opcodes::ASSERT_MY_AMOUNT,
            vec![amount.to_be_bytes().to_vec()],
        )
    }

    /// make an "assert concurrent spend" condition
    pub fn assert_concurrent_spend(coin_id: Vec<u8>) -> Self {
        Self::new(condition_opcodes::ASSERT_CONCURRENT_SPEND, vec![coin_id])
    }

    /// make an "assert concurrent puzzle" condition
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

    pub fn prove_with_nullifier(
        expression: &str,
        parameters: &[ProgramParameter],
        spend_secret: [u8; 32],
    ) -> Result<clvm_zk_core::ZKClvmNullifierResult, ClvmZkError> {
        if parameters.len() > 10 {
            return Err(ClvmZkError::InvalidProgram(
                "Too many parameters (maximum 10: a-j)".to_string(),
            ));
        }

        Self::validate_chialisp_syntax(expression)?;
        let backend = crate::backends::backend()?;
        backend.prove_with_nullifier(expression, parameters, spend_secret)
    }
}
