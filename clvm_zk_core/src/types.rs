//! core types for clvm evaluation

extern crate alloc;
use alloc::{boxed::Box, string::String, vec::Vec};

use serde::{Deserialize, Serialize};

/// parameter type for program creation - must match host exactly for borsh compatibility
#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
pub enum ProgramParameter {
    /// integer parameter (creates compact clvm atom for small numbers)
    Int(u64),
    /// byte array parameter (creates clvm atom from raw bytes)
    Bytes(Vec<u8>),
}

impl ProgramParameter {
    /// Create an integer parameter
    pub fn int(value: i64) -> Self {
        Self::Int(value as u64)
    }

    /// Create a byte array parameter from a Vec<u8>
    pub fn bytes(data: Vec<u8>) -> Self {
        Self::Bytes(data)
    }

    /// Create a byte array parameter from a slice
    pub fn from_bytes(data: &[u8]) -> Self {
        Self::Bytes(data.to_vec())
    }
}

/// represents a chialisp condition with its opcode and arguments
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Condition {
    pub opcode: u8,         // condition code
    pub args: Vec<Vec<u8>>, // condition arguments as byte vectors
}

impl Condition {
    /// create a new condition
    pub fn new(opcode: u8, args: Vec<Vec<u8>>) -> Self {
        Self { opcode, args }
    }
}

/// internal clvm value representation
#[derive(Debug, Clone, PartialEq)]
pub enum ClvmValue {
    Atom(Vec<u8>),
    Cons(Box<ClvmValue>, Box<ClvmValue>),
}

/// unified error type for clvm-zk operations
#[derive(Debug, thiserror::Error)]
pub enum ClvmZkError {
    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("CLVM error: {0}")]
    ClvmError(String),

    #[error("Prover error: {0}")]
    ProverError(String),

    #[error("Verification error: {0}")]
    VerificationError(String),

    #[error("No real ZK capabilities available")]
    NoRealZkAvailable,

    #[error("Invalid program: {0}")]
    InvalidProgram(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid proof format: {0}")]
    InvalidProofFormat(String),
}

/// common zkvm backend types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKClvmResult {
    pub result: Vec<u8>,
    pub cost: u64,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKClvmNullifierResult {
    pub nullifier: [u8; 32],
    pub result: Vec<u8>,
    pub cost: u64,
    pub proof: Vec<u8>,
}

/// guest program input/output types
#[derive(Serialize, Deserialize, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct PublicInputs {
    // Empty for now - guest generates everything
    // In future could include expected program hash for validation
}

#[derive(Serialize, Deserialize, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct Input {
    /// Raw Chialisp source code (e.g., "(mod (x y) (+ x y))")
    pub chialisp_source: String,
    /// Parameter values for the program - supports both integers and bytes
    pub program_parameters: Vec<ProgramParameter>,
    /// Optional spend secret for nullifier generation
    pub spend_secret: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ClvmOutput {
    pub result: Vec<u8>,
    pub cost: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ProofOutput {
    pub public_inputs: PublicInputs,
    /// Program hash for verification (hash of template bytecode)
    pub program_hash: [u8; 32],
    /// Nullifier for double-spend prevention
    pub nullifier: Option<[u8; 32]>,
    /// CLVM execution result
    pub clvm_output: ClvmOutput,
}
