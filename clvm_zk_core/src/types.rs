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
    /// All committed data from the guest (program_hash, nullifier, clvm_res)
    pub proof_output: ProofOutput,
    /// The actual proof bytes
    pub proof_bytes: Vec<u8>,
}

/// guest program input/output types
#[derive(Serialize, Deserialize, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct Input {
    /// Raw Chialisp source code (e.g., "(mod (x y) (+ x y))")
    pub chialisp_source: String,
    /// Parameter values for the program - supports both integers and bytes
    pub program_parameters: Vec<ProgramParameter>,

    // ============================================================================
    // Serial Commitment Protocol (v2.0) Fields
    // ============================================================================
    /// Serial number (becomes the nullifier when revealed)
    /// This is the unique identifier for the coin being spent
    pub serial_number: Option<[u8; 32]>,

    /// Serial number randomness for commitment opening
    /// Used to prove: serial_commitment = hash(serial_number || serial_randomness)
    pub serial_randomness: Option<[u8; 32]>,

    /// Merkle authentication path for coin membership proof
    /// Each element is a sibling hash in the path from leaf to root
    pub merkle_path: Option<Vec<[u8; 32]>>,

    /// Coin commitment value (hash of coin data including serial_commitment)
    /// This is the leaf value in the merkle tree
    pub coin_commitment: Option<[u8; 32]>,

    /// Expected serial commitment from the coin
    /// Guest will verify: hash(nullifier || serial_randomness) == serial_commitment
    pub serial_commitment: Option<[u8; 32]>,

    /// Expected merkle root (current tree state)
    /// Guest will verify: computed_root == merkle_root
    /// This binds the proof to a specific ledger state, preventing replay attacks
    pub merkle_root: Option<[u8; 32]>,

    /// Leaf index in the merkle tree (for position-based hashing)
    pub leaf_index: Option<usize>,

    /// Puzzle hash that locks the coin (must match program_hash)
    pub puzzle_hash: Option<[u8; 32]>,
}

#[derive(
    Serialize, Deserialize, Debug, Clone, PartialEq, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct ClvmResult {
    pub output: Vec<u8>,
    pub cost: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ProofOutput {
    /// Program hash for verification (hash of template bytecode)
    pub program_hash: [u8; 32],
    /// Nullifier for double-spend prevention
    pub nullifier: Option<[u8; 32]>,
    /// CLVM execution result
    pub clvm_res: ClvmResult,
}
