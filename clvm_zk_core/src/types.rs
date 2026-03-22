//! core types for clvm evaluation

extern crate alloc;
use alloc::{boxed::Box, string::String, string::ToString, vec::Vec};

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
///
/// this is the primary error type for the clvm-zk crate. other error types
/// (CompileError, ProtocolError, etc.) can be converted to this type.
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

    #[error("Compilation error: {0}")]
    CompilationError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Merkle proof error: {0}")]
    MerkleError(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Nullifier error: {0}")]
    NullifierError(String),
}

impl ClvmZkError {
    /// create from a static str (useful in no_std contexts)
    pub fn from_static(msg: &'static str) -> Self {
        ClvmZkError::ClvmError(msg.to_string())
    }
}

/// common zkvm backend types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKClvmResult {
    /// All committed data from the guest (program_hash, nullifier, clvm_res)
    pub proof_output: ProofOutput,
    /// The actual proof bytes
    pub proof_bytes: Vec<u8>,
}

/// Coin execution mode — determines what the zkVM guest does with this input.
/// Enforces at compile time that spend and mint are mutually exclusive.
#[derive(
    Serialize, Deserialize, Debug, Clone, Default,
    borsh::BorshSerialize, borsh::BorshDeserialize,
)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum CoinMode {
    /// Pure program execution: no coin commitment, no nullifier emitted.
    /// Used for BLS verification tests and other non-spending proofs.
    #[default]
    Execute,
    /// Spend an existing coin: verify serial commitment + merkle membership, emit nullifier.
    Spend(SerialCommitmentData),
    /// Mint new CAT supply: run TAIL program to authorize, create new coin.
    /// Mutually exclusive with Spend — enforced here, not at runtime.
    Mint(MintData),
}

/// Unified guest program input type
#[derive(Serialize, Deserialize, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct Input {
    /// Raw Chialisp source code (e.g., "(mod (x y) (+ x y))")
    pub chialisp_source: String,
    /// Parameter values for the program - supports both integers and bytes
    pub program_parameters: Vec<ProgramParameter>,

    /// Coin execution mode (spend, mint, or pure execution)
    pub coin_mode: CoinMode,

    /// Asset type identifier (TAIL hash)
    /// - None: XCH (native currency, equivalent to [0u8; 32])
    /// - Some(hash): CAT with this TAIL program hash
    #[serde(default)]
    pub tail_hash: Option<[u8; 32]>,

    /// TAIL source for spend-path delta authorization (melt/burn only).
    ///
    /// When implementing enforcement, callers MUST verify this field is `Some`
    /// for any CAT spend where delta < 0 (sum(outputs) < sum(inputs)).
    /// Do NOT rely on `is_some()` as the sole guard — callers that omit this
    /// field in JSON will deserialize as `None`, bypassing any `is_some()` check.
    /// Enforcement must explicitly reject `None` for negative-delta CAT spends.
    ///
    /// - `None` + delta == 0: pure transfer, TAIL not called
    /// - `Some(_)` + delta < 0: TAIL must authorize the melt
    /// - `None` + delta < 0 on a CAT: MUST be rejected by enforcement code
    /// - delta > 0: rejected at protocol level (use CoinMode::Mint instead)
    pub tail_source: Option<String>,

    /// additional coins for multi-coin ring spends
    /// - None: single coin spend
    /// - Some(vec): multi-coin ring spend (all coins share same tail_hash)
    #[serde(default)]
    pub additional_coins: Option<Vec<AdditionalCoinInput>>,
}

/// mint data for CAT issuance proofs
/// when present, guest executes TAIL program and creates new coin if authorized
#[derive(Serialize, Deserialize, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct MintData {
    /// TAIL program source (controls who can mint)
    /// e.g., "(mod () 1)" for unlimited, "(mod (pk sig) (bls_verify ...))" for signature-based
    pub tail_source: String,
    /// parameters to satisfy the TAIL program
    /// NOTE: genesis_nullifier is prepended automatically if genesis_coin is present
    pub tail_params: Vec<ProgramParameter>,
    /// puzzle hash for the new coin (where it can be spent)
    pub output_puzzle_hash: [u8; 32],
    /// amount to mint
    pub output_amount: u64,
    /// serial number for the new coin (for nullifier generation when spent)
    pub output_serial: [u8; 32],
    /// serial randomness for commitment hiding
    pub output_rand: [u8; 32],
    /// optional genesis coin that authorizes this mint
    /// when present, guest verifies genesis coin exists in merkle tree,
    /// computes its nullifier, and passes it to TAIL as first param.
    /// the genesis nullifier is included in proof output → validators add to nullifier set
    /// → genesis can't be reused → prevents infinite minting
    #[serde(default)]
    pub genesis_coin: Option<GenesisSpend>,
}

/// genesis coin data for single-issuance CAT minting
/// the genesis coin is spent during mint, producing a nullifier that prevents re-minting
#[derive(Serialize, Deserialize, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct GenesisSpend {
    /// serial number of the genesis coin
    pub serial_number: [u8; 32],
    /// serial randomness for opening the commitment
    pub serial_randomness: [u8; 32],
    /// puzzle hash of the genesis coin
    pub puzzle_hash: [u8; 32],
    /// amount locked in the genesis coin
    pub amount: u64,
    /// tail_hash of the genesis coin (typically XCH = [0;32])
    pub tail_hash: [u8; 32],
    /// serial commitment (hash(serial_number || serial_randomness))
    pub serial_commitment: [u8; 32],
    /// coin commitment (leaf in merkle tree)
    pub coin_commitment: [u8; 32],
    /// merkle proof path from leaf to root
    pub merkle_path: Vec<[u8; 32]>,
    /// merkle root (current tree state)
    pub merkle_root: [u8; 32],
    /// leaf index in tree
    /// u64 (not usize) for consistent Borsh encoding across 32-bit guest and 64-bit host
    pub leaf_index: u64,
}

/// additional coin input for ring spends
/// each coin evaluates independently but shares announcement verification
#[derive(Serialize, Deserialize, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct AdditionalCoinInput {
    /// Chialisp source for this coin (typically same CAT puzzle as primary)
    pub chialisp_source: String,
    /// Parameters for this coin's puzzle
    pub program_parameters: Vec<ProgramParameter>,
    /// Serial commitment data (required for ring coins)
    pub serial_commitment_data: SerialCommitmentData,
    /// Asset type (must match primary coin's tail_hash for valid ring)
    pub tail_hash: [u8; 32],
}

/// Serial commitment protocol data for nullifier-based spending
/// When None, guest performs simple program execution without nullifier verification
#[derive(Serialize, Deserialize, Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SerialCommitmentData {
    /// Serial number (becomes the nullifier when revealed)
    /// This is the unique identifier for the coin being spent
    pub serial_number: [u8; 32],

    /// Serial number randomness for commitment opening
    /// Used to prove: serial_commitment = hash(serial_number || serial_randomness)
    pub serial_randomness: [u8; 32],

    /// Merkle authentication path for coin membership proof
    /// Each element is a sibling hash in the path from leaf to root
    pub merkle_path: Vec<[u8; 32]>,

    /// Coin commitment value (hash of coin data including serial_commitment)
    /// This is the leaf value in the merkle tree
    pub coin_commitment: [u8; 32],

    /// Expected serial commitment from the coin
    /// Guest will verify: hash(serial_number || serial_randomness) == serial_commitment
    pub serial_commitment: [u8; 32],

    /// Expected merkle root (current tree state)
    /// Guest will verify: computed_root == merkle_root
    /// This binds the proof to a specific ledger state, preventing replay attacks
    pub merkle_root: [u8; 32],

    /// Leaf index in the merkle tree (for position-based hashing)
    /// u64 (not usize) for consistent Borsh encoding across 32-bit guest and 64-bit host
    pub leaf_index: u64,

    /// Puzzle hash that locks the coin (must match program_hash)
    pub program_hash: [u8; 32],

    /// Coin amount
    pub amount: u64,
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
    /// Nullifiers for double-spend prevention
    /// - Empty vec: No nullifier (simple program execution)
    /// - Single element: Standard spend (one coin)
    /// - Multiple elements: Ring spend (CAT multi-coin transaction)
    pub nullifiers: Vec<[u8; 32]>,
    /// CLVM execution result
    pub clvm_res: ClvmResult,
    /// Proof type (Transaction, ConditionalSpend, Settlement)
    #[serde(default = "default_proof_type_u8")]
    #[borsh(skip)]
    pub proof_type: u8,
    /// Additional public values (merkle_root, amount, etc.)
    #[serde(default)]
    pub public_values: Vec<Vec<u8>>,
}

fn default_proof_type_u8() -> u8 {
    0 // Transaction
}

/// aggregated proof output (no_std compatible)
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AggregatedOutput {
    pub nullifiers: alloc::vec::Vec<[u8; 32]>,
    pub conditions: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    pub commitments: alloc::vec::Vec<[u8; 32]>, // flat array of proof commitments
}
