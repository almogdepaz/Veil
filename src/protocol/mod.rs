//! Nullifier Protocol Implementation
//!
//! This module implements a secure nullifier protocol for preventing double-spending
//! in zero-knowledge transactions. The protocol uses the "Mandatory Output Channel"
//! model to ensure that nullifier generation is automatic and cannot be bypassed.
//!
//! ## Core Concepts
//!
//! - **PrivateCoin**: A coin with a secret spend_secret that generates a unique nullifier
//! - **Nullifier**: SHA256(spend_secret) - public value that prevents double-spending
//! - **PrivateSpendBundle**: Complete spend transaction with ZK proof and public outputs
//! - **Mandatory Output**: Nullifier generation happens automatically in ZK guest
//!
//! ## Security Model
//!
//! 1. Each coin has a unique 32-byte `spend_secret`
//! 2. The nullifier is computed as `SHA256(spend_secret)`  
//! 3. Nullifiers are public and stored on-chain to prevent double-spending
//! 4. Spend secrets remain private within ZK proofs
//! 5. L1 blockchain validates nullifiers haven't been used before
//! ```

pub mod encrypted_notes;
pub mod offers;
pub mod puzzles;
pub mod recursive;
pub mod spender;
pub mod structures;

// Re-export main types for convenient access
pub use encrypted_notes::{EncryptedNote, PaymentNote};
pub use offers::{ConditionalOffer, OfferMetadata};
pub use puzzles::{
    create_password_puzzle, create_password_puzzle_program, create_password_spend_parameters,
    create_password_spend_params, create_signature_puzzle, create_signature_spend_params,
    create_spend_signature, create_test_signature_setup, hash_password,
};
pub use recursive::{AggregatedOutput, AggregatedProof};
pub use spender::Spender;
pub use structures::{PrivateCoin, PrivateSpendBundle, ProtocolError, ProofType};
