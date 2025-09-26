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
//!
//! ## Usage Example
//!
//! ```rust
//! use clvm_zk::protocol::{PrivateCoin, Spender};
//! use clvm_zk::ProgramParameter;
//!
//! // Create a private coin
//! let coin = PrivateCoin::new_random("(+ a b)".to_string(), 1000);
//! println!("Coin nullifier: {}", coin.nullifier_hex());
//!
//! // Spend the coin (will be available after Task 1.3)
//! // let bundle = Spender::create_spend(&coin, &[
//! //     ProgramParameter::int(5),
//! //     ProgramParameter::int(3)
//! // ])?;
//! ```

pub mod spender;
pub mod structures;
pub mod puzzles;

// Re-export main types for convenient access
pub use spender::Spender;
pub use structures::{PrivateCoin, PrivateSpendBundle, ProtocolError};
pub use puzzles::{create_signature_puzzle, create_test_signature_setup, create_spend_signature, create_signature_spend_params, create_password_puzzle, create_password_spend_params, hash_password, create_password_puzzle_program, create_password_spend_parameters};