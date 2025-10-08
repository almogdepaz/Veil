// ============================================================================
// Core Types for CLVM-ZK Wallet System
// ============================================================================

use serde::{Deserialize, Serialize};

/// Network type for key derivation
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn coin_type(&self) -> u32 {
        match self {
            Network::Mainnet => 8444, // Chia mainnet
            Network::Testnet => 1,    // Testnet standard
        }
    }

    pub fn to_bytes(&self) -> [u8; 1] {
        match self {
            Network::Mainnet => [0x00],
            Network::Testnet => [0x01],
        }
    }
}

/// Core error type for the wallet system
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("Invalid seed (must be 16-64 bytes)")]
    InvalidSeed,

    #[error("Invalid BIP32 child number")]
    Bip32Error(#[from] bip32::Error),

    #[error("Key derivation failed")]
    DerivationFailed,

    #[error("Cryptographic operation failed")]
    CryptoError,
}
