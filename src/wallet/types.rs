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
///
/// can be converted to `ClvmZkError` for unified error handling
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

impl From<WalletError> for clvm_zk_core::ClvmZkError {
    fn from(err: WalletError) -> Self {
        match err {
            WalletError::InvalidSeed => {
                clvm_zk_core::ClvmZkError::InvalidInput("invalid seed".to_string())
            }
            WalletError::Bip32Error(e) => clvm_zk_core::ClvmZkError::CryptoError(e.to_string()),
            WalletError::DerivationFailed => {
                clvm_zk_core::ClvmZkError::CryptoError("key derivation failed".to_string())
            }
            WalletError::CryptoError => {
                clvm_zk_core::ClvmZkError::CryptoError("cryptographic operation failed".to_string())
            }
        }
    }
}
