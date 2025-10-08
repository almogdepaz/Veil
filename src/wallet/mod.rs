// Wallet module organization
pub mod hd_wallet;
pub mod tests;
pub mod types;

// Re-exports (specific to avoid ambiguity)
pub use hd_wallet::{CLVMHDWallet, ValidationError, WalletPrivateCoin, WalletRecovery};
pub use types::{Network, WalletError};

// Use HD wallet versions as primary (more complete implementations)
pub use hd_wallet::{AccountKeys, CoinKeys, SpendSecret, ViewingKey, WalletNullifier};
