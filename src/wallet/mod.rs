// Wallet module organization
pub mod types;
pub mod hd_wallet;
pub mod tests;

// Re-exports (specific to avoid ambiguity)
pub use types::{Network, WalletError};
pub use hd_wallet::{CLVMHDWallet, WalletPrivateCoin, WalletRecovery, ValidationError};

// Use HD wallet versions as primary (more complete implementations)
pub use hd_wallet::{AccountKeys, CoinKeys, SpendSecret, ViewingKey, WalletNullifier};