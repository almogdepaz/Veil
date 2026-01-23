// Wallet module organization
pub mod hd_wallet;
pub mod stealth;
pub mod tests;
pub mod types;

pub use hd_wallet::{AccountKeys, CLVMHDWallet, ValidationError, WalletPrivateCoin};
pub use stealth::{
    create_stealth_payment_hd, derive_nullifier_secrets_from_shared_secret, derive_stealth_tag,
    ScannedStealthCoin, StealthAddress, StealthKeys, StealthPayment, StealthSpendAuth,
    StealthViewKey, STEALTH_NULLIFIER_PUZZLE_HASH,
};
pub use types::{Network, WalletError};
