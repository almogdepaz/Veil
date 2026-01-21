// Wallet module organization
pub mod hd_wallet;
pub mod stealth;
pub mod tests;
pub mod types;

pub use hd_wallet::{AccountKeys, CLVMHDWallet, ValidationError, WalletPrivateCoin};
pub use stealth::{
    // Payment creation
    create_stealth_payment,
    create_stealth_payment_with_mode,
    // Serial derivation
    derive_coin_secrets_from_shared_secret,
    derive_nullifier_secrets_from_shared_secret,
    // Mode types (v2)
    ScannedStealthCoin,
    // Core types
    StealthAddress,
    StealthCoinData,
    StealthKeys,
    StealthMode,
    StealthPayment,
    StealthPaymentV2,
    StealthSpendAuth,
    StealthViewKey,
    // Constants
    STEALTH_NULLIFIER_PUZZLE_HASH,
};
pub use types::{Network, WalletError};
