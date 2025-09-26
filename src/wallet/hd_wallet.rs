// ============================================================================
// CLVM-ZK HD Wallet with Proper bip32 v0.5 API
// Zcash-style key derivation with domain-separated nullifiers
// ============================================================================

use bip32::{ChildNumber, XPrv, XPub};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// HD Wallet with bip32 v0.5
// ============================================================================

pub struct CLVMHDWallet {
    master: XPrv,
    network: crate::wallet::Network,
}

impl CLVMHDWallet {
    /// Create wallet from seed (16-64 bytes)
    pub fn from_seed(
        seed: &[u8],
        network: crate::wallet::Network,
    ) -> Result<Self, crate::wallet::WalletError> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(crate::wallet::WalletError::InvalidSeed);
        }

        // Convert seed to 32 bytes if needed
        let seed_32 = if seed.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(seed);
            arr
        } else {
            // Hash to get exactly 32 bytes
            Sha256::digest(seed).into()
        };

        let master = XPrv::new(seed_32).map_err(|_| crate::wallet::WalletError::InvalidSeed)?;

        Ok(Self { master, network })
    }

    /// Derive a key from a BIP44 path by iterating through child derivations
    fn derive_path(&self, path: &[ChildNumber]) -> Result<XPrv, crate::wallet::WalletError> {
        let mut current_key = self.master.clone();

        for &child_number in path {
            current_key = current_key
                .derive_child(child_number)
                .map_err(|e| crate::wallet::WalletError::Bip32Error(e))?;
        }

        Ok(current_key)
    }

    /// Derive account-level keys following BIP44
    /// Path: m/44'/coin_type'/account'/0'
    pub fn derive_account(
        &self,
        account_index: u32,
    ) -> Result<AccountKeys, crate::wallet::WalletError> {
        // Build BIP44 path
        let path = [
            ChildNumber::new(44, true)?,                       // purpose (hardened)
            ChildNumber::new(self.network.coin_type(), true)?, // coin type (hardened)
            ChildNumber::new(account_index, true)?,            // account (hardened)
            ChildNumber::new(0, true)?,                        // reserved (hardened)
        ];

        let account_xprv = self.derive_path(&path)?;
        let account_bytes = account_xprv.to_bytes();

        // Derive spending key from account XPrv
        let spending_key = {
            let mut hasher = Sha256::new();
            hasher.update(b"clvm_zk_spend_auth_v1");
            hasher.update(&account_bytes);
            hasher.update(&self.network.to_bytes());
            hasher.finalize().into()
        };

        // Derive viewing key from spending key
        let viewing_key = {
            let mut hasher = Sha256::new();
            hasher.update(b"clvm_zk_view_key_v1");
            hasher.update(&spending_key);
            hasher.finalize().into()
        };

        // Derive nullifier key from spending key
        let nullifier_key = {
            let mut hasher = Sha256::new();
            hasher.update(b"clvm_zk_nullifier_key_v1");
            hasher.update(&spending_key);
            hasher.finalize().into()
        };

        Ok(AccountKeys {
            spending_key,
            viewing_key,
            nullifier_key,
            account_index,
            network: self.network,
            _account_xprv: account_xprv,
        })
    }

    /// Derive spend_secret for a specific coin
    /// This uses account keys, not direct BIP32 derivation
    pub fn derive_spend_secret(
        &self,
        account_index: u32,
        coin_index: u32,
    ) -> Result<SpendSecret, crate::wallet::WalletError> {
        let account = self.derive_account(account_index)?;

        // Use HMAC to derive coin-specific spend_secret from account spending key
        let mut mac = HmacSha256::new_from_slice(&account.spending_key)
            .map_err(|_| crate::wallet::WalletError::CryptoError)?;
        mac.update(b"coin_spend_secret");
        mac.update(&coin_index.to_le_bytes());

        let secret: [u8; 32] = mac.finalize().into_bytes().into();

        Ok(SpendSecret {
            secret,
            account_index,
            coin_index,
        })
    }

    /// Create nullifier with domain separation and puzzle binding
    pub fn create_nullifier(
        &self,
        account_index: u32,
        coin_index: u32,
        puzzle_hash: [u8; 32],
    ) -> Result<WalletNullifier, crate::wallet::WalletError> {
        let spend_secret = self.derive_spend_secret(account_index, coin_index)?;

        // Domain-separated nullifier construction
        let bytes = crate::crypto_utils::generate_nullifier(&spend_secret.secret, &puzzle_hash);

        Ok(WalletNullifier {
            bytes,
            spend_secret: spend_secret.secret,
            puzzle_hash,
        })
    }

    /// Get extended public key for account (for view-only wallets)
    pub fn account_xpub(&self, account_index: u32) -> Result<XPub, crate::wallet::WalletError> {
        let account = self.derive_account(account_index)?;
        Ok(XPub::from(&account._account_xprv))
    }
}

// ============================================================================
// Account Keys
// ============================================================================

pub struct AccountKeys {
    pub spending_key: [u8; 32],
    pub viewing_key: [u8; 32],
    pub nullifier_key: [u8; 32],
    pub account_index: u32,
    pub network: crate::wallet::Network,
    _account_xprv: XPrv, // Keep for potential child derivation
}

impl AccountKeys {
    /// Derive coin-specific keys within this account
    pub fn derive_coin_keys(&self, coin_index: u32, puzzle_hash: [u8; 32]) -> CoinKeys {
        // Derive spend_secret using HMAC
        let mut mac = HmacSha256::new_from_slice(&self.spending_key).expect("Valid HMAC key");
        mac.update(b"coin_spend_secret");
        mac.update(&coin_index.to_le_bytes());
        let spend_secret: [u8; 32] = mac.finalize().into_bytes().into();

        // Create viewing tag (first 4 bytes of hash)
        let viewing_tag = crate::crypto_utils::generate_viewing_tag(&self.viewing_key, coin_index);

        // Create nullifier with domain separation
        let nullifier = crate::crypto_utils::generate_nullifier(&spend_secret, &puzzle_hash);

        CoinKeys {
            spend_secret,
            viewing_tag,
            nullifier,
            puzzle_hash,
            coin_index,
        }
    }

    /// Export viewing key for auditing
    pub fn export_viewing_key(&self) -> ViewingKey {
        ViewingKey {
            key: self.viewing_key,
            account_index: self.account_index,
            network: self.network,
        }
    }
}

// ============================================================================
// Key Types
// ============================================================================

#[derive(Clone, Debug)]
pub struct SpendSecret {
    pub secret: [u8; 32],
    pub account_index: u32,
    pub coin_index: u32,
}

#[derive(Clone, Debug)]
pub struct WalletNullifier {
    pub bytes: [u8; 32],
    pub spend_secret: [u8; 32],
    pub puzzle_hash: [u8; 32],
}

impl WalletNullifier {
    /// Verify nullifier was constructed correctly
    pub fn verify(&self, spend_secret: &[u8; 32], puzzle_hash: &[u8; 32]) -> bool {
        let expected = crate::crypto_utils::generate_nullifier(spend_secret, puzzle_hash);
        self.bytes == expected
    }
}

#[derive(Clone, Debug)]
pub struct CoinKeys {
    pub spend_secret: [u8; 32],
    pub viewing_tag: [u8; 4],
    pub nullifier: [u8; 32],
    pub puzzle_hash: [u8; 32],
    pub coin_index: u32,
}

// ============================================================================
// View-Only Wallet
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewingKey {
    pub key: [u8; 32],
    pub account_index: u32,
    pub network: crate::wallet::Network,
}

pub struct ViewOnlyWallet {
    viewing_key: ViewingKey,
}

impl ViewOnlyWallet {
    pub fn from_viewing_key(viewing_key: ViewingKey) -> Self {
        Self { viewing_key }
    }

    /// Derive viewing tag for coin discovery
    pub fn derive_viewing_tag(&self, coin_index: u32) -> [u8; 4] {
        crate::crypto_utils::generate_viewing_tag(&self.viewing_key.key, coin_index)
    }

    /// Check if a viewing tag belongs to this wallet
    pub fn check_viewing_tag(&self, tag: &[u8; 4], max_index: u32) -> Option<u32> {
        crate::crypto_utils::find_coin_index_by_viewing_tag(tag, &self.viewing_key.key, max_index)
    }
}

// ============================================================================
// Private Coin Integration
// ============================================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletPrivateCoin {
    /// Core protocol coin data
    pub coin: crate::protocol::PrivateCoin,
    /// Wallet-specific metadata
    pub account_index: u32,
    pub coin_index: u32,
}

impl WalletPrivateCoin {
    /// Create from HD wallet
    pub fn from_wallet(
        wallet: &CLVMHDWallet,
        account_index: u32,
        coin_index: u32,
        puzzle_hash: [u8; 32],
        amount: u64,
    ) -> Result<Self, crate::wallet::WalletError> {
        let spend_secret = wallet.derive_spend_secret(account_index, coin_index)?;

        Ok(Self {
            coin: crate::protocol::PrivateCoin::new(spend_secret.secret, puzzle_hash, amount),
            account_index,
            coin_index,
        })
    }

    /// Generate nullifier with domain separation
    pub fn nullifier(&self) -> [u8; 32] {
        self.coin.nullifier()
    }

    /// Create with recovery hint
    pub fn with_hint(&self) -> ([u8; 4], [u8; 32]) {
        let nullifier = self.nullifier();
        let hint = [nullifier[0], nullifier[1], nullifier[2], nullifier[3]];
        (hint, nullifier)
    }

    /// Validate coin integrity
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.coin.validate().map_err(|e| match e {
            crate::protocol::ProtocolError::InvalidSpendSecret(_) => ValidationError::WeakSecret,
            _ => ValidationError::InvalidPuzzle,
        })
    }

    /// Get the spend secret (convenience method)
    pub fn spend_secret(&self) -> [u8; 32] {
        self.coin.spend_secret
    }

    /// Get the puzzle hash (convenience method)
    pub fn puzzle_hash(&self) -> [u8; 32] {
        self.coin.puzzle_hash
    }

    /// Get the amount (convenience method)
    pub fn amount(&self) -> u64 {
        self.coin.amount
    }

    /// Convert to protocol PrivateCoin
    pub fn to_protocol_coin(&self) -> crate::protocol::PrivateCoin {
        self.coin.clone()
    }
}

// ============================================================================
// Wallet Recovery
// ============================================================================

pub struct WalletRecovery {
    wallet: CLVMHDWallet,
    gap_limit: u32,
}

impl WalletRecovery {
    pub fn new(wallet: CLVMHDWallet) -> Self {
        Self {
            wallet,
            gap_limit: 20, // BIP44 standard gap limit
        }
    }

    /// Recover coins using viewing tags
    pub fn recover_with_hints(
        &self,
        hints: &[[u8; 4]],
        max_accounts: u32,
        max_coins_per_account: u32,
    ) -> Vec<RecoveredCoin> {
        let mut recovered = Vec::new();

        for account_idx in 0..max_accounts {
            let account = match self.wallet.derive_account(account_idx) {
                Ok(acc) => acc,
                Err(_) => continue,
            };

            let mut gap_counter = 0;

            for coin_idx in 0..max_coins_per_account {
                // Derive viewing tag
                let tag = crate::crypto_utils::generate_viewing_tag(&account.viewing_key, coin_idx);

                if hints.contains(&tag) {
                    let spend_secret = self
                        .wallet
                        .derive_spend_secret(account_idx, coin_idx)
                        .expect("Valid derivation");

                    recovered.push(RecoveredCoin {
                        account_index: account_idx,
                        coin_index: coin_idx,
                        spend_secret: spend_secret.secret,
                        viewing_tag: tag,
                    });

                    gap_counter = 0; // Reset gap counter
                } else {
                    gap_counter += 1;
                    if gap_counter >= self.gap_limit {
                        break; // Move to next account
                    }
                }
            }
        }

        recovered
    }

    /// Scan blockchain for spent nullifiers
    pub fn scan_nullifiers(
        &self,
        nullifiers: &[[u8; 32]],
        puzzle_hashes: &[[u8; 32]],
        max_accounts: u32,
        max_coins_per_account: u32,
    ) -> Vec<RecoveredSpend> {
        let mut found = Vec::new();

        for account_idx in 0..max_accounts {
            for coin_idx in 0..max_coins_per_account {
                // Check against all puzzle hashes
                for &puzzle_hash in puzzle_hashes {
                    let nullifier = self
                        .wallet
                        .create_nullifier(account_idx, coin_idx, puzzle_hash)
                        .expect("Valid nullifier");

                    if nullifiers.contains(&nullifier.bytes) {
                        found.push(RecoveredSpend {
                            account_index: account_idx,
                            coin_index: coin_idx,
                            nullifier: nullifier.bytes,
                            puzzle_hash,
                        });
                    }
                }
            }
        }

        found
    }
}

#[derive(Debug)]
pub struct RecoveredCoin {
    pub account_index: u32,
    pub coin_index: u32,
    pub spend_secret: [u8; 32],
    pub viewing_tag: [u8; 4],
}

#[derive(Debug)]
pub struct RecoveredSpend {
    pub account_index: u32,
    pub coin_index: u32,
    pub nullifier: [u8; 32],
    pub puzzle_hash: [u8; 32],
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Weak or invalid spend secret")]
    WeakSecret,

    #[error("Invalid puzzle hash")]
    InvalidPuzzle,
}

// ============================================================================
// Display Implementations
// ============================================================================

impl fmt::Display for WalletNullifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "null:{}", hex::encode(&self.bytes[0..8]))
    }
}

impl fmt::Display for ViewingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "vk:{}:acc_{}",
            hex::encode(&self.key[0..4]),
            self.account_index
        )
    }
}
