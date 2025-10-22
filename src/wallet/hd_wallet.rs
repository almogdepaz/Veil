// hd wallet with bip32 key derivation

use bip32::{ChildNumber, XPrv, XPub};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub struct CLVMHDWallet {
    master: XPrv,
    network: crate::wallet::Network,
}

impl CLVMHDWallet {
    pub fn from_seed(
        seed: &[u8],
        network: crate::wallet::Network,
    ) -> Result<Self, crate::wallet::WalletError> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(crate::wallet::WalletError::InvalidSeed);
        }

        let seed_32 = if seed.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(seed);
            arr
        } else {
            Sha256::digest(seed).into()
        };

        let master = XPrv::new(seed_32).map_err(|_| crate::wallet::WalletError::InvalidSeed)?;

        Ok(Self { master, network })
    }

    fn derive_path(&self, path: &[ChildNumber]) -> Result<XPrv, crate::wallet::WalletError> {
        let mut current_key = self.master.clone();

        for &child_number in path {
            current_key = current_key
                .derive_child(child_number)
                .map_err(crate::wallet::WalletError::Bip32Error)?;
        }

        Ok(current_key)
    }

    pub fn derive_account(
        &self,
        account_index: u32,
    ) -> Result<AccountKeys, crate::wallet::WalletError> {
        let path = [
            ChildNumber::new(44, true)?,
            ChildNumber::new(self.network.coin_type(), true)?,
            ChildNumber::new(account_index, true)?,
            ChildNumber::new(0, true)?,
        ];

        let account_xprv = self.derive_path(&path)?;
        let account_bytes = account_xprv.to_bytes();

        let spending_key = {
            let mut hasher = Sha256::new();
            hasher.update(b"clvm_zk_spend_auth_v1");
            hasher.update(account_bytes);
            hasher.update(self.network.to_bytes());
            hasher.finalize().into()
        };

        let viewing_key = {
            let mut hasher = Sha256::new();
            hasher.update(b"clvm_zk_view_key_v1");
            hasher.update(spending_key);
            hasher.finalize().into()
        };

        let nullifier_key = {
            let mut hasher = Sha256::new();
            hasher.update(b"clvm_zk_nullifier_key_v1");
            hasher.update(spending_key);
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

    pub fn account_xpub(&self, account_index: u32) -> Result<XPub, crate::wallet::WalletError> {
        let account = self.derive_account(account_index)?;
        Ok(XPub::from(&account._account_xprv))
    }
}

pub struct AccountKeys {
    pub spending_key: [u8; 32],
    pub viewing_key: [u8; 32],
    pub nullifier_key: [u8; 32],
    pub account_index: u32,
    pub network: crate::wallet::Network,
    _account_xprv: XPrv, // Keep for potential child derivation
}

impl AccountKeys {
    pub fn export_viewing_key(&self) -> ViewingKey {
        ViewingKey {
            key: self.viewing_key,
            account_index: self.account_index,
            network: self.network,
        }
    }
}

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

    pub fn derive_viewing_tag(&self, coin_index: u32) -> [u8; 4] {
        crate::crypto_utils::generate_viewing_tag(&self.viewing_key.key, coin_index)
    }

    pub fn check_viewing_tag(&self, tag: &[u8; 4], max_index: u32) -> Option<u32> {
        crate::crypto_utils::find_coin_index_by_viewing_tag(tag, &self.viewing_key.key, max_index)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletPrivateCoin {
    pub coin: crate::protocol::PrivateCoin,
    pub secrets: clvm_zk_core::coin_commitment::CoinSecrets,
    pub account_index: u32,
    pub coin_index: u32,
}

impl WalletPrivateCoin {
    pub fn new(
        puzzle_hash: [u8; 32],
        amount: u64,
        account_index: u32,
        coin_index: u32,
    ) -> Self {
        let (coin, secrets) = crate::protocol::PrivateCoin::new_with_secrets(puzzle_hash, amount);

        Self {
            coin,
            secrets,
            account_index,
            coin_index,
        }
    }

    pub fn nullifier(&self) -> [u8; 32] {
        self.secrets.nullifier()
    }

    pub fn with_hint(&self) -> ([u8; 4], [u8; 32]) {
        let nullifier = self.nullifier();
        let hint = [nullifier[0], nullifier[1], nullifier[2], nullifier[3]];
        (hint, nullifier)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        self.coin.validate().map_err(|e| match e {
            crate::protocol::ProtocolError::InvalidSpendSecret(_) => ValidationError::WeakSecret,
            _ => ValidationError::InvalidPuzzle,
        })
    }

    // spend_secret removed - not part of serial commitment protocol
    // nullifier comes from secrets.serial_number

    pub fn puzzle_hash(&self) -> [u8; 32] {
        self.coin.puzzle_hash
    }

    pub fn amount(&self) -> u64 {
        self.coin.amount
    }

    pub fn to_protocol_coin(&self) -> crate::protocol::PrivateCoin {
        self.coin.clone()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Weak or invalid spend secret")]
    WeakSecret,

    #[error("Invalid puzzle hash")]
    InvalidPuzzle,
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
