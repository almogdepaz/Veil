// ============================================================================
// CLVM-ZK Protocol Simulator
// Simulates blockchain without needing actual infrastructure
// ============================================================================

use crate::protocol::{
    create_signature_spend_params, PrivateCoin, PrivateSpendBundle, ProtocolError, Spender,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;

// ============================================================================
// Simulator Core
// ============================================================================

/// Simulated blockchain state for testing protocol scenarios
#[derive(Debug, Clone)]
pub struct CLVMZkSimulator {
    /// Global nullifier set (prevents double-spends)
    nullifier_set: HashSet<[u8; 32]>,
    /// UTXO set: nullifier -> coin info
    utxo_set: HashMap<[u8; 32], CoinInfo>,
    /// Transaction history
    transactions: Vec<SimulatedTransaction>,
    /// Block height for testing
    block_height: u64,
}

impl CLVMZkSimulator {
    /// Create new simulator
    pub fn new() -> Self {
        Self {
            nullifier_set: HashSet::new(),
            utxo_set: HashMap::new(),
            transactions: Vec::new(),
            block_height: 0,
        }
    }

    /// Add a new coin to the UTXO set (simulates receiving)
    pub fn add_coin(&mut self, coin: PrivateCoin, metadata: CoinMetadata) -> [u8; 32] {
        let nullifier = coin.nullifier();
        let info = CoinInfo {
            coin: coin.clone(),
            metadata,
            created_at_height: self.block_height,
        };

        self.utxo_set.insert(nullifier, info);
        nullifier
    }

    /// Attempt to spend coins with explicit programs (simulates transaction submission)
    pub fn spend_coins(
        &mut self,
        coin_programs: Vec<(PrivateCoin, String)>,
    ) -> Result<SimulatedTransaction, SimulatorError> {
        // 1. Validate no double-spends
        let mut new_nullifiers = Vec::new();
        let mut coins = Vec::new();
        for (coin, _program) in &coin_programs {
            let nullifier = coin.nullifier();
            if self.nullifier_set.contains(&nullifier) {
                return Err(SimulatorError::DoubleSpend(hex::encode(nullifier)));
            }
            new_nullifiers.push(nullifier);
            coins.push(coin.clone());
        }

        // 2. Generate spend bundles using test protocol with provided programs
        let mut spend_bundles = Vec::new();
        for (coin, program) in coin_programs {
            // Let the Spender handle program validation - it has the proper hashing logic
            match Spender::create_spend(&coin, &program, &[]) {
                Ok(bundle) => spend_bundles.push(bundle),
                Err(e) => return Err(SimulatorError::ProofGeneration(format!("{:?}", e))),
            }
        }

        // 3. Create transaction
        let tx = SimulatedTransaction {
            id: self.generate_tx_id(),
            spend_bundles,
            nullifiers: new_nullifiers.clone(),
            block_height: self.block_height,
            timestamp: self.block_height * 10, // Mock timestamp
        };

        // 4. Update state
        for nullifier in new_nullifiers {
            self.nullifier_set.insert(nullifier);
            self.utxo_set.remove(&nullifier);
        }

        self.transactions.push(tx.clone());
        self.block_height += 1;

        Ok(tx)
    }

    /// Spend coins with signature verification (enhanced security)
    ///
    /// This method requires valid ECDSA signatures for spending coins.
    /// Each spend must provide a signature that verifies against the coin's puzzle program.
    pub fn spend_coins_with_signatures(
        &mut self,
        spends: Vec<(PrivateCoin, String, Vec<u8>, Vec<u8>)>, // (coin, program, public_key, signature)
    ) -> Result<SimulatedTransaction, SimulatorError> {
        // 1. Validate no double-spends
        let mut new_nullifiers = Vec::new();
        for (coin, _program, _public_key, _signature) in &spends {
            let nullifier = coin.nullifier();
            if self.nullifier_set.contains(&nullifier) {
                return Err(SimulatorError::DoubleSpend(hex::encode(nullifier)));
            }
            new_nullifiers.push(nullifier);
        }

        // 2. Generate spend bundles with signature verification
        let mut spend_bundles = Vec::new();
        for (coin, program, public_key_bytes, signature_bytes) in spends {
            // Create spend message (standardized message for signature verification)
            let spend_message = format!("authorize_spend_{}", hex::encode(coin.nullifier()));

            // Create program parameters including signature verification data
            let params = create_signature_spend_params(
                &public_key_bytes,
                spend_message.as_bytes(),
                &signature_bytes,
            );

            // Create spend bundle with signature verification
            match Spender::create_spend(&coin, &program, &params) {
                Ok(bundle) => spend_bundles.push(bundle),
                Err(e) => return Err(SimulatorError::ProofGeneration(format!("{:?}", e))),
            }
        }

        // 3. Create transaction
        let tx = SimulatedTransaction {
            id: self.generate_tx_id(),
            spend_bundles,
            nullifiers: new_nullifiers.clone(),
            block_height: self.block_height,
            timestamp: self.block_height * 10,
        };

        // 4. Update state
        for nullifier in new_nullifiers {
            self.nullifier_set.insert(nullifier);
            self.utxo_set.remove(&nullifier);
        }

        self.transactions.push(tx.clone());
        self.block_height += 1;

        Ok(tx)
    }

    /// Check if nullifier exists (double-spend check)
    pub fn has_nullifier(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifier_set.contains(nullifier)
    }

    /// Get coin info by nullifier
    pub fn get_coin_info(&self, nullifier: &[u8; 32]) -> Option<&CoinInfo> {
        self.utxo_set.get(nullifier)
    }

    /// Get iterator over UTXO set for testing
    pub fn utxo_iter(&self) -> impl Iterator<Item = (&[u8; 32], &CoinInfo)> {
        self.utxo_set.iter()
    }

    /// Generate transaction ID
    fn generate_tx_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"clvm_zk_tx_id");
        hasher.update(&self.block_height.to_le_bytes());
        hasher.update(&self.transactions.len().to_le_bytes());
        hasher.finalize().into()
    }

    /// Get stats for analysis
    pub fn stats(&self) -> SimulatorStats {
        SimulatorStats {
            total_coins_created: self
                .transactions
                .iter()
                .map(|tx| tx.spend_bundles.len())
                .sum(),
            total_nullifiers: self.nullifier_set.len(),
            total_transactions: self.transactions.len(),
            current_utxo_count: self.utxo_set.len(),
            current_block_height: self.block_height,
        }
    }

    /// Reset simulator state
    pub fn reset(&mut self) {
        self.nullifier_set.clear();
        self.utxo_set.clear();
        self.transactions.clear();
        self.block_height = 0;
    }
}

// ============================================================================
// Data Structures
// ============================================================================

/// Information about a coin in the simulator
#[derive(Debug, Clone)]
pub struct CoinInfo {
    pub coin: PrivateCoin,
    pub metadata: CoinMetadata,
    pub created_at_height: u64,
}

/// Metadata for testing scenarios
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinMetadata {
    pub owner: String,
    pub coin_type: CoinType,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoinType {
    Regular,
    Multisig,
    Timelocked,
    Atomic,
}

/// Simulated transaction
#[derive(Debug, Clone)]
pub struct SimulatedTransaction {
    pub id: [u8; 32],
    pub spend_bundles: Vec<PrivateSpendBundle>,
    pub nullifiers: Vec<[u8; 32]>,
    pub block_height: u64,
    pub timestamp: u64,
}

/// Simulator statistics
#[derive(Debug)]
pub struct SimulatorStats {
    pub total_coins_created: usize,
    pub total_nullifiers: usize,
    pub total_transactions: usize,
    pub current_utxo_count: usize,
    pub current_block_height: u64,
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum SimulatorError {
    #[error("Double-spend detected: nullifier {0} already used")]
    DoubleSpend(String),
    #[error("Program hash mismatch: {0}")]
    ProgramHashMismatch(String),
    #[error("Proof generation failed: {0}")]
    ProofGeneration(String),
    #[error("Test failed: {0}")]
    TestFailed(String),
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),
}

// ============================================================================
// Display Implementations
// ============================================================================

impl fmt::Display for SimulatedTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Tx {} (block {}, {} nullifiers)",
            hex::encode(&self.id[0..8]),
            self.block_height,
            self.nullifiers.len()
        )
    }
}

impl fmt::Display for SimulatorStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Simulator Stats:\n  Total Transactions: {}\n  Total Nullifiers: {}\n  Current UTXOs: {}\n  Block Height: {}",
            self.total_transactions,
            self.total_nullifiers,
            self.current_utxo_count,
            self.current_block_height
        )
    }
}
