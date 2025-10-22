// blockchain simulator for testing protocol

use crate::protocol::{PrivateCoin, PrivateSpendBundle, ProtocolError, Spender};
use clvm_zk_core::coin_commitment::CoinCommitment;
use rs_merkle::{algorithms::Sha256 as MerkleHasher, MerkleTree};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// simulated blockchain state for testing
#[derive(Clone)]
pub struct CLVMZkSimulator {
    nullifier_set: HashSet<[u8; 32]>,
    utxo_set: HashMap<[u8; 32], CoinInfo>,
    coin_tree: MerkleTree<MerkleHasher>,
    commitment_to_index: HashMap<[u8; 32], usize>,
    transactions: Vec<SimulatedTransaction>,
    block_height: u64,
}

impl Default for CLVMZkSimulator {
    fn default() -> Self {
        Self::new()
    }
}

impl CLVMZkSimulator {
    pub fn new() -> Self {
        Self {
            nullifier_set: HashSet::new(),
            utxo_set: HashMap::new(),
            coin_tree: MerkleTree::<MerkleHasher>::new(),
            commitment_to_index: HashMap::new(),
            transactions: Vec::new(),
            block_height: 0,
        }
    }

    pub fn add_coin(
        &mut self,
        coin: PrivateCoin,
        secrets: &clvm_zk_core::coin_commitment::CoinSecrets,
        metadata: CoinMetadata,
    ) -> [u8; 32] {
        let nullifier = secrets.nullifier();
        let info = CoinInfo {
            coin: coin.clone(),
            metadata,
            created_at_height: self.block_height,
        };

        let coin_commitment = CoinCommitment::compute(
            coin.amount,
            &coin.puzzle_hash,
            &coin.serial_commitment,
            crate::crypto_utils::hash_data_default,
        );

        let leaf_index = self.coin_tree.leaves_len();
        self.coin_tree.insert(coin_commitment.0);
        self.coin_tree.commit();
        self.commitment_to_index
            .insert(coin_commitment.0, leaf_index);

        self.utxo_set.insert(nullifier, info);
        nullifier
    }

    pub fn spend_coins(
        &mut self,
        spends: Vec<(
            PrivateCoin,
            String,
            clvm_zk_core::coin_commitment::CoinSecrets,
        )>,
    ) -> Result<SimulatedTransaction, SimulatorError> {
        self.spend_coins_with_params(
            spends
                .into_iter()
                .map(|(coin, program, secrets)| (coin, program, vec![], secrets))
                .collect(),
        )
    }

    pub fn spend_coins_with_params(
        &mut self,
        spends: Vec<(
            PrivateCoin,
            String,
            Vec<crate::ProgramParameter>,
            clvm_zk_core::coin_commitment::CoinSecrets,
        )>,
    ) -> Result<SimulatedTransaction, SimulatorError> {
        let mut new_nullifiers = Vec::new();
        for (_, _, _, secrets) in &spends {
            let nullifier = secrets.serial_number;
            if self.nullifier_set.contains(&nullifier) {
                return Err(SimulatorError::DoubleSpend(hex::encode(nullifier)));
            }
            new_nullifiers.push(nullifier);
        }

        let merkle_root = self.coin_tree.root().ok_or_else(|| {
            SimulatorError::TestFailed("merkle tree has no root".to_string())
        })?;
        
        let mut spend_bundles = Vec::new();
        for (coin, program, params, secrets) in spends {
            let merkle_path = self.get_merkle_path(&coin).ok_or_else(|| {
                SimulatorError::TestFailed("coin not found in merkle tree".to_string())
            })?;

            match Spender::create_spend_with_serial(&coin, &program, &params, &secrets, merkle_path, merkle_root) {
                Ok(bundle) => spend_bundles.push(bundle),
                Err(e) => return Err(SimulatorError::ProofGeneration(format!("{:?}", e))),
            }
        }

        let tx = SimulatedTransaction {
            id: self.generate_tx_id(),
            spend_bundles,
            nullifiers: new_nullifiers.clone(),
            block_height: self.block_height,
            timestamp: self.block_height * 10,
        };

        for nullifier in &new_nullifiers {
            self.nullifier_set.insert(*nullifier);
            self.utxo_set.remove(nullifier);
        }

        self.transactions.push(tx.clone());
        self.block_height += 1;

        Ok(tx)
    }

    pub fn has_nullifier(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifier_set.contains(nullifier)
    }

    pub fn get_coin_info(&self, nullifier: &[u8; 32]) -> Option<&CoinInfo> {
        self.utxo_set.get(nullifier)
    }

    pub fn get_merkle_path(&self, coin: &PrivateCoin) -> Option<Vec<[u8; 32]>> {
        let coin_commitment = CoinCommitment::compute(
            coin.amount,
            &coin.puzzle_hash,
            &coin.serial_commitment,
            crate::crypto_utils::hash_data_default,
        );

        let leaf_index = *self.commitment_to_index.get(&coin_commitment.0)?;
        let proof = self.coin_tree.proof(&[leaf_index]);
        let proof_hashes = proof.proof_hashes();

        Some(
            proof_hashes
                .iter()
                .map(|hash| {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(hash);
                    arr
                })
                .collect(),
        )
    }

    pub fn utxo_iter(&self) -> impl Iterator<Item = (&[u8; 32], &CoinInfo)> {
        self.utxo_set.iter()
    }

    fn generate_tx_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"clvm_zk_tx_id");
        hasher.update(self.block_height.to_le_bytes());
        hasher.update(self.transactions.len().to_le_bytes());
        hasher.finalize().into()
    }

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

    pub fn reset(&mut self) {
        self.nullifier_set.clear();
        self.utxo_set.clear();
        self.coin_tree = MerkleTree::<MerkleHasher>::new();
        self.commitment_to_index.clear();
        self.transactions.clear();
        self.block_height = 0;
    }
}

/// coin info in simulator
#[derive(Debug, Clone)]
pub struct CoinInfo {
    pub coin: PrivateCoin,
    pub metadata: CoinMetadata,
    pub created_at_height: u64,
}

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

#[derive(Debug, Clone)]
pub struct SimulatedTransaction {
    pub id: [u8; 32],
    pub spend_bundles: Vec<PrivateSpendBundle>,
    pub nullifiers: Vec<[u8; 32]>,
    pub block_height: u64,
    pub timestamp: u64,
}

#[derive(Debug)]
pub struct SimulatorStats {
    pub total_coins_created: usize,
    pub total_nullifiers: usize,
    pub total_transactions: usize,
    pub current_utxo_count: usize,
    pub current_block_height: u64,
}

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
