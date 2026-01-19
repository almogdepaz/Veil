// blockchain simulator for testing protocol

use crate::protocol::{PrivateCoin, PrivateSpendBundle, ProtocolError, Spender};
use clvm_zk_core::coin_commitment::CoinCommitment;
use rs_merkle::{algorithms::Sha256 as MerkleHasher, MerkleTree};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// simulated blockchain state for testing
#[derive(Clone, Serialize, Deserialize)]
pub struct CLVMZkSimulator {
    /// Set of revealed nullifiers (hash of serial_number || program_hash || amount)
    /// Used to prevent double-spending
    #[serde(with = "hex_hashset")]
    nullifier_set: HashSet<[u8; 32]>,
    /// Map of unspent coins, keyed by serial_number (not the computed nullifier)
    /// In a real system, each wallet tracks only its own UTXOs
    #[serde(with = "hex_hashmap")]
    utxo_set: HashMap<[u8; 32], CoinInfo>,
    #[serde(skip)]
    #[serde(default = "MerkleTree::new")]
    coin_tree: MerkleTree<MerkleHasher>,
    #[serde(with = "hex_hashmap")]
    commitment_to_index: HashMap<[u8; 32], usize>,
    merkle_leaves: Vec<[u8; 32]>, // persisted leaves to rebuild tree
    transactions: Vec<SimulatedTransaction>,
    block_height: u64,
}

// custom serialization for HashSet<[u8; 32]>
mod hex_hashset {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(set: &HashSet<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let vec: Vec<String> = set.iter().map(hex::encode).collect();
        vec.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashSet<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<String> = Vec::deserialize(deserializer)?;
        vec.iter()
            .map(|s| {
                hex::decode(s)
                    .map_err(serde::de::Error::custom)?
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("invalid hex length"))
            })
            .collect()
    }
}

// custom serialization for HashMap<[u8; 32], T>
mod hex_hashmap {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S, T>(map: &HashMap<[u8; 32], T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: Serialize,
    {
        let vec: Vec<(String, &T)> = map.iter().map(|(k, v)| (hex::encode(k), v)).collect();
        vec.serialize(serializer)
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<HashMap<[u8; 32], T>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        let vec: Vec<(String, T)> = Vec::deserialize(deserializer)?;
        vec.into_iter()
            .map(|(k, v)| {
                let key: [u8; 32] = hex::decode(&k)
                    .map_err(serde::de::Error::custom)?
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("invalid hex length"))?;
                Ok((key, v))
            })
            .collect()
    }
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
            merkle_leaves: Vec::new(),
            transactions: Vec::new(),
            block_height: 0,
        }
    }

    /// rebuild merkle tree from persisted leaves (call after deserialization)
    pub fn rebuild_tree(&mut self) {
        self.coin_tree = MerkleTree::<MerkleHasher>::new();
        for leaf in &self.merkle_leaves {
            self.coin_tree.insert(*leaf);
        }
        self.coin_tree.commit();
    }

    pub fn add_coin(
        &mut self,
        coin: PrivateCoin,
        secrets: &clvm_zk_core::coin_commitment::CoinSecrets,
        metadata: CoinMetadata,
    ) -> [u8; 32] {
        let serial_number = secrets.serial_number();
        let info = CoinInfo {
            coin: coin.clone(),
            metadata,
            created_at_height: self.block_height,
            ephemeral_pubkey: None,
        };

        let coin_commitment = CoinCommitment::compute(
            &coin.tail_hash,
            coin.amount,
            &coin.puzzle_hash,
            &coin.serial_commitment,
            crate::crypto_utils::hash_data_default,
        );

        let leaf_index = self.coin_tree.leaves_len();
        self.coin_tree.insert(coin_commitment.0);
        self.coin_tree.commit();
        self.merkle_leaves.push(coin_commitment.0); // track leaf for persistence
        self.commitment_to_index
            .insert(coin_commitment.0, leaf_index);

        self.utxo_set.insert(serial_number, info);
        serial_number
    }

    /// Add coin with ephemeral pubkey for stealth address scanning
    pub fn add_coin_with_ephemeral(
        &mut self,
        coin: PrivateCoin,
        secrets: &clvm_zk_core::coin_commitment::CoinSecrets,
        ephemeral_pubkey: [u8; 33],
        metadata: CoinMetadata,
    ) -> [u8; 32] {
        let serial_number = secrets.serial_number();
        let info = CoinInfo {
            coin: coin.clone(),
            metadata,
            created_at_height: self.block_height,
            ephemeral_pubkey: Some(ephemeral_pubkey.to_vec()),
        };

        let coin_commitment = CoinCommitment::compute(
            &coin.tail_hash,
            coin.amount,
            &coin.puzzle_hash,
            &coin.serial_commitment,
            crate::crypto_utils::hash_data_default,
        );

        let leaf_index = self.coin_tree.leaves_len();
        self.coin_tree.insert(coin_commitment.0);
        self.coin_tree.commit();
        self.merkle_leaves.push(coin_commitment.0);
        self.commitment_to_index
            .insert(coin_commitment.0, leaf_index);

        self.utxo_set.insert(serial_number, info);
        serial_number
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
        self.spend_coins_with_params_and_outputs(spends, vec![])
    }

    pub fn spend_coins_with_params_and_outputs(
        &mut self,
        spends: Vec<(
            PrivateCoin,
            String,
            Vec<crate::ProgramParameter>,
            clvm_zk_core::coin_commitment::CoinSecrets,
        )>,
        output_coins: Vec<(
            PrivateCoin,
            clvm_zk_core::coin_commitment::CoinSecrets,
            CoinMetadata,
        )>,
    ) -> Result<SimulatedTransaction, SimulatorError> {
        let merkle_root = self
            .coin_tree
            .root()
            .ok_or_else(|| SimulatorError::TestFailed("merkle tree has no root".to_string()))?;

        let mut spend_bundles = Vec::new();
        let mut spent_serial_numbers = Vec::new();

        // check if all coins have same tail_hash for ring spend optimization
        let can_use_ring = if spends.len() > 1 {
            let first_tail = spends[0].0.tail_hash;
            spends
                .iter()
                .all(|(coin, _, _, _)| coin.tail_hash == first_tail)
        } else {
            false
        };

        if can_use_ring {
            // multi-coin ring spend (single proof for all coins)
            let coin_data: Vec<_> = spends
                .iter()
                .map(|(coin, program, params, secrets)| {
                    let (merkle_path, leaf_index) =
                        self.get_merkle_path_and_index(coin).ok_or_else(|| {
                            SimulatorError::TestFailed("coin not found in merkle tree".to_string())
                        })?;
                    Ok((
                        coin,
                        program.as_str(),
                        params.as_slice(),
                        secrets,
                        merkle_path,
                        leaf_index,
                    ))
                })
                .collect::<Result<Vec<_>, SimulatorError>>()?;

            match Spender::create_ring_spend(coin_data, merkle_root) {
                Ok(bundle) => {
                    spend_bundles.push(bundle);
                    for (_, _, _, secrets) in &spends {
                        spent_serial_numbers.push(secrets.serial_number);
                    }
                }
                Err(e) => return Err(SimulatorError::ProofGeneration(format!("{:?}", e))),
            }
        } else {
            // separate proofs for each coin (different tail_hash or single coin)
            for (coin, program, params, secrets) in spends {
                let (merkle_path, leaf_index) =
                    self.get_merkle_path_and_index(&coin).ok_or_else(|| {
                        SimulatorError::TestFailed("coin not found in merkle tree".to_string())
                    })?;

                match Spender::create_spend_with_serial(
                    &coin,
                    &program,
                    &params,
                    &secrets,
                    merkle_path,
                    merkle_root,
                    leaf_index,
                ) {
                    Ok(bundle) => {
                        spend_bundles.push(bundle);
                        spent_serial_numbers.push(secrets.serial_number);
                    }
                    Err(e) => return Err(SimulatorError::ProofGeneration(format!("{:?}", e))),
                }
            }
        }

        // Extract nullifiers from proof outputs (not pre-computed)
        // each bundle may have multiple nullifiers (ring spends)
        let mut new_nullifiers = Vec::new();
        for bundle in &spend_bundles {
            for nullifier in &bundle.nullifiers {
                if self.nullifier_set.contains(nullifier) {
                    return Err(SimulatorError::DoubleSpend(hex::encode(nullifier)));
                }
                new_nullifiers.push(*nullifier);
            }
        }

        // Extract coin_commitments from CREATE_COIN conditions in proof outputs
        let mut new_coin_commitments = Vec::new();
        for bundle in &spend_bundles {
            // Try to parse CLVM output as conditions
            // If it fails (e.g., simple return value), skip extraction
            if let Ok(conditions) =
                clvm_zk_core::deserialize_clvm_output_to_conditions(&bundle.public_conditions)
            {
                // Extract CREATE_COIN commitments (opcode 51)
                for condition in conditions {
                    if condition.opcode == 51 {
                        if condition.args.len() != 1 {
                            return Err(SimulatorError::TestFailed(
                                "CREATE_COIN must have 1 arg (coin_commitment)".to_string(),
                            ));
                        }
                        if condition.args[0].len() != 32 {
                            return Err(SimulatorError::TestFailed(
                                "coin_commitment must be 32 bytes".to_string(),
                            ));
                        }
                        let mut commitment = [0u8; 32];
                        commitment.copy_from_slice(&condition.args[0]);
                        new_coin_commitments.push(commitment);
                    }
                }
            }
            // If parsing fails, program returned non-condition value (e.g., simple number)
            // This is fine - just means no coins were created
        }

        let tx = SimulatedTransaction {
            id: self.generate_tx_id(),
            spend_bundles,
            nullifiers: new_nullifiers.clone(),
            block_height: self.block_height,
            timestamp: self.block_height * 10,
        };

        // Add nullifiers to nullifier set (prevents double-spend)
        for nullifier in &new_nullifiers {
            self.nullifier_set.insert(*nullifier);
        }

        // Add new coin_commitments to merkle tree
        for commitment in &new_coin_commitments {
            let leaf_index = self.coin_tree.leaves_len();
            self.coin_tree.insert(*commitment);
            self.commitment_to_index.insert(*commitment, leaf_index);
            self.merkle_leaves.push(*commitment);
        }

        // Commit tree after adding all new coins
        if !new_coin_commitments.is_empty() {
            self.coin_tree.commit();
        }

        // If output coins provided (for simulator testing), validate and track them
        if !output_coins.is_empty() {
            if output_coins.len() != new_coin_commitments.len() {
                return Err(SimulatorError::TestFailed(format!(
                    "output_coins count ({}) doesn't match CREATE_COIN count ({})",
                    output_coins.len(),
                    new_coin_commitments.len()
                )));
            }

            // Validate commitments match and add to utxo_set
            for (i, (coin, secrets, metadata)) in output_coins.into_iter().enumerate() {
                let expected_commitment = CoinCommitment::compute(
                    &coin.tail_hash,
                    coin.amount,
                    &coin.puzzle_hash,
                    &coin.serial_commitment,
                    crate::crypto_utils::hash_data_default,
                );

                if expected_commitment.0 != new_coin_commitments[i] {
                    return Err(SimulatorError::TestFailed(format!(
                        "output coin {} commitment mismatch: expected {}, got {}",
                        i,
                        hex::encode(new_coin_commitments[i]),
                        hex::encode(expected_commitment.0)
                    )));
                }

                // Add to utxo_set
                self.utxo_set.insert(
                    secrets.serial_number,
                    CoinInfo {
                        coin,
                        metadata,
                        created_at_height: self.block_height,
                        ephemeral_pubkey: None, // TODO: support stealth outputs in spends
                    },
                );
            }
        }

        // Remove spent coins from utxo_set (keyed by serial_number)
        for serial_number in &spent_serial_numbers {
            self.utxo_set.remove(serial_number);
        }

        self.transactions.push(tx.clone());
        self.block_height += 1;

        Ok(tx)
    }

    pub fn has_nullifier(&self, nullifier: &[u8; 32]) -> bool {
        self.nullifier_set.contains(nullifier)
    }

    pub fn get_coin_info(&self, serial_number: &[u8; 32]) -> Option<&CoinInfo> {
        self.utxo_set.get(serial_number)
    }

    /// Iterate over all UTXOs (serial_number, CoinInfo)
    pub fn utxo_iter(&self) -> impl Iterator<Item = (&[u8; 32], &CoinInfo)> {
        self.utxo_set.iter()
    }

    /// Get all coins with ephemeral pubkeys for stealth scanning
    /// Returns (puzzle_hash, ephemeral_pubkey, coin_info) for each stealth coin
    pub fn get_stealth_scannable_coins(&self) -> Vec<(&[u8; 32], [u8; 33], &CoinInfo)> {
        self.utxo_set
            .iter()
            .filter_map(|(_serial, info)| {
                info.ephemeral_pubkey.as_ref().and_then(|eph| {
                    if eph.len() == 33 {
                        let mut arr = [0u8; 33];
                        arr.copy_from_slice(eph);
                        Some((&info.coin.puzzle_hash, arr, info))
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    pub fn get_merkle_path_and_index(&self, coin: &PrivateCoin) -> Option<(Vec<[u8; 32]>, usize)> {
        let coin_commitment = CoinCommitment::compute(
            &coin.tail_hash,
            coin.amount,
            &coin.puzzle_hash,
            &coin.serial_commitment,
            crate::crypto_utils::hash_data_default,
        );

        let leaf_index = *self.commitment_to_index.get(&coin_commitment.0)?;
        let proof = self.coin_tree.proof(&[leaf_index]);
        let proof_hashes = proof.proof_hashes();

        let path = proof_hashes
            .iter()
            .map(|hash| {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(hash);
                arr
            })
            .collect();

        Some((path, leaf_index))
    }

    /// Debug helper: verify a merkle path manually and print diagnostic info
    pub fn debug_verify_merkle_path(&self, coin: &PrivateCoin, label: &str) -> Result<(), String> {
        eprintln!("\n=== MERKLE DEBUG: {} ===", label);

        // Compute coin commitment
        let coin_commitment = CoinCommitment::compute(
            &coin.tail_hash,
            coin.amount,
            &coin.puzzle_hash,
            &coin.serial_commitment,
            crate::crypto_utils::hash_data_default,
        );
        eprintln!("  coin_commitment: {}", hex::encode(coin_commitment.0));
        eprintln!("  tail_hash: {}", hex::encode(coin.tail_hash));
        eprintln!("  amount: {}", coin.amount);
        eprintln!("  puzzle_hash: {}", hex::encode(coin.puzzle_hash));
        eprintln!(
            "  serial_commitment: {}",
            hex::encode(coin.serial_commitment.as_bytes())
        );

        // Check if commitment is in the index
        let leaf_index = match self.commitment_to_index.get(&coin_commitment.0) {
            Some(&idx) => {
                eprintln!("  leaf_index: {} (found in commitment_to_index)", idx);
                idx
            }
            None => {
                eprintln!("  ERROR: coin_commitment NOT FOUND in commitment_to_index!");
                eprintln!("  Known commitments:");
                for (comm, idx) in &self.commitment_to_index {
                    eprintln!("    idx {}: {}", idx, hex::encode(comm));
                }
                return Err("coin_commitment not found in tree".to_string());
            }
        };

        // Get the merkle proof
        let proof = self.coin_tree.proof(&[leaf_index]);
        let proof_hashes = proof.proof_hashes();
        eprintln!("  merkle_path length: {}", proof_hashes.len());
        for (i, hash) in proof_hashes.iter().enumerate() {
            eprintln!("    path[{}]: {}", i, hex::encode(hash));
        }

        // Get the expected root
        let expected_root = self.coin_tree.root();
        eprintln!("  expected_root: {:?}", expected_root.map(hex::encode));

        // Manually verify the path (same logic as guest)
        let mut current_hash = coin_commitment.0;
        let mut current_index = leaf_index;
        eprintln!("  === PATH TRAVERSAL ===");
        for (i, sibling) in proof_hashes.iter().enumerate() {
            let mut combined = [0u8; 64];
            let position = if current_index % 2 == 0 {
                "LEFT"
            } else {
                "RIGHT"
            };
            if current_index % 2 == 0 {
                combined[..32].copy_from_slice(&current_hash);
                combined[32..].copy_from_slice(sibling);
            } else {
                combined[..32].copy_from_slice(sibling);
                combined[32..].copy_from_slice(&current_hash);
            }
            let new_hash = crate::crypto_utils::hash_data_default(&combined);
            eprintln!(
                "    step {}: idx={} ({}) hash={} -> {}",
                i,
                current_index,
                position,
                hex::encode(&current_hash[..8]),
                hex::encode(&new_hash[..8])
            );
            current_hash = new_hash;
            current_index /= 2;
        }

        let computed_root = current_hash;
        eprintln!("  computed_root: {}", hex::encode(computed_root));

        if Some(computed_root) == expected_root {
            eprintln!("  RESULT: ✓ MERKLE PROOF VALID");
            Ok(())
        } else {
            eprintln!("  RESULT: ✗ MERKLE PROOF INVALID!");
            Err(format!(
                "root mismatch: computed={}, expected={:?}",
                hex::encode(computed_root),
                expected_root.map(hex::encode)
            ))
        }
    }

    /// Debug helper: dump entire merkle tree state
    pub fn debug_dump_tree_state(&self) {
        eprintln!("\n=== MERKLE TREE STATE ===");
        eprintln!("  leaves_len: {}", self.coin_tree.leaves_len());
        eprintln!("  root: {:?}", self.coin_tree.root().map(hex::encode));
        eprintln!("  merkle_leaves ({}):", self.merkle_leaves.len());
        for (i, leaf) in self.merkle_leaves.iter().enumerate() {
            eprintln!("    [{}]: {}", i, hex::encode(leaf));
        }
        eprintln!(
            "  commitment_to_index ({}):",
            self.commitment_to_index.len()
        );
        for (comm, idx) in &self.commitment_to_index {
            eprintln!("    {} -> idx {}", hex::encode(comm), idx);
        }
    }

    pub fn get_merkle_root(&self) -> Option<[u8; 32]> {
        self.coin_tree.root()
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
        self.merkle_leaves.clear();
        self.transactions.clear();
        self.block_height = 0;
    }
}

/// coin info in simulator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinInfo {
    pub coin: PrivateCoin,
    pub metadata: CoinMetadata,
    pub created_at_height: u64,
    /// ephemeral pubkey for stealth address scanning (33 bytes compressed secp256k1)
    #[serde(default)]
    pub ephemeral_pubkey: Option<Vec<u8>>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
