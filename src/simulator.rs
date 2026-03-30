// blockchain simulator for testing protocol

use crate::protocol::{PrivateCoin, PrivateSpendBundle, ProtocolError, Spender};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use clvm_zk_core::coin_commitment::CoinCommitment;
use clvm_zk_core::merkle::SparseMerkleTree;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// tree depth for simulator merkle tree (supports 2^20 = ~1M coins)
const SIMULATOR_TREE_DEPTH: usize = 20;

fn hasher() -> fn(&[u8]) -> [u8; 32] {
    crate::crypto_utils::hash_data_default
}

fn default_coin_tree() -> SparseMerkleTree {
    SparseMerkleTree::new(SIMULATOR_TREE_DEPTH, hasher())
}

/// Encrypt a 32-byte stealth nonce for the given x25519 recipient public key.
///
/// Output: ephemeral_pubkey(32) || chacha_nonce(12) || ciphertext+tag(48) = 92 bytes.
/// The shared secret is derived via ECDH then hashed with SHA-256 to produce the
/// ChaCha20Poly1305 key.
fn encrypt_stealth_nonce(nonce: &[u8; 32], recipient_pubkey: &[u8; 32]) -> Vec<u8> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    let recipient_public = PublicKey::from(*recipient_pubkey);
    let shared = ephemeral_secret.diffie_hellman(&recipient_public);

    let key_bytes = Sha256::digest(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key_bytes.as_slice()));

    let mut chacha_nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut chacha_nonce_bytes);

    // encrypt: 32 bytes plaintext → 48 bytes ciphertext (32 + 16 AEAD tag)
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&chacha_nonce_bytes), nonce.as_slice())
        .expect("ChaCha20Poly1305 encryption cannot fail for valid inputs");

    let mut blob = Vec::with_capacity(92);
    blob.extend_from_slice(ephemeral_public.as_bytes()); // 32 bytes
    blob.extend_from_slice(&chacha_nonce_bytes); // 12 bytes
    blob.extend_from_slice(&ciphertext); // 48 bytes
    blob
}

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
    #[serde(default = "default_coin_tree")]
    coin_tree: SparseMerkleTree,
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
            coin_tree: default_coin_tree(),
            commitment_to_index: HashMap::new(),
            merkle_leaves: Vec::new(),
            transactions: Vec::new(),
            block_height: 0,
        }
    }

    /// rebuild merkle tree from persisted leaves (call after deserialization)
    pub fn rebuild_tree(&mut self) {
        let h = hasher();
        self.coin_tree = SparseMerkleTree::new(SIMULATOR_TREE_DEPTH, h);
        for leaf in &self.merkle_leaves {
            self.coin_tree.insert(*leaf, h);
        }
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
            stealth_nonce: None,
            puzzle_source: None,
            tail_source: None,
        };

        let coin_commitment = CoinCommitment::compute(
            &coin.tail_hash,
            coin.amount,
            &coin.puzzle_hash,
            &coin.serial_commitment,
            crate::crypto_utils::hash_data_default,
        );

        let h = hasher();
        let leaf_index = self.coin_tree.len();
        self.coin_tree.insert(coin_commitment.0, h);
        self.merkle_leaves.push(coin_commitment.0); // track leaf for persistence
        self.commitment_to_index
            .insert(coin_commitment.0, leaf_index);

        self.utxo_set.insert(serial_number, info);
        serial_number
    }

    /// Add coin with stealth nonce for hash-based stealth address scanning.
    /// The nonce is encrypted for `recipient_pubkey` using x25519 ECDH + ChaCha20Poly1305.
    /// Stored format: ephemeral_pubkey(32) || chacha_nonce(12) || ciphertext+tag(48) = 92 bytes.
    pub fn add_coin_with_stealth_nonce(
        &mut self,
        coin: PrivateCoin,
        secrets: &clvm_zk_core::coin_commitment::CoinSecrets,
        stealth_nonce: [u8; 32],
        puzzle_source: String,
        metadata: CoinMetadata,
        recipient_pubkey: [u8; 32],
    ) -> [u8; 32] {
        let serial_number = secrets.serial_number();
        let encrypted_nonce = encrypt_stealth_nonce(&stealth_nonce, &recipient_pubkey);
        let info = CoinInfo {
            coin: coin.clone(),
            metadata,
            created_at_height: self.block_height,
            stealth_nonce: Some(encrypted_nonce),
            puzzle_source: Some(puzzle_source),
            tail_source: None,
        };

        let coin_commitment = CoinCommitment::compute(
            &coin.tail_hash,
            coin.amount,
            &coin.puzzle_hash,
            &coin.serial_commitment,
            crate::crypto_utils::hash_data_default,
        );

        let h = hasher();
        let leaf_index = self.coin_tree.len();
        self.coin_tree.insert(coin_commitment.0, h);
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
        let merkle_root = self.coin_tree.root();

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

            match Spender::create_ring_spend(coin_data, merkle_root, None, vec![]) {
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

                // for CAT coins, look up the stored tail_source so the backend can authorize
                let coin_tail_source = self
                    .utxo_set
                    .get(&secrets.serial_number)
                    .and_then(|info| info.tail_source.clone());

                match Spender::create_spend_with_serial(
                    &coin,
                    &program,
                    &params,
                    &secrets,
                    merkle_path,
                    merkle_root,
                    leaf_index,
                    coin_tail_source,
                    vec![],
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
        let h = hasher();
        for commitment in &new_coin_commitments {
            let leaf_index = self.coin_tree.len();
            self.coin_tree.insert(*commitment, h);
            self.commitment_to_index.insert(*commitment, leaf_index);
            self.merkle_leaves.push(*commitment);
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
                // NOTE: stealth outputs use separate add_coin_with_stealth_nonce flow
                // ZK proof outputs don't include stealth metadata (nonces are out-of-band)
                self.utxo_set.insert(
                    secrets.serial_number,
                    CoinInfo {
                        coin,
                        metadata,
                        created_at_height: self.block_height,
                        stealth_nonce: None,
                        puzzle_source: None,
                        tail_source: None,
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

    /// mint new CAT tokens using a TAIL program
    ///
    /// calls ClvmZkProver::prove_with_input with CoinMode::Mint, then registers the minted
    /// coin in the simulator state (merkle tree + utxo_set).
    ///
    /// returns (coin_commitment, tail_hash)
    pub fn mint_cat(
        &mut self,
        tail_source: &str,
        tail_params: Vec<crate::ProgramParameter>,
        output_puzzle_hash: [u8; 32],
        output_puzzle_source: &str,
        output_amount: u64,
        output_serial: [u8; 32],
        output_rand: [u8; 32],
        genesis_coin: Option<clvm_zk_core::GenesisSpend>,
    ) -> Result<([u8; 32], [u8; 32]), SimulatorError> {
        // Step 1: compile tail_source to get tail_hash
        let (_, tail_hash) =
            clvm_zk_core::compile_chialisp_to_bytecode(crate::crypto_utils::hash_data_default, tail_source)
                .map_err(|e| {
                    SimulatorError::ProofGeneration(format!("TAIL compilation failed: {:?}", e))
                })?;

        // Step 1b: pre-check genesis nullifier to prevent double-mint
        if let Some(ref gen) = genesis_coin {
            let genesis_nullifier = clvm_zk_core::compute_genesis_nullifier(
                crate::crypto_utils::hash_data_default,
                &gen.serial_number,
                &gen.tail_hash,
            );
            if self.nullifier_set.contains(&genesis_nullifier) {
                return Err(SimulatorError::DoubleSpend(hex::encode(genesis_nullifier)));
            }
        }

        // Step 2: build MintData
        let mint_data = clvm_zk_core::MintData {
            tail_source: tail_source.to_string(),
            tail_params,
            output_puzzle_hash,
            output_amount,
            output_serial,
            output_rand,
            genesis_coin,
        };

        // Step 3: build Input with CoinMode::Mint
        let input = crate::Input {
            chialisp_source: "(mod () ())".to_string(),
            program_parameters: vec![],
            coin_mode: crate::CoinMode::Mint(mint_data),
            tail_hash: Some(tail_hash),
            tail_source: None,
            tail_params: vec![],
            additional_coins: None,
        };

        // Step 4: prove
        let result = crate::ClvmZkProver::prove_with_input(input)
            .map_err(|e| SimulatorError::ProofGeneration(format!("{}", e)))?;

        // Step 5: extract coin_commitment from public_values[0]
        let coin_commitment_vec = result.proof_output.public_values.first().ok_or_else(|| {
            SimulatorError::ProofGeneration(
                "mint proof missing coin_commitment in public_values[0]".to_string(),
            )
        })?;
        if coin_commitment_vec.len() != 32 {
            return Err(SimulatorError::ProofGeneration(
                "coin_commitment must be 32 bytes".to_string(),
            ));
        }
        let mut coin_commitment = [0u8; 32];
        coin_commitment.copy_from_slice(coin_commitment_vec);

        // Step 6: insert genesis nullifier if present
        for nullifier in &result.proof_output.nullifiers {
            self.nullifier_set.insert(*nullifier);
        }

        // Step 7: compute serial_commitment for UTXO keying
        let serial_commitment = clvm_zk_core::compute_serial_commitment(
            crate::crypto_utils::hash_data_default,
            &output_serial,
            &output_rand,
        );

        // Step 8: insert new coin into utxo_set
        let private_coin = PrivateCoin::new_with_tail(
            output_puzzle_hash,
            output_amount,
            clvm_zk_core::coin_commitment::SerialCommitment::from_bytes(serial_commitment),
            tail_hash,
        );
        self.utxo_set.insert(
            output_serial,
            CoinInfo {
                coin: private_coin,
                metadata: CoinMetadata {
                    owner: "mint".to_string(),
                    coin_type: CoinType::Cat,
                    notes: format!("minted CAT tail:{}", hex::encode(&tail_hash[..8])),
                },
                created_at_height: self.block_height,
                stealth_nonce: None,
                puzzle_source: Some(output_puzzle_source.to_string()),
                tail_source: Some(tail_source.to_string()),
            },
        );

        // Step 9: insert coin_commitment into merkle tree
        let h = hasher();
        let leaf_index = self.coin_tree.len();
        self.coin_tree.insert(coin_commitment, h);
        self.commitment_to_index.insert(coin_commitment, leaf_index);
        self.merkle_leaves.push(coin_commitment);

        // Step 10: return (coin_commitment, tail_hash)
        Ok((coin_commitment, tail_hash))
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

    /// Get all coins with stealth nonces for hash-based stealth scanning.
    /// Returns `(puzzle_hash, nonce_blob, coin_info)` for each stealth coin.
    /// `nonce_blob` is either 92 bytes (encrypted, PR4+) or 32 bytes (plaintext, legacy).
    /// Callers must decrypt with `decrypt_stealth_nonce` before use.
    pub fn get_stealth_scannable_coins(&self) -> Vec<(&[u8; 32], Vec<u8>, &CoinInfo)> {
        self.utxo_set
            .iter()
            .filter_map(|(_serial, info)| {
                info.stealth_nonce.as_ref().and_then(|nonce| {
                    if nonce.len() == 32 || nonce.len() == 92 {
                        Some((&info.coin.puzzle_hash, nonce.clone(), info))
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
        let h = hasher();
        let proof = self
            .coin_tree
            .generate_proof(leaf_index, h)
            .inspect_err(|e| {
                eprintln!(
                    "WARN: merkle proof generation failed for leaf_index {}: {}",
                    leaf_index, e
                );
            })
            .ok()?;
        let path = proof.path;

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
        let h = hasher();
        let proof = self
            .coin_tree
            .generate_proof(leaf_index, h)
            .map_err(|e| e.to_string())?;
        let proof_hashes = &proof.path;
        eprintln!("  merkle_path length: {}", proof_hashes.len());
        for (i, hash) in proof_hashes.iter().enumerate() {
            eprintln!("    path[{}]: {}", i, hex::encode(hash));
        }

        // Get the expected root
        let expected_root = self.coin_tree.root();
        eprintln!("  expected_root: {}", hex::encode(expected_root));

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

        if computed_root == expected_root {
            eprintln!("  RESULT: ✓ MERKLE PROOF VALID");
            Ok(())
        } else {
            eprintln!("  RESULT: ✗ MERKLE PROOF INVALID!");
            Err(format!(
                "root mismatch: computed={}, expected={}",
                hex::encode(computed_root),
                hex::encode(expected_root)
            ))
        }
    }

    /// Debug helper: dump entire merkle tree state
    pub fn debug_dump_tree_state(&self) {
        eprintln!("\n=== MERKLE TREE STATE ===");
        eprintln!("  leaves_len: {}", self.coin_tree.len());
        eprintln!("  root: {}", hex::encode(self.coin_tree.root()));
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

    pub fn get_merkle_root(&self) -> [u8; 32] {
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
        self.coin_tree = default_coin_tree();
        self.commitment_to_index.clear();
        self.merkle_leaves.clear();
        self.transactions.clear();
        self.block_height = 0;
    }

    /// process settlement output: add nullifiers and commitments to simulator state
    pub fn process_settlement(
        &mut self,
        output: &crate::protocol::SettlementOutput,
    ) -> Result<(), String> {
        // reject already-spent nullifiers (double-spend protection)
        if self.nullifier_set.contains(&output.maker_nullifier) {
            return Err("maker nullifier already spent".into());
        }
        if self.nullifier_set.contains(&output.taker_nullifier) {
            return Err("taker nullifier already spent".into());
        }
        // add nullifiers to nullifier set
        self.nullifier_set.insert(output.maker_nullifier);
        self.nullifier_set.insert(output.taker_nullifier);

        // add all 4 coin commitments to merkle tree
        let commitments = [
            output.maker_change_commitment,
            output.payment_commitment,
            output.taker_goods_commitment,
            output.taker_change_commitment,
        ];

        let h = hasher();
        for commitment in &commitments {
            let leaf_index = self.coin_tree.len();
            self.coin_tree.insert(*commitment, h);
            self.commitment_to_index.insert(*commitment, leaf_index);
            self.merkle_leaves.push(*commitment);
        }
        Ok(())
    }
}

/// coin info in simulator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinInfo {
    pub coin: PrivateCoin,
    pub metadata: CoinMetadata,
    pub created_at_height: u64,
    /// stealth nonce for hash-based stealth address scanning (32 bytes)
    /// sender transmits this encrypted; receiver decrypts to derive shared_secret
    #[serde(default, alias = "ephemeral_pubkey")]
    pub stealth_nonce: Option<Vec<u8>>,
    /// chialisp source for stealth coins (needed for spending)
    #[serde(default)]
    pub puzzle_source: Option<String>,
    /// TAIL source for CAT coins (needed to re-authorize spends)
    #[serde(default)]
    pub tail_source: Option<String>,
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
    Cat,
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
