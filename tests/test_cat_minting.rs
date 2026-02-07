//! CAT minting test
//!
//! demonstrates:
//! 1. defining a TAIL program (token asset issuance limiter)
//! 2. computing tail_hash from the TAIL program bytecode
//! 3. minting CAT coins with that tail_hash
//! 4. spending minted CAT coins
//! 5. ring spends with CAT coins (multi-input)
//! 6. generating ZK mint proofs (risc0/sp1)

#[cfg(feature = "mock")]
use clvm_zk::protocol::Spender;
use clvm_zk::protocol::PrivateCoin;
use clvm_zk_core::{
    compile_chialisp_template_hash_default, coin_commitment::CoinCommitment,
    with_standard_conditions, XCH_TAIL,
};
#[cfg(feature = "mock")]
use clvm_zk_core::ProgramParameter;
#[cfg(feature = "risc0")]
use clvm_zk_core::{
    coin_commitment::CoinSecrets, merkle::SparseMerkleTree, GenesisSpend, Input, MintData,
};

/// compute SHA256 hash
fn hash_data(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// TAIL program that allows unlimited minting (for testing)
/// in production you'd use signature-based or governance-controlled TAILs
const UNLIMITED_TAIL: &str = "(mod () 1)";

/// TAIL program that requires a signature to mint
/// (more realistic but requires BLS setup)
#[allow(dead_code)]
const SIGNATURE_TAIL: &str = "(mod (pubkey signature) (bls_verify pubkey (sha256 1) signature))";

/// compute tail_hash from a TAIL program
/// this is how CAT asset types are identified
fn compute_tail_hash(tail_program: &str) -> [u8; 32] {
    compile_chialisp_template_hash_default(tail_program)
        .expect("TAIL program should compile")
}

#[test]
fn test_tail_hash_computation() {
    println!("\n=== TAIL HASH COMPUTATION TEST ===\n");

    // compute tail_hash for unlimited TAIL
    let unlimited_tail_hash = compute_tail_hash(UNLIMITED_TAIL);
    println!("unlimited TAIL program: {}", UNLIMITED_TAIL);
    println!("unlimited tail_hash: {}", hex::encode(unlimited_tail_hash));

    // verify it's not all zeros (that would be XCH)
    assert_ne!(
        unlimited_tail_hash, XCH_TAIL,
        "TAIL hash should not equal XCH_TAIL"
    );

    // verify determinism - same program should produce same hash
    let hash2 = compute_tail_hash(UNLIMITED_TAIL);
    assert_eq!(
        unlimited_tail_hash, hash2,
        "TAIL hash should be deterministic"
    );

    // different TAIL program should produce different hash
    let different_tail = "(mod () 2)";
    let different_hash = compute_tail_hash(different_tail);
    assert_ne!(
        unlimited_tail_hash, different_hash,
        "different TAIL programs should produce different hashes"
    );

    println!("\n✓ TAIL hash computation works correctly");
}

#[test]
fn test_cat_coin_creation() {
    println!("\n=== CAT COIN CREATION TEST ===\n");

    // 1. define our TAIL program
    let tail_program = UNLIMITED_TAIL;
    let tail_hash = compute_tail_hash(tail_program);
    println!("minting CAT with tail_hash: {}", hex::encode(tail_hash));

    // 2. create a puzzle for our CAT coin
    let cat_puzzle = with_standard_conditions(
        "(mod (out_puzzle out_amount out_serial out_rand)
            (list (list CREATE_COIN out_puzzle out_amount out_serial out_rand)))",
    );
    let cat_puzzle_hash =
        compile_chialisp_template_hash_default(&cat_puzzle).expect("compile puzzle");

    // 3. "mint" a CAT coin (create coin with the computed tail_hash)
    let mint_amount = 1000u64;
    let (cat_coin, cat_secrets) =
        PrivateCoin::new_with_secrets_and_tail(cat_puzzle_hash, mint_amount, tail_hash);

    println!("minted CAT coin:");
    println!("  amount: {} mojos", mint_amount);
    println!("  tail_hash: {}", hex::encode(cat_coin.tail_hash));
    println!("  is_cat: {}", cat_coin.is_cat());
    println!("  is_xch: {}", cat_coin.is_xch());

    // verify the coin is a CAT, not XCH
    assert!(cat_coin.is_cat(), "minted coin should be a CAT");
    assert!(!cat_coin.is_xch(), "minted coin should not be XCH");
    assert_eq!(cat_coin.tail_hash, tail_hash, "tail_hash should match");

    // 4. verify commitment includes tail_hash
    let commitment = CoinCommitment::compute(
        &cat_coin.tail_hash,
        cat_coin.amount,
        &cat_coin.puzzle_hash,
        &cat_coin.serial_commitment,
        hash_data,
    );

    // same coin as XCH should have different commitment
    let xch_commitment = CoinCommitment::compute(
        &XCH_TAIL,
        cat_coin.amount,
        &cat_coin.puzzle_hash,
        &cat_coin.serial_commitment,
        hash_data,
    );

    assert_ne!(
        commitment, xch_commitment,
        "CAT commitment should differ from XCH commitment"
    );

    println!("  CAT commitment: {}...", hex::encode(&commitment.0[..8]));
    println!("  XCH commitment: {}...", hex::encode(&xch_commitment.0[..8]));

    // store secrets for later use
    let _ = cat_secrets;

    println!("\n✓ CAT coin creation works correctly");
}

#[test]
#[cfg(feature = "mock")]
fn test_cat_spend() {
    println!("\n=== CAT SPEND TEST (MOCK) ===\n");

    // 1. mint a CAT coin
    let tail_hash = compute_tail_hash(UNLIMITED_TAIL);

    // balanced puzzle that outputs full amount
    let spend_puzzle = with_standard_conditions(
        "(mod (out_puzzle out_serial out_rand)
            (list (list CREATE_COIN out_puzzle 1000 out_serial out_rand)))",
    );
    let puzzle_hash = compile_chialisp_template_hash_default(&spend_puzzle).expect("compile");

    let (cat_coin, cat_secrets) =
        PrivateCoin::new_with_secrets_and_tail(puzzle_hash, 1000, tail_hash);

    println!("minted CAT: {} mojos", cat_coin.amount);
    println!("tail_hash: {}...", hex::encode(&tail_hash[..8]));

    // 2. create merkle tree (single leaf)
    let commitment = CoinCommitment::compute(
        &cat_coin.tail_hash,
        cat_coin.amount,
        &cat_coin.puzzle_hash,
        &cat_coin.serial_commitment,
        clvm_zk::crypto_utils::hash_data_default,
    );
    let merkle_root = commitment.0;

    // 3. spend parameters
    let out_puzzle = [1u8; 32];
    let out_serial = [2u8; 32];
    let out_rand = [3u8; 32];

    let solution_params = vec![
        ProgramParameter::Bytes(out_puzzle.to_vec()),
        ProgramParameter::Bytes(out_serial.to_vec()),
        ProgramParameter::Bytes(out_rand.to_vec()),
    ];

    // 4. create spend proof
    let result = Spender::create_spend_with_serial(
        &cat_coin,
        &spend_puzzle,
        &solution_params,
        &cat_secrets,
        vec![], // empty merkle path for single-leaf tree
        merkle_root,
        0,
    );

    match result {
        Ok(bundle) => {
            println!("\n✓ CAT spend proof generated");
            println!("  proof size: {} bytes", bundle.zk_proof.len());
            println!("  nullifiers: {}", bundle.nullifiers.len());

            // verify nullifier is present
            assert!(!bundle.nullifiers.is_empty(), "should have nullifier");
            assert_ne!(
                bundle.nullifiers[0], [0u8; 32],
                "nullifier should be non-zero"
            );

            println!("\n✓ CAT SPEND TEST PASSED");
        }
        Err(e) => {
            panic!("CAT spend failed: {:?}", e);
        }
    }
}

#[test]
#[cfg(feature = "mock")]
fn test_cat_ring_spend() {
    println!("\n=== CAT RING SPEND TEST (MOCK) ===\n");

    // 1. mint multiple CAT coins with SAME tail_hash
    let tail_hash = compute_tail_hash(UNLIMITED_TAIL);
    println!("minting 3 CAT coins with tail_hash: {}...", hex::encode(&tail_hash[..8]));

    // balanced puzzle - each outputs its own amount
    let puzzle1 = with_standard_conditions(
        "(mod () (list (list CREATE_COIN 0x0101010101010101010101010101010101010101010101010101010101010101 100)))",
    );
    let puzzle2 = with_standard_conditions(
        "(mod () (list (list CREATE_COIN 0x0202020202020202020202020202020202020202020202020202020202020202 200)))",
    );
    let puzzle3 = with_standard_conditions(
        "(mod () (list (list CREATE_COIN 0x0303030303030303030303030303030303030303030303030303030303030303 300)))",
    );

    let hash1 = compile_chialisp_template_hash_default(&puzzle1).expect("compile");
    let hash2 = compile_chialisp_template_hash_default(&puzzle2).expect("compile");
    let hash3 = compile_chialisp_template_hash_default(&puzzle3).expect("compile");

    let (coin1, secrets1) = PrivateCoin::new_with_secrets_and_tail(hash1, 100, tail_hash);
    let (coin2, secrets2) = PrivateCoin::new_with_secrets_and_tail(hash2, 200, tail_hash);
    let (coin3, secrets3) = PrivateCoin::new_with_secrets_and_tail(hash3, 300, tail_hash);

    println!("coin1: {} mojos, is_cat: {}", coin1.amount, coin1.is_cat());
    println!("coin2: {} mojos, is_cat: {}", coin2.amount, coin2.is_cat());
    println!("coin3: {} mojos, is_cat: {}", coin3.amount, coin3.is_cat());
    println!("total: {} mojos", coin1.amount + coin2.amount + coin3.amount);

    // 2. build merkle tree with all 3 coins
    let commit1 = CoinCommitment::compute(
        &coin1.tail_hash,
        coin1.amount,
        &coin1.puzzle_hash,
        &coin1.serial_commitment,
        clvm_zk::crypto_utils::hash_data_default,
    );
    let commit2 = CoinCommitment::compute(
        &coin2.tail_hash,
        coin2.amount,
        &coin2.puzzle_hash,
        &coin2.serial_commitment,
        clvm_zk::crypto_utils::hash_data_default,
    );
    let commit3 = CoinCommitment::compute(
        &coin3.tail_hash,
        coin3.amount,
        &coin3.puzzle_hash,
        &coin3.serial_commitment,
        clvm_zk::crypto_utils::hash_data_default,
    );

    // simple 4-leaf tree (3 coins + 1 padding)
    let padding = [0u8; 32];
    let left_branch = clvm_zk::crypto_utils::hash_data_default(
        &[commit1.0.as_slice(), commit2.0.as_slice()].concat(),
    );
    let right_branch = clvm_zk::crypto_utils::hash_data_default(
        &[commit3.0.as_slice(), padding.as_slice()].concat(),
    );
    let merkle_root =
        clvm_zk::crypto_utils::hash_data_default(&[left_branch.as_slice(), right_branch.as_slice()].concat());

    // merkle paths
    let path1 = vec![commit2.0, right_branch];
    let path2 = vec![commit1.0, right_branch];
    let path3 = vec![padding, left_branch];

    // 3. create ring spend
    let coins = vec![
        (&coin1, puzzle1.as_str(), &[][..], &secrets1, path1, 0),
        (&coin2, puzzle2.as_str(), &[][..], &secrets2, path2, 1),
        (&coin3, puzzle3.as_str(), &[][..], &secrets3, path3, 2),
    ];

    let result = Spender::create_ring_spend(coins, merkle_root);

    match result {
        Ok(bundle) => {
            println!("\n✓ CAT ring spend proof generated");
            println!("  proof size: {} bytes", bundle.zk_proof.len());
            println!("  nullifiers: {}", bundle.nullifiers.len());

            // should have 3 nullifiers (one per coin)
            assert_eq!(bundle.nullifiers.len(), 3, "should have 3 nullifiers");

            // all nullifiers should be unique
            assert_ne!(bundle.nullifiers[0], bundle.nullifiers[1]);
            assert_ne!(bundle.nullifiers[1], bundle.nullifiers[2]);
            assert_ne!(bundle.nullifiers[0], bundle.nullifiers[2]);

            println!("\n✓ CAT RING SPEND TEST PASSED");
        }
        Err(e) => {
            panic!("CAT ring spend failed: {:?}", e);
        }
    }
}

#[test]
#[cfg(feature = "mock")]
fn test_cat_tail_mismatch_rejected() {
    println!("\n=== CAT TAIL MISMATCH TEST (MOCK) ===\n");

    // try to create ring spend with different tail_hashes - should fail
    let tail1 = compute_tail_hash(UNLIMITED_TAIL);
    let tail2 = compute_tail_hash("(mod () 2)"); // different TAIL

    let puzzle = with_standard_conditions(
        "(mod () (list (list CREATE_COIN 0x0101010101010101010101010101010101010101010101010101010101010101 100)))",
    );
    let hash = compile_chialisp_template_hash_default(&puzzle).expect("compile");

    let (coin1, secrets1) = PrivateCoin::new_with_secrets_and_tail(hash, 100, tail1);
    let (coin2, secrets2) = PrivateCoin::new_with_secrets_and_tail(hash, 100, tail2);

    println!("coin1 tail: {}...", hex::encode(&tail1[..8]));
    println!("coin2 tail: {}...", hex::encode(&tail2[..8]));

    // build merkle tree
    let commit1 = CoinCommitment::compute(
        &coin1.tail_hash,
        coin1.amount,
        &coin1.puzzle_hash,
        &coin1.serial_commitment,
        clvm_zk::crypto_utils::hash_data_default,
    );
    let commit2 = CoinCommitment::compute(
        &coin2.tail_hash,
        coin2.amount,
        &coin2.puzzle_hash,
        &coin2.serial_commitment,
        clvm_zk::crypto_utils::hash_data_default,
    );

    let merkle_root = clvm_zk::crypto_utils::hash_data_default(
        &[commit1.0.as_slice(), commit2.0.as_slice()].concat(),
    );

    let path1 = vec![commit2.0];
    let path2 = vec![commit1.0];

    // attempt ring spend with mismatched tails
    let coins = vec![
        (&coin1, puzzle.as_str(), &[][..], &secrets1, path1, 0),
        (&coin2, puzzle.as_str(), &[][..], &secrets2, path2, 1),
    ];

    let result = Spender::create_ring_spend(coins, merkle_root);

    match result {
        Ok(_) => {
            panic!("ring spend with mismatched tails should fail!");
        }
        Err(e) => {
            println!("✓ correctly rejected: {:?}", e);
            assert!(
                format!("{:?}", e).contains("tail_hash"),
                "error should mention tail_hash"
            );
            println!("\n✓ CAT TAIL MISMATCH TEST PASSED");
        }
    }
}

/// test the proper ZK mint proof flow with risc0 backend
/// this generates an actual zkvm proof that verifies TAIL authorization
#[test]
#[cfg(feature = "risc0")]
fn test_mint_proof_risc0() {
    use clvm_zk_risc0::Risc0Backend;

    println!("\n=== MINT PROOF TEST (RISC0) ===\n");

    let backend = Risc0Backend::new().expect("risc0 backend should initialize");

    // prepare mint data
    let output_puzzle_hash = [42u8; 32];
    let output_serial = [1u8; 32];
    let output_rand = [2u8; 32];
    let output_amount = 1000u64;

    let mint_data = MintData {
        tail_source: UNLIMITED_TAIL.to_string(),
        tail_params: vec![],
        output_puzzle_hash,
        output_amount,
        output_serial,
        output_rand,
        genesis_coin: None,
    };

    // create input with mint mode
    let input = Input {
        chialisp_source: "".to_string(), // not used in mint mode
        program_parameters: vec![],
        serial_commitment_data: None,
        tail_hash: None,
        additional_coins: None,
        mint_data: Some(mint_data),
        tail_source: None,
    };

    println!("generating mint proof...");
    let result = backend.prove_with_input(input);

    match result {
        Ok(zk_result) => {
            println!("✓ mint proof generated");
            println!("  proof size: {} bytes", zk_result.proof_bytes.len());
            println!("  program_hash (tail_hash): {}", hex::encode(zk_result.proof_output.program_hash));
            println!("  nullifiers: {} (should be 0 for mint)", zk_result.proof_output.nullifiers.len());
            println!("  proof_type: {}", zk_result.proof_output.proof_type);

            // verify proof type is Mint (3)
            assert_eq!(zk_result.proof_output.proof_type, 3, "proof_type should be Mint (3)");

            // verify no nullifiers (minting doesn't spend coins)
            assert!(
                zk_result.proof_output.nullifiers.is_empty(),
                "mint should have no nullifiers"
            );

            // verify public_values contains tail_hash and coin_commitment
            assert_eq!(
                zk_result.proof_output.public_values.len(),
                2,
                "should have 2 public values"
            );

            let tail_hash = &zk_result.proof_output.public_values[0];
            let coin_commitment = &zk_result.proof_output.public_values[1];

            println!("  public tail_hash: {}", hex::encode(tail_hash));
            println!("  public coin_commitment: {}", hex::encode(coin_commitment));

            // verify tail_hash matches expected
            let expected_tail_hash = compute_tail_hash(UNLIMITED_TAIL);
            assert_eq!(
                tail_hash.as_slice(),
                expected_tail_hash.as_slice(),
                "tail_hash should match UNLIMITED_TAIL"
            );

            // verify coin_commitment is 32 bytes
            assert_eq!(
                coin_commitment.len(),
                32,
                "coin_commitment should be 32 bytes"
            );

            println!("\n✓ MINT PROOF TEST (RISC0) PASSED");
        }
        Err(e) => {
            panic!("mint proof failed: {:?}", e);
        }
    }
}

/// test that mint with failing TAIL is rejected
#[test]
#[cfg(feature = "risc0")]
fn test_mint_failing_tail_rejected() {
    use clvm_zk_risc0::Risc0Backend;

    println!("\n=== MINT FAILING TAIL TEST (RISC0) ===\n");

    let backend = Risc0Backend::new().expect("risc0 backend should initialize");

    // TAIL that returns nil (fails authorization)
    let failing_tail = "(mod () ())";

    let mint_data = MintData {
        tail_source: failing_tail.to_string(),
        tail_params: vec![],
        output_puzzle_hash: [42u8; 32],
        output_amount: 1000,
        output_serial: [1u8; 32],
        output_rand: [2u8; 32],
        genesis_coin: None,
    };

    let input = Input {
        chialisp_source: "".to_string(),
        program_parameters: vec![],
        serial_commitment_data: None,
        tail_hash: None,
        additional_coins: None,
        mint_data: Some(mint_data),
        tail_source: None,
    };

    println!("attempting mint with failing TAIL...");
    let result = backend.prove_with_input(input);

    match result {
        Ok(_) => {
            panic!("mint with failing TAIL should be rejected!");
        }
        Err(e) => {
            println!("✓ correctly rejected: {:?}", e);
            println!("\n✓ MINT FAILING TAIL TEST PASSED");
        }
    }
}

/// test minting multiple different CAT types
/// demonstrates that each TAIL program produces a unique asset type
#[test]
#[cfg(feature = "risc0")]
fn test_mint_multiple_cats() {
    use clvm_zk_risc0::Risc0Backend;

    println!("\n=== MINT MULTIPLE CATS TEST (RISC0) ===\n");

    let backend = Risc0Backend::new().expect("risc0 backend should initialize");

    // define 3 different CAT types with different TAIL programs
    let cats = vec![
        ("GOLD", "(mod () 1)"),                           // unlimited gold
        ("SILVER", "(mod () 2)"),                         // different constant = different hash
        ("BRONZE", "(mod (x) (> x 0))"),                  // requires positive param
    ];

    let mut minted_cats: Vec<([u8; 32], Vec<u8>)> = vec![];

    for (i, (name, tail_source)) in cats.iter().enumerate() {
        println!("minting {}...", name);

        let mint_data = MintData {
            tail_source: tail_source.to_string(),
            tail_params: if *name == "BRONZE" {
                vec![clvm_zk_core::ProgramParameter::Int(100)] // pass positive param
            } else {
                vec![]
            },
            output_puzzle_hash: [(i + 1) as u8; 32],
            output_amount: (i + 1) as u64 * 1000,
            output_serial: [(i + 10) as u8; 32],
            output_rand: [(i + 20) as u8; 32],
            genesis_coin: None,
        };

        let input = Input {
            chialisp_source: "".to_string(),
            program_parameters: vec![],
            serial_commitment_data: None,
            tail_hash: None,
            additional_coins: None,
            mint_data: Some(mint_data),
            tail_source: None,
        };

        let result = backend.prove_with_input(input).expect("mint should succeed");

        let tail_hash: [u8; 32] = result.proof_output.public_values[0]
            .clone()
            .try_into()
            .expect("tail_hash should be 32 bytes");
        let coin_commitment = result.proof_output.public_values[1].clone();

        println!("  {} tail_hash: {}", name, hex::encode(&tail_hash[..8]));
        println!("  {} coin_commitment: {}", name, hex::encode(&coin_commitment[..8]));
        println!("  {} amount: {} mojos", name, (i + 1) * 1000);

        minted_cats.push((tail_hash, coin_commitment));
    }

    // verify all tail_hashes are unique
    println!("\nverifying uniqueness...");
    assert_ne!(minted_cats[0].0, minted_cats[1].0, "GOLD != SILVER");
    assert_ne!(minted_cats[1].0, minted_cats[2].0, "SILVER != BRONZE");
    assert_ne!(minted_cats[0].0, minted_cats[2].0, "GOLD != BRONZE");

    // verify all coin_commitments are unique
    assert_ne!(minted_cats[0].1, minted_cats[1].1, "commitments unique");
    assert_ne!(minted_cats[1].1, minted_cats[2].1, "commitments unique");

    println!("✓ all 3 CAT types have unique tail_hashes");
    println!("✓ all coin_commitments are unique");

    // verify none equal XCH
    for (i, (tail_hash, _)) in minted_cats.iter().enumerate() {
        assert_ne!(
            *tail_hash, XCH_TAIL,
            "CAT {} should not equal XCH",
            ["GOLD", "SILVER", "BRONZE"][i]
        );
    }
    println!("✓ none equal XCH_TAIL");

    println!("\n✓ MINT MULTIPLE CATS TEST PASSED");
    println!("  minted: GOLD (1000), SILVER (2000), BRONZE (3000)");
}

/// test genesis-linked minting: mint is bound to a genesis coin
/// the genesis coin's nullifier prevents double-minting
#[test]
#[cfg(feature = "risc0")]
fn test_genesis_linked_mint() {
    use clvm_zk_risc0::Risc0Backend;

    println!("\n=== GENESIS-LINKED MINT TEST (RISC0) ===\n");

    let backend = Risc0Backend::new().expect("risc0 backend should initialize");

    // 1. create a genesis coin (an XCH coin that authorizes one-time minting)
    let genesis_serial = [11u8; 32];
    let genesis_rand = [12u8; 32];
    let genesis_puzzle_hash = [13u8; 32];
    let genesis_amount = 0u64; // genesis can be zero-value
    let genesis_tail_hash = XCH_TAIL; // genesis is XCH

    // compute genesis commitments
    let genesis_secrets = CoinSecrets::new(genesis_serial, genesis_rand);
    let genesis_serial_commitment = genesis_secrets.serial_commitment(hash_data);
    let genesis_coin_commitment = CoinCommitment::compute(
        &genesis_tail_hash,
        genesis_amount,
        &genesis_puzzle_hash,
        &genesis_serial_commitment,
        hash_data,
    );

    // put genesis coin in merkle tree
    let mut merkle_tree = SparseMerkleTree::new(20, hash_data);
    let leaf_index = merkle_tree.insert(*genesis_coin_commitment.as_bytes(), hash_data);
    let merkle_root = merkle_tree.root();
    let merkle_proof = merkle_tree.generate_proof(leaf_index, hash_data).unwrap();

    println!("genesis coin created:");
    println!("  commitment: {}...", hex::encode(&genesis_coin_commitment.as_bytes()[..8]));
    println!("  merkle_root: {}...", hex::encode(&merkle_root[..8]));

    // 2. TAIL program that checks genesis_nullifier matches expected value
    // for this test, use unlimited TAIL (just verifies genesis mechanism works)
    // a production TAIL would: (mod (genesis_nullifier) (= genesis_nullifier EXPECTED))
    let tail_source = "(mod (genesis_nullifier) 1)"; // accepts any genesis nullifier

    // 3. create mint with genesis coin
    let mint_data = MintData {
        tail_source: tail_source.to_string(),
        tail_params: vec![], // genesis_nullifier will be prepended automatically
        output_puzzle_hash: [42u8; 32],
        output_amount: 5000,
        output_serial: [50u8; 32],
        output_rand: [51u8; 32],
        genesis_coin: Some(GenesisSpend {
            serial_number: genesis_serial,
            serial_randomness: genesis_rand,
            puzzle_hash: genesis_puzzle_hash,
            amount: genesis_amount,
            tail_hash: genesis_tail_hash,
            serial_commitment: *genesis_serial_commitment.as_bytes(),
            coin_commitment: *genesis_coin_commitment.as_bytes(),
            merkle_path: merkle_proof.path,
            merkle_root,
            leaf_index,
        }),
    };

    let input = Input {
        chialisp_source: "".to_string(),
        program_parameters: vec![],
        serial_commitment_data: None,
        tail_hash: None,
        additional_coins: None,
        mint_data: Some(mint_data),
        tail_source: None,
    };

    println!("generating genesis-linked mint proof...");
    let result = backend.prove_with_input(input).expect("genesis mint should succeed");

    // verify proof includes genesis nullifier
    assert_eq!(result.proof_output.proof_type, 3, "should be mint type");
    assert_eq!(
        result.proof_output.nullifiers.len(),
        1,
        "should have 1 nullifier (genesis)"
    );

    let genesis_nullifier = result.proof_output.nullifiers[0];
    println!("  genesis nullifier: {}", hex::encode(genesis_nullifier));
    assert_ne!(genesis_nullifier, [0u8; 32], "nullifier should be non-zero");

    // verify determinism: same genesis should produce same nullifier
    // this is what prevents double-minting: validators track nullifier set
    let expected_nullifier = clvm_zk_core::compute_nullifier(
        hash_data,
        &genesis_serial,
        &genesis_puzzle_hash,
        genesis_amount,
    );
    assert_eq!(
        genesis_nullifier, expected_nullifier,
        "nullifier should be deterministic"
    );

    println!("  ✓ genesis nullifier matches expected");
    println!("  ✓ same genesis coin → same nullifier → can't mint twice");

    println!("\n✓ GENESIS-LINKED MINT TEST PASSED");
}

/// verify that genesis nullifier is deterministic across mints
/// (same genesis = same nullifier = validator rejects second mint)
#[test]
#[cfg(feature = "risc0")]
fn test_genesis_nullifier_determinism() {
    println!("\n=== GENESIS NULLIFIER DETERMINISM TEST ===\n");

    // two different genesis coins should produce different nullifiers
    let nullifier_a = clvm_zk_core::compute_nullifier(
        hash_data,
        &[1u8; 32], // serial_number
        &[2u8; 32], // puzzle_hash
        100,
    );
    let nullifier_b = clvm_zk_core::compute_nullifier(
        hash_data,
        &[3u8; 32], // different serial
        &[2u8; 32],
        100,
    );

    assert_ne!(nullifier_a, nullifier_b, "different genesis = different nullifier");
    println!("  ✓ different genesis coins → different nullifiers");

    // same genesis coin always produces same nullifier
    let nullifier_a2 = clvm_zk_core::compute_nullifier(
        hash_data,
        &[1u8; 32],
        &[2u8; 32],
        100,
    );
    assert_eq!(nullifier_a, nullifier_a2, "same genesis = same nullifier");
    println!("  ✓ same genesis coin → same nullifier (deterministic)");

    println!("\n✓ GENESIS NULLIFIER DETERMINISM TEST PASSED");
    println!("  validators add genesis nullifier to spent set");
    println!("  second mint attempt → nullifier already in set → REJECTED");
}
