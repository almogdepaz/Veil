use clvm_zk::{ClvmZkProver, ProgramParameter};
use clvm_zk_core::coin_commitment::{CoinCommitment, CoinSecrets};
use clvm_zk_core::merkle::SparseMerkleTree;
use sha2::{Digest, Sha256};

fn hash_data(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn compile_program_hash(program: &str) -> [u8; 32] {
    clvm_zk_core::compile_chialisp_template_hash(hash_data, program)
        .expect("program compilation failed")
}

fn main() {
    println!("=== recursive proof aggregation demo ===\n");
    println!("note: requires risc0 or sp1 backend (mock backend doesn't support aggregation)\n");

    // setup: create merkle tree for coins
    println!("setting up merkle tree...");
    let mut merkle_tree = SparseMerkleTree::new(20, hash_data);
    let program = "(mod (x) (* x 2))";
    let program_hash = compile_program_hash(program);

    // create 10 coins with proper commitments
    println!("creating 10 coins with serial commitments...");
    let mut coin_data = Vec::new();

    for i in 0..10 {
        let amount = 1000 + i as u64;

        // generate coin secrets (serial_number + serial_randomness)
        let serial_number = [i as u8; 32];
        let serial_randomness = [(i + 100) as u8; 32];
        let coin_secrets = CoinSecrets::new(serial_number, serial_randomness);

        // compute commitments
        let serial_commitment = coin_secrets.serial_commitment(hash_data);
        let coin_commitment = CoinCommitment::compute(amount, &program_hash, &serial_commitment, hash_data);

        // insert into merkle tree
        let leaf_index = merkle_tree.insert(*coin_commitment.as_bytes(), hash_data);

        coin_data.push((coin_secrets, amount, serial_commitment, coin_commitment, leaf_index));
    }

    let merkle_root = merkle_tree.root();
    println!("✓ created 10 coins in merkle tree\n");

    // generate 10 transaction proofs with nullifiers
    println!("generating 10 base proofs with nullifiers...");
    let mut proofs = Vec::new();

    for (i, (coin_secrets, amount, serial_commitment, coin_commitment, leaf_index)) in coin_data.iter().enumerate() {
        // generate merkle proof
        let merkle_proof_struct = merkle_tree.generate_proof(*leaf_index, hash_data).unwrap();
        let merkle_path = merkle_proof_struct.path;

        // generate proof with serial commitment (full nullifier protocol)
        let proof = ClvmZkProver::prove_with_serial_commitment(
            program,
            &[ProgramParameter::Int(i as u64)],
            coin_secrets,
            merkle_path,
            *coin_commitment.as_bytes(),
            *serial_commitment.as_bytes(),
            merkle_root,
            *leaf_index,
            program_hash,
            *amount,
        )
        .unwrap();

        proofs.push(proof);
    }
    println!("✓ generated 10 proofs with nullifiers\n");

    let proof_refs: Vec<&[u8]> = proofs.iter().map(|p| p.proof_bytes.as_slice()).collect();

    // aggregate all proofs into one
    println!("aggregating 10 proofs → 1...");
    let start = std::time::Instant::now();
    let aggregated = ClvmZkProver::aggregate_proofs(&proof_refs)
        .expect("aggregation failed - backend may not support recursion");
    let elapsed = start.elapsed();

    println!("✓ aggregation complete");
    println!("  took: {:?}", elapsed);
    println!("  proof size: {} KB", aggregated.len() / 1024);
    println!("  compression: {} proofs → 1 proof", proofs.len());

    println!("\n=== demo complete ===");
}
