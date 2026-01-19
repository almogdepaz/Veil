use clvm_zk::{ClvmZkProver, ProgramParameter};
use clvm_zk_core::coin_commitment::{CoinCommitment, CoinSecrets, XCH_TAIL};
use clvm_zk_core::merkle::SparseMerkleTree;
use sha2::{Digest, Sha256};
use std::fs;
use std::time::Instant;

fn hash_data(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn compile_program_hash(program: &str) -> [u8; 32] {
    clvm_zk_core::compile_chialisp_template_hash(hash_data, program)
        .expect("program compilation failed")
}

/// # Proof Database Generator
///
/// generates realistic coin-spending proofs for testing recursive aggregation.
///
/// ## aggregation testing workflow
///
/// 1. **generate base proofs**: creates N independent coin-spend proofs
///    - each with unique nullifier (prevents collisions during aggregation)
///    - uses CREATE_COIN chialisp program
///    - proves knowledge of spend_secret
///
/// 2. **save to disk**: stores proofs as binary files for benchmarking
///    - backend-specific directory: `test_proof_database_{risc0|sp1}/`
///    - numbered files: `proof_000.bin`, `proof_001.bin`, etc.
///
/// 3. **test aggregation**: combines proofs into single aggregated proof
///    - demonstrates flat aggregation: N base proofs → 1 aggregated proof
///    - measures compression ratio (total input size / output size)
///    - verifies recursive proving implementation works
///
/// 4. **output metadata**: CSV with timing and size data for analysis
///
/// ## aggregation mechanics tested
///
/// - **nullifier merging**: all N nullifiers included in aggregated output
/// - **condition merging**: all N clvm outputs preserved
/// - **commitment generation**: hash(program_hash || nullifier || output) per proof
/// - **proof compression**: N×262KB → 1×262KB (risc0) = Nx compression
///
/// ## usage
///
/// ```bash
/// # generate 3 proofs with risc0 (default)
/// cargo run --example generate_proof_database --no-default-features --features risc0 --release
///
/// # generate 20 proofs with sp1
/// cargo run --example generate_proof_database --no-default-features --features sp1 --release -- 20
/// ```
///
/// ## performance
///
/// - risc0: ~45s per proof, 3 proofs ≈ 2-3 min
/// - sp1: significantly faster
fn main() {
    // parse command line arguments for proof count
    let args: Vec<String> = std::env::args().collect();
    let proof_count: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(3); // default: 3 proofs

    // detect backend from cargo features
    let backend_name = if cfg!(feature = "risc0") {
        "risc0"
    } else if cfg!(feature = "sp1") {
        "sp1"
    } else {
        eprintln!("error: no backend feature enabled");
        eprintln!("run with: --no-default-features --features <risc0|sp1>");
        std::process::exit(1);
    };

    println!(
        "=== generating {} coin-spending proofs ({} backend) ===\n",
        proof_count, backend_name
    );

    // backend-specific directory for proof database
    let output_dir = format!("test_proof_database_{}", backend_name);
    fs::create_dir_all(&output_dir).expect("failed to create output directory");

    // chialisp program that creates CREATE_COIN condition
    // CREATE_COIN is recognized by the compiler and converted to opcode 51
    let coin_spend_program = r#"
        (mod (amount recipient_hash)
            (list CREATE_COIN recipient_hash amount)
        )
    "#;

    let mut total_prove_time = std::time::Duration::ZERO;
    let mut total_proof_size = 0usize;
    let mut proofs_data = Vec::new();

    // setup: create merkle tree and coins with proper commitments
    println!("creating coins with serial commitments...");
    let program_hash = compile_program_hash(coin_spend_program);
    let mut merkle_tree = SparseMerkleTree::new(20, hash_data);
    let mut coin_data = Vec::new();

    for i in 0..proof_count {
        let amount = (100 + (i * 99)) as u64;

        // generate unique coin secrets
        let serial_number = {
            let mut sn = [0u8; 32];
            sn[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            sn
        };
        let serial_randomness = {
            let mut sr = [0u8; 32];
            sr[0..8].copy_from_slice(&((i + 1000) as u64).to_le_bytes());
            sr
        };
        let coin_secrets = CoinSecrets::new(serial_number, serial_randomness);

        // compute commitments
        let serial_commitment = coin_secrets.serial_commitment(hash_data);
        let coin_commitment = CoinCommitment::compute(
            &XCH_TAIL,
            amount,
            &program_hash,
            &serial_commitment,
            hash_data,
        );

        // insert into merkle tree
        let leaf_index = merkle_tree.insert(*coin_commitment.as_bytes(), hash_data);

        coin_data.push((
            coin_secrets,
            amount,
            serial_commitment,
            coin_commitment,
            leaf_index,
        ));
    }

    let merkle_root = merkle_tree.root();
    println!("✓ created {} coins in merkle tree\n", proof_count);

    println!("generating proofs with nullifiers...");
    let start_all = Instant::now();

    for (i, (coin_secrets, amount, serial_commitment, coin_commitment, leaf_index)) in
        coin_data.iter().enumerate()
    {
        // generate recipient hash for CREATE_COIN condition
        let mut recipient_hash = [0u8; 32];
        let recipient_id = ((i + 1) % 100) as u64;
        recipient_hash[0..8].copy_from_slice(&recipient_id.to_le_bytes());

        // generate merkle proof
        let merkle_proof_struct = merkle_tree.generate_proof(*leaf_index, hash_data).unwrap();
        let merkle_path = merkle_proof_struct.path;

        // generate proof with serial commitment (full nullifier protocol)
        let prove_start = Instant::now();
        let result = ClvmZkProver::prove_with_serial_commitment(
            coin_spend_program,
            &[
                ProgramParameter::Int(*amount),
                ProgramParameter::Bytes(recipient_hash.to_vec()),
            ],
            coin_secrets,
            merkle_path,
            *coin_commitment.as_bytes(),
            *serial_commitment.as_bytes(),
            merkle_root,
            *leaf_index,
            program_hash,
            *amount,
            None, // XCH (no CAT tail_hash)
        )
        .expect(&format!("failed to generate proof {}", i));

        let prove_time = prove_start.elapsed();
        total_prove_time += prove_time;
        total_proof_size += result.proof_bytes.len();

        // save proof for aggregation benchmarking
        let proof_path = format!("{}/proof_{:03}.bin", output_dir, i);
        fs::write(&proof_path, &result.proof_bytes).expect(&format!("failed to write proof {}", i));

        proofs_data.push((
            i,
            amount,
            result.proof_output.nullifiers.first().copied().unwrap(),
            prove_time,
            result.proof_bytes.len(),
        ));

        // progress output
        let progress_interval = (proof_count / 10).max(1);
        if (i + 1) % progress_interval == 0 || i + 1 == proof_count {
            println!(
                "  [{:3}/{}] avg time: {:>4}ms, avg size: {:>3}KB",
                i + 1,
                proof_count,
                total_prove_time.as_millis() / (i as u128 + 1),
                total_proof_size / (i + 1) / 1024
            );
        }
    }

    let total_time = start_all.elapsed();

    println!("\n=== proof generation complete ===");
    println!("total time: {:.2}s", total_time.as_secs_f64());
    println!(
        "average time per proof: {}ms",
        total_prove_time.as_millis() / proof_count as u128
    );
    println!(
        "average proof size: {}KB",
        total_proof_size / proof_count / 1024
    );
    println!(
        "total size: {:.2}MB",
        total_proof_size as f64 / 1024.0 / 1024.0
    );

    // save metadata CSV
    let mut metadata = String::from("proof_id,amount,nullifier,prove_time_ms,size_bytes\n");
    for (id, amount, nullifier, time, size) in proofs_data {
        metadata.push_str(&format!(
            "{},{},{},{},{}\n",
            id,
            amount,
            hex::encode(nullifier),
            time.as_millis(),
            size
        ));
    }

    fs::write(format!("{}/metadata.csv", output_dir), metadata).expect("failed to write metadata");

    println!("\nproofs saved to: {}/", output_dir);
    println!("metadata saved to: {}/metadata.csv", output_dir);

    // test aggregation: N base proofs → 1 aggregated proof
    if proof_count >= 2 {
        println!("\n=== testing aggregation ===");
        let agg_count = proof_count.min(10);
        println!("loading {} proofs...", agg_count);

        let mut proof_bytes = Vec::new();
        for i in 0..agg_count {
            let proof_path = format!("{}/proof_{:03}.bin", output_dir, i);
            let bytes = fs::read(&proof_path).expect("failed to read proof");
            proof_bytes.push(bytes);
        }

        let proof_refs: Vec<&[u8]> = proof_bytes.iter().map(|p| p.as_slice()).collect();

        // aggregate: guest verifies N proofs via zkVM verify(), merges outputs
        println!("aggregating {} proofs...", agg_count);
        let agg_start = Instant::now();
        let aggregated = ClvmZkProver::aggregate_proofs(&proof_refs).expect("aggregation failed");
        let agg_time = agg_start.elapsed();

        let total_size: usize = proof_bytes.iter().map(|p| p.len()).sum();
        let compression = total_size as f64 / aggregated.len() as f64;

        println!("✓ aggregation successful");
        println!("  time: {:.2}s", agg_time.as_secs_f64());
        println!("  aggregated proof size: {}KB", aggregated.len() / 1024);
        println!(
            "  compression: {:.1}x ({} KB → {} KB)",
            compression,
            total_size / 1024,
            aggregated.len() / 1024
        );
    } else {
        println!("\n=== skipping aggregation test (need ≥2 proofs) ===");
    }

    println!("\n=== benchmark complete ===");
}
