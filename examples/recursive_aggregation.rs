use clvm_zk::{ClvmZkProver, ProgramParameter};

fn main() {
    println!("=== recursive proof aggregation demo ===\n");

    // create 10 transaction proofs
    println!("generating 10 base proofs...");
    let mut proofs = Vec::new();
    for i in 0..10 {
        let spend_secret = [i as u8; 32];
        let proof = ClvmZkProver::prove_with_nullifier(
            "(mod (x) (* x 2))",
            &[ProgramParameter::Int(i as u64)],
            spend_secret,
        )
        .unwrap();
        proofs.push(proof);
    }
    println!("✓ generated 10 proofs\n");

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
