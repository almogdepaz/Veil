use clvm_zk::ClvmZkProver;
use std::fs;
use std::time::Instant;

/// # Aggregation Benchmarking Tool
///
/// benchmarks recursive proof aggregation across different batch sizes.
/// uses pre-generated proof database from `generate_proof_database`.
///
/// ## workflow
///
/// 1. **load proofs**: reads all proofs from `test_proof_database_{backend}/`
/// 2. **test batch sizes**: aggregates 2, 5, 10, 20, 50, 100 proofs (up to available)
/// 3. **measure metrics**: time, proof size, compression ratio, throughput
///
/// ## aggregation mechanics
///
/// for each batch:
/// - **guest program**: verifies N base proofs using zkVM verify()
/// - **merges outputs**: combines nullifiers, conditions, commitments
/// - **constant output size**: aggregated proof ≈ 262KB (risc0) regardless of N
/// - **compression**: N×262KB → 1×262KB = Nx compression
///
/// ## metrics
///
/// - **time**: increases with N (more proofs to verify)
/// - **proof KB**: constant (~262KB for risc0)
/// - **compress**: N proofs → 1 proof ratio
/// - **throughput**: proofs/second aggregated
///
/// ## usage
///
/// ```bash
/// # generate database first
/// cargo run --example generate_proof_database --no-default-features --features risc0 --release -- 20
///
/// # then benchmark
/// cargo run --example benchmark_aggregation --no-default-features --features risc0 --release
/// ```
fn main() {
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

    let proof_dir = format!("test_proof_database_{}", backend_name);

    if !std::path::Path::new(&proof_dir).exists() {
        eprintln!(
            "error: proof database not found for {} backend",
            backend_name
        );
        eprintln!(
            "run: cargo run --example generate_proof_database --no-default-features --features {}",
            backend_name
        );
        std::process::exit(1);
    }

    println!(
        "=== recursive aggregation benchmark ({} backend) ===\n",
        backend_name
    );

    // count available proofs
    let available_proofs = fs::read_dir(&proof_dir)
        .expect("failed to read directory")
        .filter(|e| e.is_ok())
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .path()
                .extension()
                .map_or(false, |ext| ext == "bin")
        })
        .count();

    if available_proofs == 0 {
        eprintln!("error: no proofs found in {}", proof_dir);
        std::process::exit(1);
    }

    // load all proofs
    println!("loading {} proofs...", available_proofs);
    let load_start = Instant::now();
    let mut all_proofs = Vec::new();
    for i in 0..available_proofs {
        let proof_path = format!("{}/proof_{:03}.bin", proof_dir, i);
        let bytes = fs::read(&proof_path).expect(&format!("failed to read proof {}", i));
        all_proofs.push(bytes);
    }
    let load_time = load_start.elapsed();
    println!(
        "✓ loaded {} proofs in {}ms\n",
        available_proofs,
        load_time.as_millis()
    );

    // test batch sizes up to available proofs
    let batch_sizes: Vec<usize> = vec![2, 5, 10, 20, 50, 100]
        .into_iter()
        .filter(|&size| size <= available_proofs)
        .collect();

    println!(
        "{:>5} | {:>10} | {:>10} | {:>10} | {:>10}",
        "batch", "time (s)", "proof KB", "compress", "throughput"
    );
    println!(
        "{:-<5}-+-{:-<10}-+-{:-<10}-+-{:-<10}-+-{:-<10}",
        "", "", "", "", ""
    );

    for &batch_size in &batch_sizes {
        if batch_size > all_proofs.len() {
            continue;
        }

        let batch: Vec<&[u8]> = all_proofs[0..batch_size]
            .iter()
            .map(|p| p.as_slice())
            .collect();

        // aggregate N → 1: guest verifies each base proof, merges outputs
        let agg_start = Instant::now();
        let result = ClvmZkProver::aggregate_proofs(&batch);
        let agg_time = agg_start.elapsed();

        match result {
            Ok(aggregated) => {
                let input_size: usize = batch.iter().map(|p| p.len()).sum();
                let output_size = aggregated.len();
                let compression = input_size as f64 / output_size as f64;
                let throughput = batch_size as f64 / agg_time.as_secs_f64();

                println!(
                    "{:>5} | {:>10.2} | {:>10} | {:>10.1}x | {:>7.1} p/s",
                    batch_size,
                    agg_time.as_secs_f64(),
                    output_size / 1024,
                    compression,
                    throughput
                );
            }
            Err(e) => {
                println!("{:>5} | FAILED: {}", batch_size, e);
            }
        }
    }

    println!("\n=== benchmark complete ===");
}
