#![cfg(feature = "risc0")]

use clvm_zk_risc0::{Risc0Backend, RecursiveAggregator, AggregationStrategy};
use clvm_zk_core::ProgramParameter;

#[test]
fn test_minimal_aggregation_2_to_1() {
    println!("testing minimal 2→1 aggregation...");

    let backend = Risc0Backend::new().expect("risc0 backend should initialize");
    let aggregator = RecursiveAggregator::new().expect("aggregator should initialize");

    // generate 2 base proofs
    let mut proofs = Vec::new();
    for i in 0..2 {
        let spend_secret = [i as u8; 32];
        let proof = backend
            .prove_chialisp_with_nullifier(
                "(mod (x) (* x 2))",
                &[ProgramParameter::Int(i as u64)],
                spend_secret
            )
            .expect("proof generation should succeed");
        proofs.push(proof);
    }

    let proof_refs: Vec<&[u8]> = proofs.iter().map(|p| p.proof_bytes.as_slice()).collect();

    // aggregate
    let aggregated = aggregator
        .aggregate_proofs_with_strategy(&proof_refs, AggregationStrategy::Flat)
        .expect("aggregation should succeed");

    // verify aggregated proof is smaller than 2 separate proofs
    let total_size: usize = proofs.iter().map(|p| p.proof_bytes.len()).sum();
    println!("  2 separate proofs: {} bytes", total_size);
    println!("  1 aggregated proof: {} bytes", aggregated.len());
    assert!(aggregated.len() < total_size, "aggregated proof should be smaller");

    println!("✓ 2→1 aggregation works");
}

#[test]
fn test_aggregation_strategies_produce_same_size() {
    println!("testing that all strategies produce same proof size...");

    let backend = Risc0Backend::new().expect("risc0 backend should initialize");
    let aggregator = RecursiveAggregator::new().expect("aggregator should initialize");

    // generate 6 base proofs
    let mut proofs = Vec::new();
    for i in 0..6 {
        let spend_secret = [i as u8; 32];
        let proof = backend
            .prove_chialisp_with_nullifier(
                "(mod (x) (+ x 1))",
                &[ProgramParameter::Int(i as u64)],
                spend_secret
            )
            .expect("proof generation should succeed");
        proofs.push(proof);
    }

    let proof_refs: Vec<&[u8]> = proofs.iter().map(|p| p.proof_bytes.as_slice()).collect();

    // test flat
    let flat_size = aggregator
        .aggregate_proofs_with_strategy(&proof_refs, AggregationStrategy::Flat)
        .expect("flat aggregation should succeed")
        .len();

    // test multi-level with batch_size=2 (6→3→2→1)
    let multilevel_size = aggregator
        .aggregate_proofs_with_strategy(&proof_refs, AggregationStrategy::MultiLevel { batch_size: 2 })
        .expect("multi-level aggregation should succeed")
        .len();

    // test auto
    let auto_size = aggregator
        .aggregate_proofs_with_strategy(&proof_refs, AggregationStrategy::Auto)
        .expect("auto aggregation should succeed")
        .len();

    println!("  flat: {} bytes", flat_size);
    println!("  multi-level: {} bytes", multilevel_size);
    println!("  auto: {} bytes", auto_size);

    // all strategies should produce roughly same size (within 10%)
    let max_size = flat_size.max(multilevel_size).max(auto_size);
    let min_size = flat_size.min(multilevel_size).min(auto_size);
    let variance = (max_size - min_size) as f64 / min_size as f64;

    assert!(variance < 0.1, "proof sizes should be within 10%, got variance: {:.1}%", variance * 100.0);

    println!("✓ all strategies produce consistent proof sizes");
}

#[test]
fn test_nullifier_uniqueness_preserved() {
    println!("testing nullifier uniqueness is preserved...");

    let backend = Risc0Backend::new().expect("risc0 backend should initialize");
    let aggregator = RecursiveAggregator::new().expect("aggregator should initialize");

    // generate 3 proofs with different nullifiers
    let secrets = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let mut proofs = Vec::new();

    for (i, secret) in secrets.iter().enumerate() {
        let proof = backend
            .prove_chialisp_with_nullifier(
                "(mod (x) x)",
                &[ProgramParameter::Int(i as u64)],
                *secret
            )
            .expect("proof generation should succeed");
        proofs.push(proof);
    }

    let proof_refs: Vec<&[u8]> = proofs.iter().map(|p| p.proof_bytes.as_slice()).collect();

    // aggregate - should succeed because all nullifiers are unique
    let result = aggregator.aggregate_proofs_with_strategy(&proof_refs, AggregationStrategy::Flat);
    assert!(result.is_ok(), "aggregation should succeed with unique nullifiers");

    println!("✓ nullifier uniqueness preserved");
}

#[test]
fn test_single_proof_handling() {
    println!("testing single proof edge case...");

    let backend = Risc0Backend::new().expect("risc0 backend should initialize");
    let aggregator = RecursiveAggregator::new().expect("aggregator should initialize");

    // generate 1 proof
    let proof = backend
        .prove_chialisp_with_nullifier(
            "(mod (x) (* x 3))",
            &[ProgramParameter::Int(5)],
            [42u8; 32]
        )
        .expect("proof generation should succeed");

    let proof_refs = vec![proof.proof_bytes.as_slice()];

    // aggregate single proof
    let result = aggregator.aggregate_proofs_with_strategy(&proof_refs, AggregationStrategy::Flat);

    // should handle gracefully (either wrap it or return it as-is)
    assert!(result.is_ok(), "single proof aggregation should succeed");

    println!("✓ single proof handled correctly");
}

#[test]
fn test_empty_batch_rejected() {
    println!("testing empty batch is rejected...");

    let aggregator = RecursiveAggregator::new().expect("aggregator should initialize");

    let empty_proofs: Vec<&[u8]> = vec![];

    // should reject empty batch
    let result = aggregator.aggregate_proofs_with_strategy(&empty_proofs, AggregationStrategy::Flat);

    assert!(result.is_err(), "empty batch should be rejected");

    println!("✓ empty batch rejected");
}

#[test]
fn test_auto_strategy_chooses_correctly() {
    println!("testing auto strategy selection...");

    let backend = Risc0Backend::new().expect("risc0 backend should initialize");
    let aggregator = RecursiveAggregator::new().expect("aggregator should initialize");

    // generate 5 proofs (should choose flat)
    let mut proofs = Vec::new();
    for i in 0..5 {
        let proof = backend
            .prove_chialisp_with_nullifier(
                "(mod (x) x)",
                &[ProgramParameter::Int(i as u64)],
                [i as u8; 32]
            )
            .expect("proof generation should succeed");
        proofs.push(proof);
    }

    let proof_refs: Vec<&[u8]> = proofs.iter().map(|p| p.proof_bytes.as_slice()).collect();

    let start = std::time::Instant::now();
    let auto_result = aggregator
        .aggregate_proofs_with_strategy(&proof_refs, AggregationStrategy::Auto)
        .expect("auto aggregation should succeed");
    let auto_time = start.elapsed();

    let start = std::time::Instant::now();
    let flat_result = aggregator
        .aggregate_proofs_with_strategy(&proof_refs, AggregationStrategy::Flat)
        .expect("flat aggregation should succeed");
    let flat_time = start.elapsed();

    println!("  auto: {:?}", auto_time);
    println!("  flat: {:?}", flat_time);

    // for 5 proofs, auto should choose flat (times should be similar)
    assert_eq!(auto_result.len(), flat_result.len(), "auto should choose flat for small batches");

    println!("✓ auto strategy working correctly");
}
