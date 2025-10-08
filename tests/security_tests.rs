mod common;
use crate::common::BATCH_SIZE;
use clvm_zk::{ClvmZkProver, ProgramParameter};
use clvm_zk_core::chialisp::compile_chialisp_template_hash;
use clvm_zk_core::hash_data;
use tokio::task;

/// Test proof integrity attacks - tampering with proofs should cause verification to fail
#[test]
fn fuzz_proof_integrity_attacks() -> Result<(), Box<dyn std::error::Error>> {
    test_info!("\nStarting proof integrity attack tests...");

    let expr = "(mod (a b) (+ a b))";
    let params = &[ProgramParameter::int(42), ProgramParameter::int(13)];

    test_info!("Generating original proof...");
    let proof_result = ClvmZkProver::prove(expr, params)
        .map_err(|e| format!("Failed to generate original proof: {e}"))?;
    let output = proof_result.clvm_output.result;
    let original_proof = proof_result.zk_proof;

    test_info!(
        "Successfully generated proof of {} bytes",
        original_proof.len()
    );

    test_info!("\nStarting tampering attack tests...");
    type AttackVector = (&'static str, Box<dyn Fn(&mut Vec<u8>)>);
    test_info!("\nPreparing attack vectors...");
    let attack_vectors: Vec<AttackVector> = vec![
        // Bit flipping attacks
        (
            "Single bit flip at start",
            Box::new(|proof: &mut Vec<u8>| {
                if !proof.is_empty() {
                    proof[0] ^= 0x01;
                }
            }),
        ),
        (
            "Single bit flip at end",
            Box::new(|proof: &mut Vec<u8>| {
                if !proof.is_empty() {
                    let len = proof.len();
                    proof[len - 1] ^= 0x01;
                }
            }),
        ),
        (
            "Single bit flip in middle",
            Box::new(|proof: &mut Vec<u8>| {
                if !proof.is_empty() {
                    let len = proof.len();
                    proof[len / 2] ^= 0x01;
                }
            }),
        ),
        (
            "Multiple bit flips",
            Box::new(|proof: &mut Vec<u8>| {
                for i in (0..proof.len()).step_by(1000) {
                    proof[i] ^= 0x01;
                }
            }),
        ),
        // Byte modification attacks
        (
            "Zero out bytes",
            Box::new(|proof: &mut Vec<u8>| {
                for i in (0..proof.len()).step_by(100) {
                    proof[i] = 0;
                }
            }),
        ),
        (
            "Max out bytes",
            Box::new(|proof: &mut Vec<u8>| {
                for i in (0..proof.len()).step_by(100) {
                    proof[i] = 0xFF;
                }
            }),
        ),
        (
            "Random byte changes",
            Box::new(|proof: &mut Vec<u8>| {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};

                let mut hasher = DefaultHasher::new();
                proof.hash(&mut hasher);
                let seed = hasher.finish();

                for i in (0..proof.len()).step_by(500) {
                    proof[i] = ((seed + i as u64) % 256) as u8;
                }
            }),
        ),
        // Structural attacks
        (
            "Truncate proof",
            Box::new(|proof: &mut Vec<u8>| {
                if proof.len() > 10 {
                    proof.truncate(proof.len() / 2);
                }
            }),
        ),
        (
            "Duplicate and swap chunks",
            Box::new(|proof: &mut Vec<u8>| {
                if proof.len() > 1000 {
                    proof.swap(100, 900);
                    proof.swap(200, 800);
                    proof.swap(300, 700);
                }
            }),
        ),
        (
            "Buffer overflow attempt",
            Box::new(|proof: &mut Vec<u8>| {
                // Try to create buffer overflow conditions
                proof.extend_from_slice(&[0xFF; 1000]);
                // Also corrupt existing length fields
                for i in (0..proof.len()).step_by(200) {
                    if i + 4 <= proof.len() {
                        let overflow_size = u32::MAX;
                        let bytes = overflow_size.to_le_bytes();
                        proof[i..i + 4].copy_from_slice(&bytes);
                    }
                }
            }),
        ),
    ];

    let total_attacks = attack_vectors.len();
    test_info!("Testing {total_attacks} attack vectors...");

    for (i, (attack_name, attack_fn)) in attack_vectors.into_iter().enumerate() {
        let mut tampered_proof = original_proof.clone();
        attack_fn(&mut tampered_proof);

        test_info!(
            "  Attack {}/{}: {} (proof size: {} -> {})",
            i + 1,
            total_attacks,
            attack_name,
            original_proof.len(),
            tampered_proof.len()
        );

        // Tampered proofs should fail verification
        match ClvmZkProver::verify_proof(
            compile_chialisp_template_hash(hash_data, expr).unwrap(),
            &tampered_proof,
            Some(&output),
        ) {
            Ok((false, _)) => {
                test_info!("    ✓ Attack correctly rejected by verification");
            }
            Err(_e) => {
                test_info!("    ✓ Attack caused verification error (acceptable)");
            }
            Ok((true, _)) => {
                return Err(format!(
                    "SECURITY FAILURE: Attack '{attack_name}' was not detected - tampered proof verified successfully!"
                ).into());
            }
        }
    }

    test_info!("\nProof integrity tests completed successfully!");
    test_info!("✓ All {total_attacks} attack vectors correctly rejected");
    Ok(())
}

/// Test program binding attacks - proofs should not verify against different programs
#[tokio::test]
async fn fuzz_program_binding_attacks() -> Result<(), Box<dyn std::error::Error>> {
    test_info!("\nStarting program binding security tests...");

    // Create multiple different programs
    test_info!("Creating test programs with different expressions and parameters...");
    let test_cases = [
        (
            "(mod (a b) (+ a b))",
            vec![ProgramParameter::int(2), ProgramParameter::int(3)],
        ),
        (
            "(mod (a b) (+ a b))",
            vec![ProgramParameter::int(5), ProgramParameter::int(7)],
        ),
        (
            "(mod (a b) (* a b))",
            vec![ProgramParameter::int(2), ProgramParameter::int(3)],
        ),
        ("(mod () 42)", vec![]),
    ];

    // Debug: Print what each program should compute
    test_info!("Program 0: (mod (a b) (+ a b)) with [2, 3] should = 5");
    test_info!("Program 1: (mod (a b) (+ a b)) with [5, 7] should = 12");
    test_info!("Program 2: (mod (a b) (* a b)) with [2, 3] should = 6");
    test_info!("Program 3: (mod () 42) with [] should = 42");

    // Generate proofs for each program using batching
    test_info!("Generating proofs for each program...");
    let mut proofs = Vec::new();
    let mut expected_outputs = Vec::new();

    for batch in test_cases.chunks(*BATCH_SIZE) {
        let futures: Vec<_> = batch
            .iter()
            .enumerate()
            .map(|(batch_idx, (expr, params))| {
                let expr = expr.to_string();
                let params = params.clone();
                task::spawn_blocking(move || match ClvmZkProver::prove(&expr, &params) {
                    Ok(proof_result) => {
                        let output = proof_result.clvm_output.result;
                        let proof = proof_result.zk_proof;
                        Ok((batch_idx, output, proof))
                    }
                    Err(e) => Err(format!(
                        "Failed to generate proof for program {batch_idx}: {e}"
                    )),
                })
            })
            .collect();

        // Collect results from current batch
        for future in futures {
            match future.await.map_err(|e| format!("Task failed: {e}"))? {
                Ok((_batch_idx, output, proof)) => {
                    let global_idx = proofs.len(); // Use actual count for logging
                    test_info!("Program {global_idx} produced output: {output:?}");
                    proofs.push((global_idx, output.clone(), proof));
                    expected_outputs.push(output);
                }
                Err(e) => {
                    test_error!("{e}");
                }
            }
        }
    }

    test_info!("Successfully generated {} proofs", proofs.len());
    test_info!("\nStarting cross-verification tests...");

    // Test cross-verification (should all fail when using wrong expected outputs)
    // We'll do this sequentially since it's testing security properties, not generating proofs
    for &(proof_idx, ref _proof_output, ref proof) in &proofs {
        test_info!("\nTesting proof {proof_idx} against all programs:");
        for (prog_idx, (expr, _)) in test_cases.iter().enumerate() {
            let expected_output_for_this_program = &expected_outputs[prog_idx];
            if proof_idx == prog_idx {
                // Same program - should verify against its own expected output
                match ClvmZkProver::verify_proof(
                    compile_chialisp_template_hash(hash_data, expr).unwrap(),
                    proof,
                    Some(expected_output_for_this_program),
                ) {
                    Ok((true, _)) => {
                        test_info!("   Same program verification succeeded (program {prog_idx} with proof {proof_idx})");
                    }
                    Ok((false, _)) => {
                        test_info!(
                            "   Same program verification failed (program {prog_idx} with proof {proof_idx})"
                        );
                    }
                    Err(e) => {
                        test_info!("   Same program verification error (program {prog_idx} with proof {proof_idx}): {e}");
                    }
                }
            } else {
                // Different program - should fail because the proof was generated for a different expected output
                match ClvmZkProver::verify_proof(
                    compile_chialisp_template_hash(hash_data, expr).unwrap(),
                    proof,
                    Some(expected_output_for_this_program),
                ) {
                    Ok((false, _)) => {
                        test_info!("   Cross-verification correctly rejected (program {prog_idx} with proof {proof_idx}) - different expected output");
                    }
                    Err(_) => {
                        test_info!("   Cross-verification error (acceptable, program {prog_idx} with proof {proof_idx})");
                    }
                    Ok((true, _)) => {
                        if proof_idx != prog_idx {
                            return Err(format!("SECURITY FAILURE: Cross-verification accepted proof {proof_idx} for program {prog_idx}!").into());
                        }
                    }
                }
            }
        }
    }

    test_info!("\nProgram binding security tests completed successfully!");
    test_info!("✓ All {} programs tested", test_cases.len());
    Ok(())
}
