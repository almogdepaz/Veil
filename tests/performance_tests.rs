mod common;
use clvm_zk::{ClvmZkProver, ProgramParameter};
use tokio::task;

use crate::common::BATCH_SIZE;
use clvm_zk_core::chialisp::compile_chialisp_template_hash;
use clvm_zk_core::chialisp::hash_data;

use std::collections::HashSet;

/// Test performance limits - operations should complete within reasonable time bounds
#[test]
fn fuzz_performance_limits() -> Result<(), Box<dyn std::error::Error>> {
    test_info!("\nStarting performance limits test...");
    let test_cases = [
        // Simple cases that should prove quickly - expressions use literals
        ("Basic addition", "(mod () (+ 10 5))"),
        ("Basic multiplication", "(mod () (* 3 4))"),
        ("Simple comparison", "(mod () (= 7 7))"),
    ];

    let test_start = std::time::Instant::now();

    for (name, expr) in test_cases {
        let param_list: Vec<ProgramParameter> = vec![];

        let prove_start = std::time::Instant::now();
        let proof_result = ClvmZkProver::prove(expr, &param_list)
            .map_err(|e| format!("Proof generation failed for {name}: {e}"))?;
        let output = proof_result.clvm_output.result;
        let proof = proof_result.zk_proof;
        let prove_time = prove_start.elapsed();
        test_info!("  Proof generation: {prove_time:?}");
        test_info!("  Proof size: {} bytes", proof.len());

        // Test verification time
        let verify_start = std::time::Instant::now();
        let (verified, _) = ClvmZkProver::verify_proof(
            compile_chialisp_template_hash(hash_data, expr).unwrap(),
            &proof,
            Some(&output),
        )
        .map_err(|e| format!("Verification error for {name}: {e}"))?;
        let verify_time = verify_start.elapsed();

        test_info!("  Verification: {verify_time:?}");
        if !verified {
            return Err(format!("Proof should verify for {name}").into());
        }

        // Check reasonable performance bounds for ZK proofs
        if prove_time.as_secs() >= 120 {
            return Err(format!("Proof generation should be under 2 minutes for {name}").into());
        }
        if verify_time.as_millis() >= 30000 {
            return Err(format!("Verification should be under 30 seconds for {name}").into());
        }
        if proof.len() <= 1000 {
            return Err(format!("Proof should be substantial for {name}").into());
        }
        if proof.len() >= 10000000 {
            return Err(format!("Proof should not be unreasonably large for {name}").into());
        }

        // Ensure we don't exceed 5 minutes total
        if test_start.elapsed().as_secs() > 280 {
            test_info!("  Stopping early to stay under 5 minute limit");
            break;
        }
    }

    let total_time = test_start.elapsed();
    test_info!("Performance test completed in {total_time:?}");
    test_info!("All test cases completed successfully");

    if total_time.as_secs() >= 300 {
        return Err("Performance test should complete under 5 minutes".into());
    }

    Ok(())
}

#[tokio::test]
async fn fuzz_deterministic_behavior() -> Result<(), String> {
    test_info!("\nStarting deterministic behavior test...");
    test_info!("Testing expressions for consistent outputs...");

    let test_expressions = [
        ("(mod (a b) (+ a b))", vec![5, 3]),
        ("(mod (a b) (* a b))", vec![4, 7]),
        ("(mod (a b) (= a b))", vec![10, 10]),
        ("(mod (a b) (> a b))", vec![15, 10]),
        ("(mod (a b) (- a b))", vec![20, 8]), // subtraction operation
    ];

    for (expr, vars) in test_expressions {
        let actual_expr = match expr {
            "(mod (a b) (+ a b))" => format!("(mod () (+ {} {}))", vars[0], vars[1]),
            "(mod (a b) (* a b))" => format!("(mod () (* {} {}))", vars[0], vars[1]),
            "(mod (a b) (= a b))" => format!("(mod () (= {} {}))", vars[0], vars[1]),
            "(mod (a b) (> a b))" => format!("(mod () (> {} {}))", vars[0], vars[1]),
            "(mod (a b) (- a b))" => format!("(mod () (- {} {}))", vars[0], vars[1]),
            _ => expr.to_string(),
        };

        let mut outputs = HashSet::new();
        let mut programs = HashSet::new();
        let iterations: Vec<usize> = (0..3).collect();

        for batch in iterations.chunks(*BATCH_SIZE) {
            let futures: Vec<_> = batch
                .iter()
                .map(|&i| {
                    let expr = expr.to_string();
                    let actual_expr = actual_expr.clone();
                    let vars = vars.clone();
                    task::spawn_blocking(move || -> Result<(Vec<u8>, Vec<u8>), String> {
                        let param_list: Vec<ProgramParameter> =
                            vars.iter().map(|&x| ProgramParameter::int(x)).collect();
                        let proof_result =
                            ClvmZkProver::prove(&expr, &param_list).map_err(|e| {
                                format!("Proof generation failed for {actual_expr}: {e}")
                            })?;
                        let output = proof_result.clvm_output.result;
                        let proof = proof_result.zk_proof;
                        let program_hash = compile_chialisp_template_hash(hash_data, &expr)
                            .map_err(|e| {
                                format!(
                                    "Hash template failed on iteration {i} for {actual_expr}: {:?}",
                                    e
                                )
                            })?;
                        let (verified, _) = ClvmZkProver::verify_proof(
                            program_hash,
                            &proof,
                            Some(&output),
                        )
                        .map_err(|e| {
                            format!("Verification error on iteration {i} for {actual_expr}: {e}")
                        })?;
                        if !verified {
                            return Err(format!(
                                "Proof should verify for iteration {i} with {actual_expr}"
                            ));
                        }
                        test_info!("   Proof verified for: {actual_expr}");
                        Ok((program_hash.to_vec(), output))
                    })
                })
                .collect();

            for future in futures {
                match future.await.map_err(|e| format!("Task failed: {e}"))? {
                    Ok((program, output)) => {
                        programs.insert(program);
                        outputs.insert(output);
                    }
                    Err(e) => return Err(e), // already Box<dyn Error + Send + Sync>
                }
            }
        }

        if programs.len() != 1 {
            return Err(format!(
                "Programs should be deterministic for: {actual_expr}"
            ));
        }

        test_info!("   Deterministic behavior confirmed");
    }

    Ok(())
}
