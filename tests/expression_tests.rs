use clvm_zk::{ClvmZkProver, ProgramParameter};
use clvm_zk_core::chialisp::compile_chialisp_template_hash_default;

use tokio::task;

mod common;
use crate::common::BATCH_SIZE;

/// Test malformed expressions that should fail gracefully
#[test]
fn fuzz_malformed_expressions() -> Result<(), String> {
    test_info!("\nStarting malformed expressions test...");
    test_info!("Testing {} malformed expression categories...", 8); // categories: empty, unbalanced, invalid ops, wrong args, etc.
    let malformed_expressions = [
        // Empty and whitespace
        "",
        " ",
        "   ",
        "\n",
        "\t",
        // Unbalanced parentheses
        "(",
        ")",
        "(((",
        ")))",
        "(+ 1 2",
        "+ 1 2)",
        "((+ 1 2)",
        "(+ 1 2 3 4 5 6 7 8 9)", // Too many parameters for binary operator
        // Invalid operators and malformed expressions
        "(unknown_operator 1 2)",
        "(completely-invalid 1 2)",
        "(123abc 1 2)", // Invalid operator name
        "(+ 1)",        // Missing required parameter
        "()",           // Empty expression
        "(() 1 2)",     // Invalid empty operator
        "(+ (missing_paren 1 2)",
        "(-- 1 2)",
        // Wrong number of arguments
        "(+)",
        "(+ 1)",
        "(+ 1 2 3)",
        "(+ 1 2 3 4)",
        "(= 1)",
        "(= 1 2 3)",
        "(>)",
        "(> 1)",
        "(> 1 2 3)",
        // Invalid numbers and mixed types
        "(+ 1 undefined_var)",
        "(+ undefined_var 2)",
        "(+ 1.5 2)",
        "(+ 1 2.5)",
        "(+ 999999999999999999999 1)",
        // Nested malformed
        "(+ (+ 1) 2)",
        "(+ 1 (+ 2))",
        "(+ (unknown 1 2) 3)",
        // Special characters
        "(+ 1 @)",
        "(+ # 2)",
        "(+ 1 $)",
        "(+ 1 2 #)",
        // Mixed valid/invalid
        "(+ 1 2 3)", // Wrong arity - + expects exactly 2 arguments
        "(definitely_invalid_operator 1 2)",
        "((+ 1 2) (+ 3 4))", // Nested expressions without operator
    ];

    for expr in malformed_expressions {
        // All of these should fail at program creation or proof generation
        let param_list: Vec<ProgramParameter> = [1, 2, 3]
            .iter()
            .map(|&x| ProgramParameter::int(x))
            .collect();

        // If program creation succeeds, proof generation should fail
        match ClvmZkProver::prove(expr, &param_list) {
            Ok(result) => {
                let output = result.proof_output.clvm_res;
                let _proof = result.proof_bytes;
                // If proof somehow succeeds, it should be an error result
                return Err(format!("Malformed expression '{expr}' should not generate proof but got output: {output:?}"));
            }
            Err(_e) => {
                test_info!("  Correctly rejected at proof generation");
            }
        }
    }
    Ok(())
}

/// Test complex nested expressions
#[tokio::test]
async fn fuzz_complex_nested_expressions() -> Result<(), String> {
    test_info!("\nStarting complex nested expressions test...");
    test_info!("Preparing test cases...");
    let complex_expressions = [
        // Deeply nested arithmetic
        "(+ (+ (+ 1 2) (+ 3 4)) (+ (+ 5 6) (+ 7 8)))",
        "(* (* 2 3) (* 4 5))",
        "(- (+ 10 5) (- 8 3))",
        // Mixed operations
        "(+ (* 2 3) (- 10 4))",
        "(* (+ 1 2) (- 5 3))",
        "(- (* 4 5) (+ 2 3))",
        // Complex comparisons
        "(= (+ 1 2) (- 5 2))",
        "(= (* 2 3) (+ 4 2))",
        "(> (+ 5 3) (* 2 3))",
        "(> (* 3 4) (+ 5 6))",
        // Nested comparisons
        "(= (= 1 1) (= 2 2))",
        "(= (> 3 2) (> 5 4))",
        "(> (= 1 1) (= 1 2))",
        // Chain operations
        "(+ (+ (+ 1 1) 1) 1)",
        "(* (* (* 2 2) 2) 2)",
        "(- (- (- 10 1) 1) 1)",
        // Mixed with zeros
        "(+ (* 0 5) (- 10 10))",
        "(* (+ 0 1) (- 5 0))",
        "(= (+ 0 0) (* 0 5))",
        // Large nested expressions
        "(= (+ (* 2 3) (- 8 2)) (+ (+ 1 5) (- 7 1)))",
        "(> (+ (* 3 3) (- 10 1)) (+ (+ 4 4) (- 12 3)))",
    ];

    let total_cases = complex_expressions.len();
    let mut completed_count = 0;

    for batch in complex_expressions.chunks(*BATCH_SIZE) {
        let futures: Vec<_> = batch
            .iter()
            .map(|&expr| {
                let expr = expr.to_string();
                task::spawn_blocking(move || {
                    // These expressions use only literals, so no parameters needed
                    let param_list: Vec<ProgramParameter> = vec![];

                    match ClvmZkProver::prove(&expr, &param_list) {
                        Ok(result) => {
                            let output = result.proof_output.clvm_res;
                            let _proof = result.proof_bytes;
                            // Verify the proof
                            let program_hash =compile_chialisp_template_hash_default(&expr)
                                .map_err(|e| format!("Hash template failed: {:?}", e))?;
                            let (verified, _) = ClvmZkProver::verify_proof(program_hash, &_proof, Some(&output.output))
                                .map_err(|e| format!("Verification error: {e}"))?;

                            if !verified {
                                return Err(format!(
                                    "Valid proof should verify for complex expression: {expr}"
                                ));
                            }
                            // Check output is reasonable
                            if output.output.is_empty() {
                                return Err("Output should not be empty".to_string());
                            }
                            if output.output.len() > 8 {
                                return Err("Output should be reasonable size".to_string());
                            }
                            test_info!("  Success: {expr} -> {output:?}");
                            Ok(())
                        }
                        Err(e) => {
                            Err(format!(
                                "Complex expression '{expr}' should have produced a proof, but failed: {e}"
                            ))
                        }
                    }
                })
            })
            .collect();

        // Wait for current batch to complete
        for future in futures {
            match future.await.map_err(|e| format!("Task failed: {e}"))? {
                Ok(_) => completed_count += 1,
                Err(e) => return Err(e),
            }
        }
    }

    test_info!(
        "Complex nested expressions: tested {} expressions successfully",
        completed_count
    );
    if completed_count != total_cases {
        return Err(format!(
            "All test cases should complete: got {} expected {}",
            completed_count, total_cases
        ));
    }
    Ok(())
}
