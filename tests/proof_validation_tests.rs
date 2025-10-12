use clvm_zk::{ClvmZkProver, ProgramParameter};
use tokio::task;
mod common;
use clvm_zk_core::chialisp::compile_chialisp_template_hash_default;

use common::BATCH_SIZE;

/// Test that proofs are actually different for different inputs
#[test]
fn test_proofs_differ_for_different_inputs() -> Result<(), Box<dyn std::error::Error>> {
    // Create two different programs

    // Generate proofs
    let proof_result1 = ClvmZkProver::prove(
        "(mod (a b) (+ a b))",
        &[ProgramParameter::int(2), ProgramParameter::int(3)],
    )
    .expect("Failed to generate proof 1");
    let output1 = proof_result1.result;
    let proof1 = proof_result1.proof;

    let proof_result2 = ClvmZkProver::prove(
        "(mod (a b) (+ a b))",
        &[ProgramParameter::int(5), ProgramParameter::int(7)],
    )
    .expect("Failed to generate proof 2");
    let output2 = proof_result2.result;
    let proof2 = proof_result2.proof;

    // Outputs should be different
    if output1 == output2 {
        return Err("Different programs should produce different outputs".into());
    }
    // Debug: print actual outputs
    println!("DEBUG: output1 = {:?}, expected = {:?}", output1, vec![5]);
    println!("DEBUG: output2 = {:?}, expected = {:?}", output2, vec![12]);

    // Test simple parameter access
    let test_a = ClvmZkProver::prove("(mod (a) a)", &[ProgramParameter::int(42)]).unwrap();
    println!("DEBUG: 'a' alone = {:?}, expected = [42]", test_a.result);

    let test_b = ClvmZkProver::prove(
        "(mod (a b) b)",
        &[ProgramParameter::int(10), ProgramParameter::int(20)],
    )
    .unwrap();
    println!(
        "DEBUG: 'b' with (a=10, b=20) = {:?}, expected = [20]",
        test_b.result
    );

    if output1 != vec![5] {
        return Err(format!("2 + 3 should equal 5, got {:?}", output1).into());
    }
    if output2 != vec![12] {
        return Err(format!("5 + 7 should equal 12, got {:?}", output2).into());
    }

    // Proofs should be different
    if proof1 == proof2 {
        return Err("Different programs should produce different proofs".into());
    }

    // Both proofs should be substantial in size (real ZK proofs are large)
    // Mock backend produces tiny fake proofs, so skip this check
    #[cfg(not(feature = "mock"))]
    {
        if proof1.len() <= 100000 {
            return Err(format!("Proof1 should be substantial size, got {}", proof1.len()).into());
        }
        if proof2.len() <= 100000 {
            return Err(format!("Proof2 should be substantial size, got {}", proof2.len()).into());
        }
    }

    Ok(())
}

/// Test that verification actually validates the proof against the correct program
#[test]
fn test_verification_rejects_wrong_program() -> Result<(), Box<dyn std::error::Error>> {
    // Generate proof for program1
    let proof_result1 = ClvmZkProver::prove(
        "(mod (a b) (+ a b))",
        &[ProgramParameter::int(5), ProgramParameter::int(3)],
    )?;
    let output1 = proof_result1.result;
    let proof1 = proof_result1.proof;

    // Verify proof1 against correct template (should succeed)
    let (result1, _) = ClvmZkProver::verify_proof(
        compile_chialisp_template_hash_default("(mod (a b) (+ a b))").unwrap(),
        &proof1,
        Some(&output1),
    )?;
    if !result1 {
        return Err("Proof1 should verify against correct template".into());
    }

    // Try to verify proof1 against wrong template (should fail)
    let result2 = ClvmZkProver::verify_proof(
        compile_chialisp_template_hash_default("(mod (a b) (* a b))").unwrap(),
        &proof1,
        Some(&output1),
    );

    // This should either fail to verify or return false
    match result2 {
        Ok((false, _)) => {
            // Verification returned false - this is correct behavior
            println!("Verification correctly rejected wrong program");
        }
        Err(_) => {
            // Verification failed with error - this is also acceptable
            println!("Verification correctly failed for wrong program");
        }
        Ok((true, _)) => {
            return Err(
                "Verification should not succeed when proof is for different program".into(),
            );
        }
    }

    Ok(())
}

/// Test that verification rejects tampered proofs
#[test]
fn test_verification_rejects_tampered_proof() -> Result<(), String> {
    let expression = "(mod (a b) (+ a b))";
    // Generate valid proof
    let proof_result = ClvmZkProver::prove(
        expression,
        &[ProgramParameter::int(5), ProgramParameter::int(3)],
    )
    .map_err(|e| format!("Failed to prove program: {e:?}"))?;
    let output = proof_result.result;
    let mut proof = proof_result.proof;

    // Verify original proof works
    let (result, _) = ClvmZkProver::verify_proof(
        compile_chialisp_template_hash_default(expression)
            .map_err(|e| format!("Failed to hash template: {e:?}"))?,
        &proof,
        Some(&output),
    )
    .map_err(|e| format!("Failed to verify original proof: {e:?}"))?;
    if !result {
        return Err("Original proof should verify but did not".into());
    }

    // Tamper with the proof by flipping a bit in the middle
    let tamper_index = proof.len() / 2;
    proof[tamper_index] ^= 0x01;

    // Verification should fail
    let result = ClvmZkProver::verify_proof(
        compile_chialisp_template_hash_default(expression)
            .map_err(|e| format!("Failed to hash template: {e:?}"))?,
        &proof,
        Some(&output),
    );

    match result {
        Ok((false, _)) => {
            println!("Verification correctly rejected tampered proof");
            Ok(())
        }
        Err(_) => {
            println!("Verification correctly failed for tampered proof");
            Ok(())
        }
        Ok((true, _)) => Err("Verification should not succeed for tampered proof".into()),
    }
}

// Note: Equality operator (=) is tested in fuzz_comparison_operations to avoid duplication

/// Test complex nested expressions (concurrent version)
#[tokio::test]
async fn test_complex_nested_expressions() -> Result<(), String> {
    // Test: (= (+ (* a b) (- c d)) 100)
    let test_cases = [
        // (a, b, c, d, expected_result)
        (10, 5, 75, 25, 1), // 10*5 + (75-25) = 50 + 50 = 100, so (= 100 100) = 1
        (10, 5, 76, 25, 0), // 10*5 + (76-25) = 50 + 51 = 101, so (= 101 100) = 0
        (2, 3, 100, 6, 1),  // 2*3 + (100-6) = 6 + 94 = 100, so (= 100 100) = 1
    ];

    let total_cases = test_cases.len();
    let mut completed_results = Vec::new();

    // Process test cases in batches to limit concurrency
    for (batch_num, batch) in test_cases.chunks(*BATCH_SIZE).enumerate() {
        test_info!(
            "Processing batch {}/{} ({} test cases)...",
            batch_num + 1,
            total_cases.div_ceil(*BATCH_SIZE),
            batch.len()
        );

        // Create futures for current batch
        let futures: Vec<_> = batch
                .iter()
                .map(|(a, b, c, d, expected)| {
                    let a = *a;
                    let b = *b;
                    let c = *c;
                    let d = *d;
                    let expected = *expected;
                    task::spawn_blocking(move || -> Result<(i64, i64, i64, i64, i64), String> {
                        let param_list: Vec<ProgramParameter> = [a, b, c, d, 100].iter().map(|&x| ProgramParameter::int(x)).collect();
                        let expression = "(mod (a b c d e) (= (+ (* a b) (- c d)) e))";  // Use variable 'e' for the target value 100 
                        // Generate proof
                        let proof_result = ClvmZkProver::prove(expression, &param_list)
                            .map_err(|e| format!("Failed to prove complex expression {a},{b},{c},{d}: {e}"))?;
                        let output = proof_result.result;

                        // Debug output
                        println!("DEBUG complex: params={:?}, output={:?}, expected={}", [a,b,c,d,100], output, expected);
                        let proof = proof_result.proof;

                        // Check output is correct
                        if output != vec![expected] {
                            return Err(format!(
                                "Complex expression with {a},{b},{c},{d} should return {expected}, got {output:?}"
                            ));
                        }

                        // Verify proof
                        let (verified, _) = ClvmZkProver::verify_proof(
                          compile_chialisp_template_hash_default(expression).map_err(|e| format!("Failed to hash template: {:?}", e))?,
                            &proof,
                            Some(&output)
                        ).map_err(|e| format!("Failed to verify complex proof {a},{b},{c},{d}: {e}"))?;
                        if !verified {
                            return Err(format!("Complex proof should verify for {a},{b},{c},{d}"));
                        }

                        // Ensure proof is substantial
                        // Mock backend produces tiny fake proofs, so skip this check
                        #[cfg(not(feature = "mock"))]
                        {
                            if proof.len() <= 100000 {
                                return Err(format!(
                                    "Complex proof should be substantial size, got {}",
                                    proof.len()
                                ));
                            }
                        }

                        Ok((a, b, c, d, expected as i64))
                    })
                })
                .collect();

        // Wait for current batch to complete
        for future in futures {
            match future.await.map_err(|e| format!("Task join error: {e}"))? {
                Ok(result) => completed_results.push(result),
                Err(error) => {
                    return Err(error);
                }
            }
        }
        test_info!(
            "Batch {} completed: {}/{} total cases done",
            batch_num + 1,
            completed_results.len(),
            total_cases
        );
    }

    test_info!(
        "Complex nested expressions: tested {} operations in batches of {}",
        completed_results.len(),
        *BATCH_SIZE
    );
    if completed_results.len() != total_cases {
        return Err(format!(
            "All test cases should complete: got {} expected {}",
            completed_results.len(),
            total_cases
        ));
    }
    Ok(())
}

/// Test arithmetic operations not covered in fuzz tests (/, %, <)
#[tokio::test]
async fn test_arithmetic_operations() -> Result<(), String> {
    let test_cases = vec![
        ("/", 15, 3, 5),
        ("%", 15, 7, 1),
        ("/", 20, 4, 5),
        ("%", 10, 3, 1),
        ("<", 5, 10, 1),
        ("<", 10, 5, 0),
    ];

    let total_cases = test_cases.len();
    let mut completed_results = Vec::new();

    for (batch_num, batch) in test_cases.chunks(*BATCH_SIZE).enumerate() {
        test_info!(
            "Processing batch {}/{} ({} test cases)...",
            batch_num + 1,
            total_cases.div_ceil(*BATCH_SIZE),
            batch.len()
        );

        let futures: Vec<_> = batch
            .iter()
            .map(|(op, a, b, expected)| {
                let op: &str = op;
                let a: i64 = *a;
                let b = *b;
                let expected = *expected;
                task::spawn_blocking(move || -> Result<(char, i64, i64, i64), String> {
                    let expression = format!("(mod (a b) ({op} a b))");
                    let param_list: Vec<ProgramParameter> =
                        [a, b].iter().map(|&x| ProgramParameter::int(x)).collect();

                    let proof_result = ClvmZkProver::prove(&expression, &param_list)
                        .map_err(|e| format!("Failed to prove {op} operation: {e:?}"))?;
                    let output = proof_result.result;
                    let proof = proof_result.proof;

                    if output != vec![expected as u8] {
                        return Err(format!(
                            "Operation {op} {a} {b} should return {expected}, got {output:?}"
                        ));
                    }

                    let (verified, _) = ClvmZkProver::verify_proof(
                        compile_chialisp_template_hash_default(&expression)
                            .map_err(|e| format!("Failed to hash template: {:?}", e))?,
                        &proof,
                        Some(&output),
                    )
                    .map_err(|e| format!("Failed to verify {op} proof: {e:?}"))?;

                    if !verified {
                        return Err(format!("Arithmetic proof should verify for {op} {a} {b}"));
                    }

                    Ok((op.chars().next().unwrap(), a, b, expected))
                })
            })
            .collect();

        for future in futures {
            completed_results.push(future.await.map_err(|e| e.to_string())??);
            // The double `?` unwraps the JoinError and the Result inside
        }

        test_info!(
            "Batch {} completed: {}/{} total cases done",
            batch_num + 1,
            completed_results.len(),
            total_cases
        );
    }

    test_info!(
        "Arithmetic operations: tested {} operations in batches of {}",
        completed_results.len(),
        *BATCH_SIZE
    );

    if completed_results.len() != total_cases {
        return Err(format!(
            "All test cases should complete: got {} expected {}",
            completed_results.len(),
            total_cases
        ));
    }

    Ok(())
}

/// Test modular exponentiation operator (concurrent version)
#[tokio::test]
async fn test_modpow_operator() -> Result<(), String> {
    let test_cases = [(2, 3, 5, 3), (3, 4, 7, 4), (5, 2, 3, 1), (2, 10, 1000, 24)];

    let total_cases = test_cases.len();
    let mut completed_results = Vec::new();

    for (batch_num, batch) in test_cases.chunks(*BATCH_SIZE).enumerate() {
        test_info!(
            "Processing batch {}/{} ({} test cases)...",
            batch_num + 1,
            total_cases.div_ceil(*BATCH_SIZE),
            batch.len()
        );

        let futures: Vec<_> = batch
            .iter()
            .map(|(base, exponent, modulus, expected)| {
                let base = *base;
                let exponent = *exponent;
                let modulus = *modulus;
                let expected = *expected;
                task::spawn_blocking(move || -> Result<_, String> {
                    let expression = "(mod (a b c) (modpow a b c))".to_string();
                    let param_list: Vec<ProgramParameter> =
                        [base, exponent, modulus].iter().map(|&x| ProgramParameter::int(x)).collect();

                    let proof_result =
                        ClvmZkProver::prove(&expression, &param_list)
                            .map_err(|e| format!("Failed to prove modpow operation: {e:?}"))?;
                    let output = proof_result.result;

                    // Debug output
                    println!("DEBUG modpow: {}^{} mod {} = {}, output={:?}", base, exponent, modulus, expected, output);
                    let proof = proof_result.proof;

                    if output != vec![expected as u8] {
                        return Err(format!(
                            "Operation modpow {base} {exponent} {modulus} should return {expected}, got {output:?}"
                        ));
                    }

                    let (verified, _) = ClvmZkProver::verify_proof(
                      compile_chialisp_template_hash_default(&expression).map_err(|e| format!("Failed to hash template: {:?}", e))?,
                        &proof,
                        Some(&output)
                    ).map_err(|e| format!("Failed to verify modpow proof: {e:?}"))?;

                    if !verified {
                        return Err(format!(
                            "Modpow proof should verify for {base}^{exponent} mod {modulus}"
                        ));
                    }

                    Ok((base, exponent, modulus, expected))
                })
            })
            .collect();

        for future in futures {
            completed_results.push(future.await.map_err(|e| e.to_string())??);
        }

        test_info!(
            "Batch {} completed: {}/{} total cases done",
            batch_num + 1,
            completed_results.len(),
            total_cases
        );
    }

    test_info!(
        "Modpow operations: tested {} operations in batches of {}",
        completed_results.len(),
        *BATCH_SIZE
    );

    if completed_results.len() != total_cases {
        return Err(format!(
            "All test cases should complete: got {} expected {}",
            completed_results.len(),
            total_cases
        ));
    }

    Ok(())
}

#[tokio::test]
async fn test_list_operators() -> Result<(), String> {
    let test_operations = vec![
        (
            "c",
            "(mod (a b) (c a b))",
            vec![3, 4],
            vec![0xFF, 3, 4],
            "c operator should return cons pair (3 . 4)",
        ),
        (
            "f",
            "(mod (a b) (f (c a b)))",
            vec![7, 8],
            vec![7],
            "f operator should return first element of cons pair",
        ),
        (
            "r",
            "(mod (a b) (r (c a b)))",
            vec![7, 8],
            vec![8],
            "r operator should return rest element of cons pair",
        ),
        (
            "l_cons",
            "(mod (a b) (l (c a b)))",
            vec![3, 4],
            vec![1],
            "l operator should return 1 for cons pairs",
        ),
        (
            "l_atom",
            "(mod (a) (l a))",
            vec![5],
            vec![0x80], // l operator returns 0x80 (nil) for atoms according to CLVM spec
            "l operator should return nil (0x80) for atoms",
        ),
    ];

    let total_cases = test_operations.len();
    let mut completed_results = Vec::new();

    for (batch_num, batch) in test_operations.chunks(*BATCH_SIZE).enumerate() {
        test_info!(
            "Processing batch {}/{} ({} test cases)...",
            batch_num + 1,
            total_cases.div_ceil(*BATCH_SIZE),
            batch.len()
        );

        let futures: Vec<_> = batch
            .iter()
            .map(|(op_name, expr, vars, expected_output, description)| {
                let op_name = *op_name;
                let expr = *expr;
                let vars = vars.clone();
                let expected_output = expected_output.clone();
                let description = *description;

                task::spawn_blocking(move || -> Result<_, String> {
                    let param_list: Vec<ProgramParameter> =
                        vars.iter().map(|&x| ProgramParameter::int(x)).collect();

                    let proof_result = ClvmZkProver::prove(expr, &param_list)
                        .map_err(|e| format!("Failed to prove {op_name} operation: {e:?}"))?;
                    let output = proof_result.result;
                    if output != expected_output {
                        return Err(format!(
                            "{description} - expected {expected_output:?}, got {output:?}"
                        ));
                    }

                    Ok((op_name, expr, expected_output))
                })
            })
            .collect();

        for future in futures {
            completed_results.push(future.await.map_err(|e| e.to_string())??);
        }

        test_info!(
            "Batch {} completed: {}/{} total cases done",
            batch_num + 1,
            completed_results.len(),
            total_cases
        );
    }

    test_info!(
        "List operations: tested {} operations in batches of {}",
        completed_results.len(),
        *BATCH_SIZE
    );

    if completed_results.len() != total_cases {
        return Err(format!(
            "All test cases should complete: got {} expected {}",
            completed_results.len(),
            total_cases
        ));
    }

    Ok(())
}

#[tokio::test]
async fn test_divmod_operator() -> Result<(), String> {
    let test_cases = [(15, 4, 3, 3), (20, 6, 3, 2), (7, 2, 3, 1), (100, 7, 14, 2)];

    let total_cases = test_cases.len();
    let mut completed_results = Vec::new();

    for (batch_num, batch) in test_cases.chunks(*BATCH_SIZE).enumerate() {
        test_info!(
            "Processing batch {}/{} ({} test cases)...",
            batch_num + 1,
            total_cases.div_ceil(*BATCH_SIZE),
            batch.len()
        );

        let futures: Vec<_> = batch
            .iter()
            .map(|(dividend, divisor, expected_quot, expected_rem)| {
                let dividend = *dividend;
                let divisor = *divisor;
                let expected_quot = *expected_quot;
                let expected_rem = *expected_rem;

                task::spawn_blocking(move || -> Result<_, String> {
                    let param_list: Vec<ProgramParameter> =
                        [dividend, divisor].iter().map(|&x| ProgramParameter::int(x)).collect();
                    let expression = "(mod (a b) (divmod a b))".to_string();                   
                    let proof_result = ClvmZkProver::prove(&expression, &param_list)
                        .map_err(|e| format!("Failed to prove divmod operation: {e:?}"))?;
                    let output = proof_result.result;
                    let proof = proof_result.proof;

                    let expected_bytes = vec![0xFF, expected_quot as u8, expected_rem as u8];

                    if output != expected_bytes {
                        return Err(format!(
                            "Operation divmod {dividend} {divisor} should return cons pair (quot={expected_quot}, rem={expected_rem}), got {output:?}"
                        ));
                    }

                    let (verified, _) = ClvmZkProver::verify_proof(
                      compile_chialisp_template_hash_default(&expression).map_err(|e| format!("Failed to hash template: {:?}", e))?,
                        &proof,
                        Some(&output)
                    ).map_err(|e| format!("Failed to verify divmod proof: {e:?}"))?;

                    if !verified {
                        return Err(format!(
                            "Divmod proof should verify for {dividend} ÷ {divisor}"
                        ));
                    }

                    Ok((dividend, divisor, expected_quot, expected_rem))
                })
            })
            .collect();

        for future in futures {
            completed_results.push(future.await.map_err(|e| e.to_string())??);
        }

        test_info!(
            "Batch {} completed: {}/{} total cases done",
            batch_num + 1,
            completed_results.len(),
            total_cases
        );
    }

    test_info!(
        "Divmod operations: tested {} operations in batches of {}",
        completed_results.len(),
        *BATCH_SIZE
    );

    if completed_results.len() != total_cases {
        return Err(format!(
            "All test cases should complete: got {} expected {}",
            completed_results.len(),
            total_cases
        ));
    }

    Ok(())
}

/// Test that the system rejects invalid expressions (concurrent version)
#[tokio::test]
async fn test_invalid_expression_rejection() -> Result<(), String> {
    let invalid_expressions = [
        "invalid syntax",
        "(unknown_operator 1 2)",
        "(+ 1)",        // Missing second argument
        "(+ 1 2 3)",    // Too many arguments
        "((+ 1 2)",     // Unbalanced parentheses
        "",             // Empty expression
        "(/ 5 0)",      // Division by zero
        "(% 5 0)",      // Modulo by zero
        "(divmod 5 0)", // Divmod by zero
    ];

    let total_cases = invalid_expressions.len();
    let mut completed_results = Vec::new();

    // Process test cases in batches to limit concurrency
    for (batch_num, batch) in invalid_expressions.chunks(*BATCH_SIZE).enumerate() {
        test_info!(
            "Processing batch {}/{} ({} test cases)...",
            batch_num + 1,
            total_cases.div_ceil(*BATCH_SIZE),
            batch.len()
        );

        // Create futures for current batch
        let futures: Vec<_> = batch
                .iter()
                .map(|expr| {
                    let expr = *expr;
                    task::spawn_blocking(move || -> Result<String, String> {
                        let param_list: Vec<ProgramParameter> = [1, 2]
                            .iter()
                            .map(|&x| ProgramParameter::int(x))
                            .collect();
                        let result =compile_chialisp_template_hash_default(expr);
                        match result {
                            Err(_) => {
                                // This is expected - invalid expressions should fail
                                test_info!("Correctly rejected invalid expression: {expr}");
                                Ok(expr.to_string())
                            }
                            Ok(_program) => {
                                // If program creation succeeded, proof generation should fail
                                let prove_result = ClvmZkProver::prove(expr, &param_list);
                                if prove_result.is_ok() {
                                    return Err(format!("Invalid expression '{expr}' should fail during proof generation"));
                                }
                                Ok(expr.to_string())
                            }
                        }
                    })
                })
                .collect();

        // Wait for current batch to complete
        for future in futures {
            let result = future.await.map_err(|e| format!("Task join error: {e}"))?;
            match result {
                Ok(expr_str) => completed_results.push(expr_str),
                Err(e) => return Err(e),
            }
        }
        test_info!(
            "Batch {} completed: {}/{} total cases done",
            batch_num + 1,
            completed_results.len(),
            total_cases
        );
    }

    test_info!(
        "Invalid expression rejection: tested {} operations in batches of {}",
        completed_results.len(),
        *BATCH_SIZE
    );
    if completed_results.len() != total_cases {
        return Err(format!(
            "All test cases should complete: got {} expected {}",
            completed_results.len(),
            total_cases
        ));
    }
    Ok(())
}

/// Test that outputs are deterministic (same input produces same output)
/// Note: ZK proofs themselves may contain randomness, but outputs should be deterministic
#[test]
fn test_output_determinism() -> Result<(), String> {
    let expr = "(mod (a b) (+ a b))";
    // Generate the same proof twice
    let proof_result1 = ClvmZkProver::prove(
        expr,
        &[ProgramParameter::int(42), ProgramParameter::int(13)],
    )
    .map_err(|e| format!("Failed to prove program first time: {e}"))?;
    let output1 = proof_result1.result;
    let proof1 = proof_result1.proof;
    let proof_result2 = ClvmZkProver::prove(
        expr,
        &[ProgramParameter::int(42), ProgramParameter::int(13)],
    )
    .map_err(|e| format!("Failed to prove program second time: {e}"))?;
    let output2 = proof_result2.result;
    let proof2 = proof_result2.proof;

    // Outputs should be identical (deterministic computation)
    if output1 != output2 {
        return Err("Deterministic programs should produce identical outputs".into());
    }

    // Both proofs should verify (even if they contain different randomness)
    let (verified1, _) = ClvmZkProver::verify_proof(
        compile_chialisp_template_hash_default(expr)
            .map_err(|e| format!("Failed to hash template: {:?}", e))?,
        &proof1,
        Some(&output1),
    )
    .map_err(|e| format!("Failed to verify first proof: {e}"))?;
    let (verified2, _) = ClvmZkProver::verify_proof(
        compile_chialisp_template_hash_default(expr)
            .map_err(|e| format!("Failed to hash template: {:?}", e))?,
        &proof2,
        Some(&output2),
    )
    .map_err(|e| format!("Failed to verify second proof: {e}"))?;

    if !verified1 {
        return Err("First proof should verify".into());
    }
    if !verified2 {
        return Err("Second proof should verify".into());
    }

    // Both proofs should be substantial size (real ZK proofs)
    // Mock backend produces tiny fake proofs, so skip this check
    #[cfg(not(feature = "mock"))]
    {
        if proof1.len() <= 100000 {
            return Err("First proof should be substantial size".into());
        }
        if proof2.len() <= 100000 {
            return Err("Second proof should be substantial size".into());
        }
    }
    Ok(())
}
