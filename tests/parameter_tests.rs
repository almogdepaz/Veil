use clvm_zk::{ClvmZkProver, ProgramParameter};
mod common;
use clvm_zk_core::chialisp::compile_chialisp_template_hash_default;

/// Test unified API with mixed byte and integer parameters
#[test]
fn fuzz_mixed_parameters() -> Result<(), Box<dyn std::error::Error>> {
    test_info!("Testing unified API with mixed byte and integer parameters");

    let test_cases = [
        // Test 1: Pure integers (equivalent to old API)
        (
            "pure_integers",
            "(mod (a b) (+ a b))",
            vec![ProgramParameter::int(5), ProgramParameter::int(7)],
            12i64, // Expected result: 5 + 7 = 12
        ),
        // Test 2: Pure bytes for arithmetic (should work with small bytes)
        (
            "pure_bytes_arithmetic",
            "(mod (a b) (+ a b))",
            vec![
                ProgramParameter::from_bytes(&[10]), // 10 as single byte
                ProgramParameter::from_bytes(&[20]), // 20 as single byte
            ],
            30i64, // Expected result: 10 + 20 = 30
        ),
        // Test 3: Mixed parameters - integer comparison with byte data
        (
            "mixed_comparison",
            "(mod (a) (> a 50))",
            vec![
                ProgramParameter::int(80), // Integer for comparison (< 128 for single-byte)
            ],
            1i64, // Expected result: 80 > 50 = true (1)
        ),
        // Test 4: Conditional with mixed types
        (
            "mixed_conditional",
            "(mod (a b c) (i (> a 50) b c))",
            vec![
                ProgramParameter::int(75),           // Condition: 75 > 50 = true
                ProgramParameter::from_bytes(&[42]), // Then value: 42 as bytes
                ProgramParameter::int(99),           // Else value: 99 as int
            ],
            42i64, // Expected result: since 75 > 50, return 42
        ),
        // Test 5: Arithmetic with mixed integer and byte (result < 128 for single-byte encoding)
        (
            "mixed_arithmetic",
            "(mod (a b) (+ a b))",
            vec![
                ProgramParameter::int(60),           // Integer
                ProgramParameter::from_bytes(&[39]), // Byte representation of 39
            ],
            99i64, // Expected result: 60 + 39 = 99 (0x63 < 0x80, single-byte encoding)
        ),
    ];

    for (test_name, expression, params, expected) in &test_cases {
        test_info!("Testing: {test_name} - {expression}");

        let proof_result = ClvmZkProver::prove(expression, params)
            .map_err(|e| format!("Proof generation failed for {test_name}: {e}"))?;
        let output = proof_result.output.clvm_res;
        let proof = proof_result.proof;

        test_info!("  Proof generated: {} bytes", proof.len());

        // Verify the proof
        let (verified, _) = ClvmZkProver::verify_proof(
            compile_chialisp_template_hash_default(&expression).unwrap(),
            &proof,
            Some(&output.output),
        )
        .map_err(|e| format!("Verification error for {test_name}: {e}"))?;

        if !verified {
            return Err(format!("Proof verification failed for {test_name}").into());
        }

        test_info!("  Proof verified successfully");

        // Validate result (all test cases must have expected values and single-byte outputs)
        if output.output.len() != 1 {
            return Err(format!(
                "Test {test_name}: expected single-byte output, got {} bytes: {output:?}",
                output.output.len()
            )
            .into());
        }

        let actual_val = output.output[0] as i64;
        if actual_val != *expected {
            return Err(format!("Test {test_name}: expected {expected}, got {actual_val}").into());
        }

        test_info!("  ✓ Result matches expected: {expected}");
    }

    test_info!(
        "Mixed parameters fuzz: All {} test cases completed successfully",
        test_cases.len()
    );
    Ok(())
}
