//! Security tests for verification vulnerabilities
//!
//! These tests ensure that critical security bugs don't regress,
//! particularly the program hash and output validation issues
//! that were accidentally removed during the backend refactor.
use clvm_zk::{ClvmZkProver, ProgramParameter};
use clvm_zk_core::chialisp::compile_chialisp_template_hash_default;

#[cfg(test)]
mod verification_security_tests {
    use super::*;

    /// Test that proofs cannot be reused with wrong expected outputs
    /// This tests the critical security fix where verification was ignoring public outputs
    #[test]
    fn test_proof_reuse_with_wrong_outputs_rejected() -> Result<(), String> {
        println!("Testing proof reuse with wrong outputs is properly rejected...");

        // Generate a valid proof for expression A with parameters
        let expr_a = "(mod (a b) (+ a b))";
        let params_a = vec![ProgramParameter::int(10), ProgramParameter::int(20)];
        let proof_result_a = ClvmZkProver::prove(expr_a, &params_a)
            .map_err(|e| format!("Failed to generate proof A: {e}"))?;

        let correct_output = proof_result_a.result;
        let proof = proof_result_a.proof;
        // 1. Verify with correct output (should succeed)
        let (valid_result, _) = ClvmZkProver::verify_proof(
            compile_chialisp_template_hash_default(expr_a)
                .map_err(|e| format!("Hash template failed: {:?}", e))?,
            &proof,
            Some(&correct_output),
        )
        .map_err(|e| format!("Verification with correct output failed: {e}"))?;
        if !valid_result {
            return Err("Valid proof with correct output should verify successfully".to_string());
        }
        println!("✓ Valid proof with correct output verified successfully");

        // 2. Try to reuse proof with completely different output (should fail)
        let wrong_output = b"totally_different_output".to_vec();
        let (invalid_result, _) = ClvmZkProver::verify_proof(
            compile_chialisp_template_hash_default(expr_a)
                .map_err(|e| format!("Hash template failed: {:?}", e))?,
            &proof,
            Some(&wrong_output),
        )
        .map_err(|e| format!("Verification with wrong output failed: {e}"))?;
        if invalid_result {
            return Err(
                "SECURITY VULNERABILITY: Proof was accepted with wrong output!".to_string(),
            );
        }
        println!("✓ Proof correctly rejected with wrong output");

        // 3. Try to reuse proof with output from different computation (should fail)
        let expr_b = "(mod (a b) (+ a b))"; // same template but different parameters
        let params_b = vec![ProgramParameter::int(5), ProgramParameter::int(7)];
        let proof_result_b = ClvmZkProver::prove(expr_b, &params_b)
            .map_err(|e| format!("Failed to generate proof B: {e}"))?;
        let output_b = proof_result_b.result;

        // Try to use proof_a with output_b
        let (cross_result, _) = ClvmZkProver::verify_proof(
            compile_chialisp_template_hash_default(expr_a)
                .map_err(|e| format!("Hash template failed: {:?}", e))?,
            &proof,
            Some(&output_b),
        )
        .map_err(|e| format!("Cross-verification failed: {e}"))?;
        if cross_result {
            return Err("SECURITY VULNERABILITY: Proof was accepted with output from different computation!".to_string());
        }
        println!("✓ Proof correctly rejected with output from different computation");

        Ok(())
    }

    /// Test that proofs cannot be reused with wrong program hashes
    /// This tests the critical security fix where verification was ignoring program hashes
    #[test]
    fn test_proof_reuse_with_wrong_programs_rejected() -> Result<(), String> {
        println!("Testing proof reuse with wrong programs is properly rejected...");

        // Generate proofs for two different programs
        let expr_a = "(mod (a b) (+ a b))";
        let params_a = &[ProgramParameter::int(10), ProgramParameter::int(20)];
        let proof_result_a = ClvmZkProver::prove(expr_a, params_a)
            .map_err(|e| format!("Failed to generate proof A: {e}"))?;

        let expr_b = "(mod (a b) (* a b))"; // different program
        let params_b = &[ProgramParameter::int(10), ProgramParameter::int(20)];
        let proof_result_b = ClvmZkProver::prove(expr_b, params_b)
            .map_err(|e| format!("Failed to generate proof B: {e}"))?;

        // 1. Verify each proof with its correct program (should succeed)
        let (valid_a, _) = ClvmZkProver::verify_proof(
            compile_chialisp_template_hash_default(expr_a)
                .map_err(|e| format!("Hash template A failed: {:?}", e))?,
            &proof_result_a.proof,
            Some(&proof_result_a.result),
        )
        .map_err(|e| format!("Verification A failed: {e}"))?;
        let (valid_b, _) = ClvmZkProver::verify_proof(
            compile_chialisp_template_hash_default(expr_b)
                .map_err(|e| format!("Hash template B failed: {:?}", e))?,
            &proof_result_b.proof,
            Some(&proof_result_b.result),
        )
        .map_err(|e| format!("Verification B failed: {e}"))?;

        if !valid_a || !valid_b {
            return Err(
                "Valid proofs with correct programs should verify successfully".to_string(),
            );
        }
        println!("✓ Valid proofs with correct programs verified successfully");

        // 2. Try to use proof_a with program_b (should fail due to program hash mismatch)
        let (cross_result_1, _) = ClvmZkProver::verify_proof(
            compile_chialisp_template_hash_default(expr_b)
                .map_err(|e| format!("Hash template B failed: {:?}", e))?,
            &proof_result_a.proof,
            Some(&proof_result_a.result),
        )
        .map_err(|e| format!("Cross-verification 1 failed: {e}"))?;
        if cross_result_1 {
            return Err("SECURITY VULNERABILITY: Proof A was accepted with Program B!".to_string());
        }
        println!("✓ Proof A correctly rejected with Program B");

        // 3. Try to use proof_b with program_a (should fail due to program hash mismatch)
        let (cross_result_2, _) = ClvmZkProver::verify_proof(
            compile_chialisp_template_hash_default(expr_a)
                .map_err(|e| format!("Hash template A failed: {:?}", e))?,
            &proof_result_b.proof,
            Some(&proof_result_b.result),
        )
        .map_err(|e| format!("Cross-verification 2 failed: {e}"))?;
        if cross_result_2 {
            return Err("SECURITY VULNERABILITY: Proof B was accepted with Program A!".to_string());
        }
        println!("✓ Proof B correctly rejected with Program A");

        Ok(())
    }

    /// Test edge cases that could bypass validation
    #[test]
    fn test_verification_edge_cases() -> Result<(), String> {
        println!("Testing verification edge cases...");

        let expr = "(mod (a b) (create_coin a b))";
        let params = vec![ProgramParameter::int(1000), ProgramParameter::int(500)];
        let proof_result = ClvmZkProver::prove(expr, &params)
            .map_err(|e| format!("Failed to generate proof: {e}"))?;

        // Test with empty output
        let (empty_result, _) = ClvmZkProver::verify_proof(
            compile_chialisp_template_hash_default(expr)
                .map_err(|e| format!("Hash template failed: {:?}", e))?,
            &proof_result.proof,
            Some(&vec![]),
        )
        .map_err(|e| format!("Empty output verification failed: {e}"))?;
        if empty_result {
            return Err("SECURITY ISSUE: Proof accepted with empty output".to_string());
        }
        println!("✓ Proof correctly rejected with empty output");

        // Test with truncated output
        let truncated_output = if proof_result.result.len() > 1 {
            proof_result.result[..proof_result.result.len() - 1].to_vec()
        } else {
            vec![]
        };
        let (truncated_result, _) = ClvmZkProver::verify_proof(
            compile_chialisp_template_hash_default(expr)
                .map_err(|e| format!("Hash template failed: {:?}", e))?,
            &proof_result.proof,
            Some(&truncated_output),
        )
        .map_err(|e| format!("Truncated output verification failed: {e}"))?;
        if truncated_result {
            return Err("SECURITY ISSUE: Proof accepted with truncated output".to_string());
        }
        println!("✓ Proof correctly rejected with truncated output");

        // Test with extended output
        let mut extended_output = proof_result.result.clone();
        extended_output.push(0xFF);
        let (extended_result, _) = ClvmZkProver::verify_proof(
            compile_chialisp_template_hash_default(expr)
                .map_err(|e| format!("Hash template failed: {:?}", e))?,
            &proof_result.proof,
            Some(&extended_output),
        )
        .map_err(|e| format!("Extended output verification failed: {e}"))?;
        if extended_result {
            return Err("SECURITY ISSUE: Proof accepted with extended output".to_string());
        }
        println!("✓ Proof correctly rejected with extended output");

        Ok(())
    }
}
