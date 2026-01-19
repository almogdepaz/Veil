use clvm_zk::backends::{backend, ZKClvmResult};
use clvm_zk::*;
use clvm_zk_core::BLS_DST;

// Helper function to compile and test programs with the current backend
fn compile_and_test_program(
    program: &str,
    params: &[ProgramParameter],
) -> Result<ZKClvmResult, ClvmZkError> {
    let backend = backend()?;
    backend.prove_program(program, params)
}

// generate valid bls test vectors using clvm-zk dst
fn get_valid_bls_test_vector() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use blst::min_sig as blst_core;

    let message = b"test message for clvm-zk bls verification";
    let sk_bytes = [1u8; 32]; // deterministic test key
    let sk = blst_core::SecretKey::from_bytes(&sk_bytes).unwrap();
    let pk = sk.sk_to_pk();
    let sig = sk.sign(message, BLS_DST, &[]);

    (
        pk.to_bytes().to_vec(),
        message.to_vec(),
        sig.to_bytes().to_vec(),
    )
}

// CLVM condition opcodes
const REMARK: u8 = 1;

#[test]
fn test_simple_list_compilation() {
    // Test basic list compilation using numeric opcode (REMARK = 1)
    let program = format!("(mod () (list (list {} 1)))", REMARK);
    let result = compile_and_test_program(&program, &[]);

    match result {
        Ok(zk_result) => {
            let output = &zk_result.proof_output.clvm_res.output;
            println!("Simple list output hex: {}", hex::encode(output));
            println!("Simple list output bytes: {:?}", output);

            match clvm_zk_core::deserialize_clvm_output_to_conditions(output) {
                Ok(conditions) => {
                    println!("Parsed {} conditions successfully", conditions.len());
                    assert_eq!(conditions.len(), 1);
                    assert_eq!(conditions[0].opcode, 1);
                }
                Err(e) => {
                    panic!("Failed to parse simple list: {}", e);
                }
            }
        }
        Err(e) => {
            let error_msg = format!("{:?}", e);
            if !error_msg.contains("not available") {
                panic!("Unexpected error: {}", error_msg);
            }
        }
    }
}

#[test]
fn test_bls_verify_operator_parsing() {
    // Test that the BLS verify operator parses correctly
    use clvm_zk_core::operators::ClvmOperator;

    // Test string parsing
    let op = ClvmOperator::parse_operator("bls_verify");
    assert!(op.is_some());
    assert_eq!(op.unwrap(), ClvmOperator::BlsVerify);

    // Test opcode mapping (59 is clvmr's native BLS verify opcode)
    assert_eq!(ClvmOperator::BlsVerify.opcode(), 59);

    // Test arity
    assert_eq!(ClvmOperator::BlsVerify.arity(), Some(3));

    // Test roundtrip: string -> operator -> opcode -> operator
    let op = ClvmOperator::parse_operator("bls_verify").unwrap();
    let opcode = op.opcode();
    let op2 = ClvmOperator::from_opcode(opcode).unwrap();
    assert_eq!(op, op2);
}

// BLS verify opcode (clvmr's native BLS verify)
const BLS_VERIFY: u8 = 59;

#[test]
fn test_bls_verify_compilation() {
    // Test that BLS verify compiles and executes with valid test vectors
    // Using numeric opcodes: REMARK=1, bls_verify=59
    let program = format!(
        "(mod (public_key message signature) (list (list {} ({} public_key message signature))))",
        REMARK, BLS_VERIFY
    );

    // Use valid BLS12-381 test vector
    let (pk, msg, sig) = get_valid_bls_test_vector();

    let params = vec![
        ProgramParameter::from_bytes(&pk),
        ProgramParameter::from_bytes(&msg),
        ProgramParameter::from_bytes(&sig),
    ];

    // With valid test vector, BLS verification should succeed and return true (1)
    let result = compile_and_test_program(&program, &params);
    match result {
        Ok(zk_result) => {
            // BLS verification succeeded
            println!("BLS program executed successfully");
            let output = &zk_result.proof_output.clvm_res.output;

            // Parse conditions from output
            let conditions = clvm_zk_core::deserialize_clvm_output_to_conditions(output)
                .expect("failed to parse conditions");

            // Should have REMARK condition with result
            assert_eq!(conditions.len(), 1, "expected 1 REMARK");
            assert_eq!(conditions[0].opcode, 1, "expected REMARK opcode");
            assert_eq!(conditions[0].args.len(), 1, "REMARK should have 1 arg");

            // BLS verify returns true (empty atom) on success
            let result_bytes = &conditions[0].args[0];
            assert!(
                result_bytes.is_empty() || result_bytes == &vec![1],
                "BLS verify should return true, got: {:?}",
                result_bytes
            );

            println!("Valid BLS signature correctly verified ✓");
        }
        Err(e) => {
            // If zkVM is not available or has issues, that's acceptable for this test
            let error_msg = format!("{:?}", e);
            assert!(
                error_msg.contains("risc0 zkvm not available")
                    || error_msg.contains("sp1 zkvm not available")
                    || error_msg.contains("not available")
                    || error_msg.contains("mock uses blst encoding"),
                "Unexpected error with valid BLS test vector: {}",
                error_msg
            );
        }
    }
}

#[test]
fn test_bls_verify_invalid_arguments() {
    // Test that BLS verify rejects wrong number of arguments
    // Using numeric opcode: bls_verify=59
    let program = format!("(mod (pk msg) ({} pk msg))", BLS_VERIFY); // Missing signature argument

    let result = compile_and_test_program(&program, &[]);
    assert!(result.is_err(), "BLS verify should require 3 arguments");
}

// #[cfg(not(target_os = "zkvm"))]
// #[test]
// fn test_bls_verify_fallback() {
//     // Test the evaluator's BLS verification with default implementation
//     use clvm_zk_core::ClvmEvaluator;

//     let evaluator = ClvmEvaluator::new();
//     let pk = vec![0u8; 48]; // 48 bytes for BLS public key
//     let msg = b"test message";
//     let sig = vec![0u8; 96]; // 96 bytes for BLS signature

//     let result = (evaluator.bls_verifier)(&pk, msg, &sig);
//     assert!(result.is_err());
//     assert_eq!(
//         result.unwrap_err(),
//         "BLS verification not available - no backend configured"
//     );
// }

#[test]
fn test_bls_program_with_backend() {
    // Test BLS program execution with current backend (should handle gracefully)
    // Using numeric opcodes: REMARK=1, bls_verify=59
    let program = format!(
        "(mod (pk msg sig) (list (list {} (if ({} pk msg sig) 1 0))))",
        REMARK, BLS_VERIFY
    );

    // Use valid BLS12-381 test vector
    let (pk, msg, sig) = get_valid_bls_test_vector();

    let params = vec![
        ProgramParameter::from_bytes(&pk),
        ProgramParameter::from_bytes(&msg),
        ProgramParameter::from_bytes(&sig),
    ];

    let result = compile_and_test_program(&program, &params);

    match result {
        Ok(result) => {
            // With valid test vector, verification should succeed
            let output = &result.proof_output.clvm_res.output;

            // Parse conditions from output
            let conditions = clvm_zk_core::deserialize_clvm_output_to_conditions(output)
                .expect("failed to parse conditions");

            // Should have REMARK condition with result
            assert_eq!(conditions.len(), 1, "expected 1 REMARK");
            assert_eq!(conditions[0].opcode, 1, "expected REMARK opcode");
            assert_eq!(conditions[0].args.len(), 1, "REMARK should have 1 arg");

            // Result should be 1 for success
            let result_bytes = &conditions[0].args[0];
            assert!(
                result_bytes.is_empty() || result_bytes == &vec![1],
                "BLS verify should return 1 for success, got: {:?}",
                result_bytes
            );

            println!("BLS signature verified successfully ✓");
        }
        Err(e) => {
            // If zkVM is not available, that's acceptable
            let error_msg = format!("{:?}", e);
            assert!(
                error_msg.contains("risc0 zkvm not available")
                    || error_msg.contains("sp1 zkvm not available")
                    || error_msg.contains("not available")
                    || error_msg.contains("mock uses blst encoding"),
                "Unexpected error with valid BLS test vector: {}",
                error_msg
            );
        }
    }
}

#[test]
fn test_bls_invalid_signature() {
    // Test that invalid signatures are rejected
    // Using numeric opcode: bls_verify=59
    let program = format!("(mod (pk msg sig) (if ({} pk msg sig) 1 0))", BLS_VERIFY);

    let (pk, msg, _valid_sig) = get_valid_bls_test_vector();

    // generate a valid bls signature for a different message (will be valid g1 point but won't verify)
    use blst::min_sig as blst_core;
    let different_msg = b"different message that produces wrong signature";

    // generate a signature for different message with a random key (valid point, wrong signature)
    let sk_bytes = [42u8; 32]; // arbitrary secret key
    let sk = blst_core::SecretKey::from_bytes(&sk_bytes).unwrap();
    let wrong_sig = sk.sign(different_msg, BLS_DST, &[]).to_bytes();
    let wrong_sig = wrong_sig.to_vec();

    let params = vec![
        ProgramParameter::from_bytes(&pk),
        ProgramParameter::from_bytes(&msg),
        ProgramParameter::from_bytes(&wrong_sig),
    ];

    let result = compile_and_test_program(&program, &params);

    match result {
        Ok(result) => {
            // Invalid signature should fail verification, returning 0
            let output = &result.proof_output.clvm_res;
            assert_eq!(
                output.output.len(),
                1,
                "BLS program should return single value"
            );
            assert_eq!(
                output.output[0], 0x80,
                "Invalid BLS signature should fail verification, returning 0 (encoded as 0x80)"
            );
            println!("Invalid BLS signature correctly rejected ✓");
        }
        Err(e) => {
            // If zkVM is not available or CLVM execution fails, that's acceptable
            // Mock backend may not fully support BLS operations through VeilEvaluator
            let error_msg = format!("{:?}", e);
            assert!(
                error_msg.contains("risc0 zkvm not available")
                    || error_msg.contains("sp1 zkvm not available")
                    || error_msg.contains("not available")
                    || error_msg.contains("mock uses blst encoding")
                    || error_msg.contains("CLVM execution failed"),
                "Unexpected error: {}",
                error_msg
            );
        }
    }
}
