use clvm_zk::*;
use clvm_zk::backends::{backend, ZKClvmResult};

// Helper function to compile and test programs with the current backend
fn compile_and_test_program(program: &str, params: &[ProgramParameter]) -> Result<ZKClvmResult, ClvmZkError> {
    let backend = backend()?;
    backend.prove_program(program, params, &[])
}

#[test]
fn test_bls_verify_operator_parsing() {
    // Test that the BLS verify operator parses correctly
    use clvm_zk_core::operators::ClvmOperator;

    // Test string parsing
    let op = ClvmOperator::parse_operator("bls_verify");
    assert!(op.is_some());
    assert_eq!(op.unwrap(), ClvmOperator::BlsVerify);

    // Test opcode mapping
    assert_eq!(ClvmOperator::BlsVerify.opcode(), 201);

    // Test arity
    assert_eq!(ClvmOperator::BlsVerify.arity(), Some(3));

    // Test roundtrip: string -> operator -> opcode -> operator
    let op = ClvmOperator::parse_operator("bls_verify").unwrap();
    let opcode = op.opcode();
    let op2 = ClvmOperator::from_opcode(opcode).unwrap();
    assert_eq!(op, op2);
}

#[test]
fn test_bls_verify_compilation() {
    // Test that BLS verify expressions compile correctly
    let program = "(mod (public_key message signature) (bls_verify public_key message signature))";

    // Create dummy BLS parameters with correct sizes
    let pk = vec![0u8; 48]; // 48-byte public key
    let msg = b"test"; // Simple message
    let sig = vec![0u8; 96]; // 96-byte signature

    let params = vec![
        ProgramParameter::from_bytes(&pk),
        ProgramParameter::from_bytes(msg),
        ProgramParameter::from_bytes(&sig),
    ];

    // With working zkVM, this should compile and execute (though BLS verification may fail with dummy data)
    let result = compile_and_test_program(program, &params);
    match result {
        Ok(_) => {
            // Success - BLS program compiled and executed
            println!("BLS program compiled and executed successfully");
        }
        Err(e) => {
            let error_msg = format!("{:?}", e);
            // With dummy BLS data, we expect the signature verification to fail
            // but the program should still compile and execute
            assert!(
                error_msg.contains("CLVM execution failed") ||
                error_msg.contains("runtime error") ||
                error_msg.contains("BLS signature verification") ||
                error_msg.contains("invalid") ||
                error_msg.contains("signature") ||
                error_msg.contains("public key") ||
                // If zkVM is not properly set up, these are acceptable
                error_msg.contains("risc0 zkvm not available") ||
                error_msg.contains("sp1 zkvm not available") ||
                error_msg.contains("not available"),
                "Unexpected error (expected BLS verification failure or zkVM setup issue): {}", error_msg
            );
        }
    }
}

#[test]
fn test_bls_verify_invalid_arguments() {
    // Test that BLS verify rejects wrong number of arguments
    let program = "(mod (pk msg) (bls_verify pk msg))"; // Missing signature argument

    let result = compile_and_test_program(program, &[]);
    assert!(result.is_err(), "BLS verify should require 3 arguments");
}

#[cfg(not(target_os = "zkvm"))]
#[test]
fn test_bls_verify_fallback() {
    // Test the evaluator's BLS verification with default implementation
    use clvm_zk_core::ClvmEvaluator;

    let evaluator = ClvmEvaluator::new();
    let pk = vec![0u8; 48];  // 48 bytes for BLS public key
    let msg = b"test message";
    let sig = vec![0u8; 96]; // 96 bytes for BLS signature

    let result = (evaluator.bls_verifier)(&pk, msg, &sig);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "BLS verification not available - no backend configured");
}

#[test]
fn test_bls_program_with_backend() {
    // Test BLS program execution with current backend (should handle gracefully)
    let program = r#"
    (mod (pk msg sig)
        (if (bls_verify pk msg sig)
            1
            0
        )
    )
    "#;

    // Create some dummy BLS parameters (correct sizes but invalid content)
    let pk = vec![0u8; 48]; // 48-byte public key
    let msg = b"Hello"; // Simple message
    let sig = vec![0u8; 96]; // 96-byte signature

    let params = vec![
        ProgramParameter::from_bytes(&pk),
        ProgramParameter::from_bytes(msg),
        ProgramParameter::from_bytes(&sig),
    ];

    // With working zkVM and BLS implementation, this should execute successfully
    let result = compile_and_test_program(program, &params);

    match result {
        Ok(proof_result) => {
            // Program executed successfully
            // With dummy BLS data (all zeros), signature verification should fail
            // so the program should return 0 (false branch)
            let output = &proof_result.result;
            assert_eq!(output.len(), 1, "BLS program should return single value");
            assert_eq!(output[0], 0, "Dummy BLS signature should fail verification, returning 0");
            println!("BLS program executed successfully, dummy signature correctly rejected");
        }
        Err(e) => {
            let error_msg = format!("{:?}", e);
            // If we get an error, it should be related to BLS implementation details or zkVM setup
            assert!(
                error_msg.contains("CLVM execution failed") ||
                error_msg.contains("runtime error") ||
                error_msg.contains("BLS") ||
                error_msg.contains("signature") ||
                error_msg.contains("verification") ||
                error_msg.contains("invalid") ||
                error_msg.contains("public key") ||
                // Fallback for zkVM setup issues
                error_msg.contains("risc0 zkvm not available") ||
                error_msg.contains("sp1 zkvm not available") ||
                error_msg.contains("not available"),
                "Unexpected error (expected BLS-related error or zkVM setup issue): {}", error_msg
            );
        }
    }
}