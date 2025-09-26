use clvm_zk::{ClvmZkProver, ProgramParameter};

#[test]
fn test_large_atom_operations() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing different opcodes with large atoms...");

    // Test CREATE_COIN with large atoms
    println!("\n1. Testing CREATE_COIN with 33-byte atoms:");
    let large_puzzle_hash = vec![0x01; 33];
    let large_amount = vec![0x02; 33];

    match ClvmZkProver::prove(
        "(create_coin a b)",
        &[
            ProgramParameter::from_bytes(&large_puzzle_hash),
            ProgramParameter::from_bytes(&large_amount),
        ],
    ) {
        Ok(proof_result) => println!(
            "   CREATE_COIN with large atoms: SUCCESS {:?}",
            proof_result.clvm_output.result
        ),
        Err(e) => println!("   CREATE_COIN with large atoms: FAILED {e}"),
    }

    // Test AGG_SIG_UNSAFE with large atoms
    println!("\n2. Testing AGG_SIG_UNSAFE with 33-byte atoms:");
    let large_pubkey = vec![0x03; 33];
    let large_message = vec![0x04; 33];
    let large_signature = vec![0x05; 33]; // Intentionally wrong size to see if we get that far

    match ClvmZkProver::prove(
        "(mod (a b c) (agg_sig_unsafe a b c))",
        &[
            ProgramParameter::from_bytes(&large_pubkey),
            ProgramParameter::from_bytes(&large_message),
            ProgramParameter::from_bytes(&large_signature),
        ],
    ) {
        Ok(proof_result) => println!(
            "   AGG_SIG_UNSAFE with large atoms: SUCCESS {:?}",
            proof_result.clvm_output.result
        ),
        Err(e) => {
            println!("   AGG_SIG_UNSAFE with large atoms: FAILED {e}");
            if e.to_string().contains("signature size") {
                println!("   Got to signature verification (parsing worked!)");
            } else if e.to_string().contains("unsupported or invalid") {
                println!("   Parsing failed (never got to verification)");
            }
        }
    }

    // Test with smaller atoms to see if it's an atom size issue
    println!("\n3. Testing AGG_SIG_UNSAFE with 8-byte atoms:");
    let small_pubkey = vec![0x06; 8];
    let small_message = vec![0x07; 8];
    let small_signature = vec![0x08; 8];

    match ClvmZkProver::prove(
        "(mod (a b c) (agg_sig_unsafe a b c))",
        &[
            ProgramParameter::from_bytes(&small_pubkey),
            ProgramParameter::from_bytes(&small_message),
            ProgramParameter::from_bytes(&small_signature),
        ],
    ) {
        Ok(proof_result) => println!(
            "   AGG_SIG_UNSAFE with small atoms: SUCCESS {:?}",
            proof_result.clvm_output.result
        ),
        Err(e) => {
            println!("   AGG_SIG_UNSAFE with small atoms: FAILED {e}");
            if e.to_string().contains("signature size") {
                println!("   Got to signature verification (parsing worked!)");
            } else if e.to_string().contains("unsupported or invalid") {
                println!("   Parsing failed (never got to verification)");
            }
        }
    }

    Ok(())
}
