/// Test CREATE_COIN transformation for output privacy
#[cfg(feature = "mock")]
use clvm_zk_core::{extract_coin_commitments, hash_data, ProgramParameter};

#[cfg(feature = "mock")]
use clvm_zk_mock::MockBackend;

#[test]
#[cfg(feature = "mock")]
fn test_create_coin_private_mode() {
    // Generate random serials for output coin
    let serial_number: [u8; 32] = rand::random();
    let serial_randomness: [u8; 32] = rand::random();

    // Recipient and amount
    let recipient_puzzle = [0x42u8; 32];
    let amount: u64 = 1000;

    // Chialisp program with 4-arg CREATE_COIN (private mode)
    let program = r#"
        (mod (recipient amount serial_num serial_rand)
            (list (list CREATE_COIN recipient amount serial_num serial_rand)))
    "#;

    // Parameters: recipient, amount, serial_number, serial_randomness
    let params = vec![
        ProgramParameter::Bytes(recipient_puzzle.to_vec()),
        ProgramParameter::Int(amount),
        ProgramParameter::Bytes(serial_number.to_vec()),
        ProgramParameter::Bytes(serial_randomness.to_vec()),
    ];

    // Generate proof
    let backend = MockBackend::new().expect("failed to create backend");
    let result = backend
        .prove_chialisp_program(program, &params)
        .expect("proof generation failed");

    // Extract coin commitments from proof output
    let commitments =
        extract_coin_commitments(&result.proof_output).expect("failed to extract commitments");

    // Should have exactly 1 commitment
    assert_eq!(commitments.len(), 1, "expected 1 coin commitment");

    // Verify commitment was computed correctly
    let expected_commitment = compute_coin_commitment(
        &recipient_puzzle,
        amount,
        &serial_number,
        &serial_randomness,
    );

    assert_eq!(commitments[0], expected_commitment, "commitment mismatch");

    println!("✓ CREATE_COIN private mode working");
    println!("  coin_commitment: {}", hex::encode(commitments[0]));
}

#[test]
#[cfg(feature = "mock")]
fn test_create_coin_multiple_outputs() {
    // Generate random serials for 2 output coins
    let serial1: [u8; 32] = rand::random();
    let serial_rand1: [u8; 32] = rand::random();
    let serial2: [u8; 32] = rand::random();
    let serial_rand2: [u8; 32] = rand::random();

    let recipient1 = [0x11u8; 32];
    let recipient2 = [0x22u8; 32];
    let amount1: u64 = 500;
    let amount2: u64 = 300;

    // Chialisp program creating 2 coins
    let program = r#"
        (mod (r1 a1 s1 sr1 r2 a2 s2 sr2)
            (list
                (list CREATE_COIN r1 a1 s1 sr1)
                (list CREATE_COIN r2 a2 s2 sr2)))
    "#;

    let params = vec![
        ProgramParameter::Bytes(recipient1.to_vec()),
        ProgramParameter::Int(amount1),
        ProgramParameter::Bytes(serial1.to_vec()),
        ProgramParameter::Bytes(serial_rand1.to_vec()),
        ProgramParameter::Bytes(recipient2.to_vec()),
        ProgramParameter::Int(amount2),
        ProgramParameter::Bytes(serial2.to_vec()),
        ProgramParameter::Bytes(serial_rand2.to_vec()),
    ];

    let backend = MockBackend::new().expect("failed to create backend");
    let result = backend
        .prove_chialisp_program(program, &params)
        .expect("proof generation failed");

    let commitments =
        extract_coin_commitments(&result.proof_output).expect("failed to extract commitments");

    // Should have exactly 2 commitments
    assert_eq!(commitments.len(), 2, "expected 2 coin commitments");

    // Verify both commitments
    let expected1 = compute_coin_commitment(&recipient1, amount1, &serial1, &serial_rand1);
    let expected2 = compute_coin_commitment(&recipient2, amount2, &serial2, &serial_rand2);

    assert_eq!(commitments[0], expected1, "commitment 1 mismatch");
    assert_eq!(commitments[1], expected2, "commitment 2 mismatch");

    println!("✓ CREATE_COIN multiple outputs working");
    println!("  commitment 1: {}", hex::encode(commitments[0]));
    println!("  commitment 2: {}", hex::encode(commitments[1]));
}

#[test]
#[cfg(feature = "mock")]
fn test_create_coin_transparent_mode() {
    // Test backward compatibility: 2-arg CREATE_COIN should pass through unchanged
    let recipient = [0x33u8; 32];
    let amount: u64 = 777;

    let program = r#"
        (mod (recipient amount)
            (list (list CREATE_COIN recipient amount)))
    "#;

    let params = vec![
        ProgramParameter::Bytes(recipient.to_vec()),
        ProgramParameter::Int(amount),
    ];

    let backend = MockBackend::new().expect("failed to create backend");
    let result = backend
        .prove_chialisp_program(program, &params)
        .expect("proof generation failed");

    // Parse output to verify 2-arg format preserved
    let conditions = deserialize_output_conditions(&result.proof_output.clvm_res.output)
        .expect("failed to parse conditions");

    assert_eq!(conditions.len(), 1, "expected 1 condition");
    assert_eq!(conditions[0].opcode, 51, "expected CREATE_COIN opcode");
    assert_eq!(
        conditions[0].args.len(),
        2,
        "expected 2 args (transparent mode)"
    );
    assert_eq!(&conditions[0].args[0], &recipient.to_vec());

    println!("✓ CREATE_COIN transparent mode (backward compatibility) working");
}

// Helper: compute coin_commitment v2 (with XCH tail_hash)
#[cfg(feature = "mock")]
fn compute_coin_commitment(
    puzzle_hash: &[u8; 32],
    amount: u64,
    serial_number: &[u8; 32],
    serial_randomness: &[u8; 32],
) -> [u8; 32] {
    use clvm_zk_core::coin_commitment::{build_coin_commitment_preimage, XCH_TAIL};

    // Compute serial_commitment
    let serial_domain = b"clvm_zk_serial_v1.0";
    let mut serial_data = [0u8; 83];
    serial_data[..19].copy_from_slice(serial_domain);
    serial_data[19..51].copy_from_slice(serial_number);
    serial_data[51..83].copy_from_slice(serial_randomness);
    let serial_commitment = hash_data(&serial_data);

    // Compute coin_commitment v2 using shared function
    let coin_data = build_coin_commitment_preimage(
        &XCH_TAIL, // XCH (native currency)
        amount,
        puzzle_hash,
        &serial_commitment,
    );
    hash_data(&coin_data)
}

// Helper: deserialize conditions for transparent mode test
#[cfg(feature = "mock")]
fn deserialize_output_conditions(
    output: &[u8],
) -> Result<Vec<clvm_zk_core::Condition>, &'static str> {
    use clvm_zk_core::{ClvmParser, ClvmValue, Condition};

    let mut parser = ClvmParser::new(output);
    let parsed = parser.parse()?;

    // Parse list of conditions
    let mut conditions = Vec::new();
    let mut current = &parsed;

    loop {
        match current {
            ClvmValue::Atom(ref bytes) if bytes.is_empty() => break,
            ClvmValue::Cons(ref first, ref rest) => {
                // Parse condition
                if let ClvmValue::Cons(ref opcode_val, ref args_val) = first.as_ref() {
                    let opcode = match opcode_val.as_ref() {
                        ClvmValue::Atom(ref bytes) if bytes.len() == 1 => bytes[0],
                        _ => return Err("invalid opcode"),
                    };

                    // Extract args
                    let mut args = Vec::new();
                    let mut arg_current = args_val.as_ref();
                    loop {
                        match arg_current {
                            ClvmValue::Atom(ref bytes) if bytes.is_empty() => break,
                            ClvmValue::Cons(ref arg_first, ref arg_rest) => {
                                if let ClvmValue::Atom(ref arg_bytes) = arg_first.as_ref() {
                                    args.push(arg_bytes.clone());
                                }
                                arg_current = arg_rest.as_ref();
                            }
                            _ => return Err("invalid args structure"),
                        }
                    }

                    conditions.push(Condition { opcode, args });
                }
                current = rest.as_ref();
            }
            _ => return Err("invalid list structure"),
        }
    }

    Ok(conditions)
}
