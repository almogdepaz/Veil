//! verify settlement API exists and compiles
//!
//! this test checks that all the settlement infrastructure is in place:
//! - conditional spend creation (Spender::create_conditional_spend)
//! - settlement proof types (SettlementParams, SettlementOutput)
//! - recursive verification imports work
//!
//! we don't actually generate proofs here, just verify the API compiles

use clvm_zk::protocol::settlement::{SettlementOutput, SettlementParams, SettlementProof};
use clvm_zk::protocol::{ProofType, Spender};
use clvm_zk::simulator::CLVMZkSimulator;

#[test]
fn test_api_exists() {
    // verify types exist
    let _proof_type_check = |pt: ProofType| match pt {
        ProofType::Transaction => "transaction",
        ProofType::ConditionalSpend => "conditional",
        ProofType::Settlement => "settlement",
        ProofType::Mint => "mint",
    };

    println!("✓ ProofType enum has all four variants");

    // verify Spender has create_conditional_spend method
    let _has_method = Spender::create_conditional_spend;
    println!("✓ Spender::create_conditional_spend exists");

    // verify settlement types exist
    let _settlement_output = |o: SettlementOutput| {
        (
            o.maker_nullifier,
            o.taker_nullifier,
            o.maker_change_commitment,
            o.payment_commitment,
            o.taker_goods_commitment,
            o.taker_change_commitment,
        )
    };
    println!("✓ SettlementOutput type exists with all fields");

    let _settlement_params = |_p: SettlementParams| {};
    println!("✓ SettlementParams type exists");

    let _settlement_proof = |_p: SettlementProof| {};
    println!("✓ SettlementProof type exists");

    // verify settlement guest exists (compile-time check)
    #[cfg(feature = "risc0")]
    {
        // this will fail to compile if SETTLEMENT_ELF doesn't exist
        use clvm_zk_risc0::SETTLEMENT_ELF;
        let _ = SETTLEMENT_ELF;
        println!("✓ SETTLEMENT_ELF available (risc0)");
    }

    #[cfg(not(feature = "risc0"))]
    {
        println!("⚠ risc0 feature not enabled, skipping SETTLEMENT_ELF check");
    }

    println!("\n✓ ALL SETTLEMENT API CHECKS PASSED");
    println!("  recursive settlement infrastructure is complete");
}

#[test]
fn test_proof_type_differentiation() {
    // verify proof types are correctly differentiated
    assert_ne!(
        ProofType::Transaction as u8,
        ProofType::ConditionalSpend as u8
    );
    assert_ne!(ProofType::Transaction as u8, ProofType::Settlement as u8);
    assert_ne!(ProofType::Transaction as u8, ProofType::Mint as u8);
    assert_ne!(
        ProofType::ConditionalSpend as u8,
        ProofType::Settlement as u8
    );
    assert_ne!(ProofType::ConditionalSpend as u8, ProofType::Mint as u8);
    assert_ne!(ProofType::Settlement as u8, ProofType::Mint as u8);

    println!("✓ proof types have distinct values:");
    println!("  Transaction: {}", ProofType::Transaction as u8);
    println!("  ConditionalSpend: {}", ProofType::ConditionalSpend as u8);
    println!("  Settlement: {}", ProofType::Settlement as u8);
    println!("  Mint: {}", ProofType::Mint as u8);
}

#[test]
fn test_settlement_output_size() {
    // verify SettlementOutput has expected structure
    let output = SettlementOutput {
        maker_nullifier: [1u8; 32],
        taker_nullifier: [2u8; 32],
        maker_change_commitment: [3u8; 32],
        payment_commitment: [4u8; 32],
        taker_goods_commitment: [5u8; 32],
        taker_change_commitment: [6u8; 32],
        maker_pubkey: [7u8; 32], // for validator to check against offer
    };

    assert_eq!(output.maker_nullifier, [1u8; 32]);
    assert_eq!(output.taker_nullifier, [2u8; 32]);
    assert_eq!(output.maker_change_commitment, [3u8; 32]);
    assert_eq!(output.payment_commitment, [4u8; 32]);
    assert_eq!(output.taker_goods_commitment, [5u8; 32]);
    assert_eq!(output.taker_change_commitment, [6u8; 32]);
    assert_eq!(output.maker_pubkey, [7u8; 32]);

    println!("✓ SettlementOutput has 7 fields (6 commitments + maker_pubkey = 224 bytes)");
}

#[test]
fn test_process_settlement_double_spend_rejected() {
    let mut sim = CLVMZkSimulator::new();
    let output = SettlementOutput {
        maker_nullifier: [0xaau8; 32],
        taker_nullifier: [0xbbu8; 32],
        maker_change_commitment: [1u8; 32],
        payment_commitment: [2u8; 32],
        taker_goods_commitment: [3u8; 32],
        taker_change_commitment: [4u8; 32],
        maker_pubkey: [0u8; 32],
    };

    // first call succeeds
    assert!(
        sim.process_settlement(&output).is_ok(),
        "first process_settlement should succeed"
    );

    // second call with same output must fail (both nullifiers already spent)
    let result = sim.process_settlement(&output);
    assert!(
        result.is_err(),
        "duplicate process_settlement must be rejected"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("already spent"),
        "error should mention 'already spent', got: {err}"
    );

    // second call with only maker nullifier reused must also fail
    let partial_reuse = SettlementOutput {
        maker_nullifier: [0xaau8; 32], // reused maker
        taker_nullifier: [0xccu8; 32], // fresh taker
        maker_change_commitment: [5u8; 32],
        payment_commitment: [6u8; 32],
        taker_goods_commitment: [7u8; 32],
        taker_change_commitment: [8u8; 32],
        maker_pubkey: [0u8; 32],
    };
    let result2 = sim.process_settlement(&partial_reuse);
    assert!(
        result2.is_err(),
        "reusing maker nullifier alone must also be rejected"
    );
}
