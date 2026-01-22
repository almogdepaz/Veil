//! tests to verify hardcoded precompiled bytecode matches source
//!
//! critical security test: if these fail, the guest programs have stale bytecode
//! that doesn't match the source, which could lead to unexpected behavior

use sha2::{Digest, Sha256};

fn sha2_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// these must match the constants in backends/risc0/guest/src/main.rs
// and backends/sp1/program/src/main.rs
const DELEGATED_PUZZLE_SOURCE: &str = r#"(mod (offered requested maker_pubkey change_amount change_puzzle change_serial change_rand)
  (c
    (c 51 (c change_puzzle (c change_amount (c change_serial (c change_rand ())))))
    (c offered (c requested (c maker_pubkey ())))
  )
)"#;

const DELEGATED_PUZZLE_BYTECODE: &[u8] = &[
    0xff, 0x02, 0xff, 0xff, 0x01, 0xff, 0x04, 0xff, 0xff, 0x04, 0xff, 0xff, 0x01, 0x33, 0xff, 0xff,
    0x04, 0xff, 0x5f, 0xff, 0xff, 0x04, 0xff, 0x2f, 0xff, 0xff, 0x04, 0xff, 0x82, 0x00, 0xbf, 0xff,
    0xff, 0x04, 0xff, 0x82, 0x01, 0x7f, 0xff, 0xff, 0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xff,
    0xff, 0x04, 0xff, 0x05, 0xff, 0xff, 0x04, 0xff, 0x0b, 0xff, 0xff, 0x04, 0xff, 0x17, 0xff, 0xff,
    0x01, 0x80, 0x80, 0x80, 0x80, 0x80, 0xff, 0xff, 0x04, 0xff, 0xff, 0x01, 0x80, 0xff, 0x01, 0x80,
    0x80,
];

const DELEGATED_PUZZLE_HASH: [u8; 32] = [
    0x26, 0x24, 0x38, 0x09, 0xc2, 0x14, 0xb0, 0x80, 0x00, 0x4c, 0x48, 0x36, 0x05, 0x75, 0x7a, 0xa7,
    0xb3, 0xfc, 0xd5, 0x24, 0x34, 0xad, 0xd2, 0x4f, 0xe8, 0x20, 0x69, 0x7b, 0xfd, 0x8a, 0x63, 0x81,
];

#[test]
fn test_delegated_puzzle_bytecode_matches_source() {
    // compile the source and verify it matches the hardcoded bytecode
    let (compiled_bytecode, compiled_hash) =
        clvm_zk_core::compile_chialisp_to_bytecode(sha2_hash, DELEGATED_PUZZLE_SOURCE)
            .expect("delegated puzzle should compile");

    // verify bytecode matches
    assert_eq!(
        compiled_bytecode, DELEGATED_PUZZLE_BYTECODE,
        "CRITICAL: delegated puzzle bytecode mismatch! \
         the hardcoded bytecode in guest programs is stale. \
         run `cargo run --example precompile_delegated` to regenerate."
    );

    // verify hash matches
    assert_eq!(
        compiled_hash, DELEGATED_PUZZLE_HASH,
        "CRITICAL: delegated puzzle hash mismatch! \
         the hardcoded hash in guest programs is stale. \
         run `cargo run --example precompile_delegated` to regenerate."
    );
}

#[test]
fn test_delegated_puzzle_hash_matches_bytecode() {
    // independently verify the hash is correct for the bytecode
    let computed_hash = sha2_hash(DELEGATED_PUZZLE_BYTECODE);
    assert_eq!(
        computed_hash, DELEGATED_PUZZLE_HASH,
        "CRITICAL: hardcoded hash doesn't match hardcoded bytecode! \
         the constants are inconsistent."
    );
}

#[test]
fn test_precompiled_constants_documentation() {
    // this test exists to document what the precompiled puzzle does
    // and ensure it's correct

    // the delegated puzzle:
    // 1. creates a change coin: (51 change_puzzle change_amount change_serial change_rand)
    // 2. returns: (offered requested maker_pubkey) for external verification

    // parse to verify structure
    let (bytecode, _) =
        clvm_zk_core::compile_chialisp_to_bytecode(sha2_hash, DELEGATED_PUZZLE_SOURCE)
            .expect("should compile");

    assert!(!bytecode.is_empty(), "bytecode should not be empty");
    assert_eq!(
        bytecode.len(),
        81,
        "bytecode length changed - update guest constants"
    );
}
