// quick test to verify XCH and CAT commitments are different
use clvm_zk_core::{CoinCommitment, SerialCommitment, XCH_TAIL};
use sha2::{Digest, Sha256};

fn hash_data(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn main() {
    let puzzle_hash = [0x42u8; 32];
    let amount = 1000u64;
    let serial_commitment = SerialCommitment([0x99u8; 32]);

    // XCH commitment
    let xch_commitment = CoinCommitment::compute(
        &XCH_TAIL,
        amount,
        &puzzle_hash,
        &serial_commitment,
        hash_data,
    );

    // CAT commitment with tail hash
    let cat_tail = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

    let cat_commitment = CoinCommitment::compute(
        &cat_tail,
        amount,
        &puzzle_hash,
        &serial_commitment,
        hash_data,
    );

    println!("XCH commitment: {:02x}{:02x}{:02x}{:02x}...",
        xch_commitment.as_bytes()[0],
        xch_commitment.as_bytes()[1],
        xch_commitment.as_bytes()[2],
        xch_commitment.as_bytes()[3]);

    println!("CAT commitment: {:02x}{:02x}{:02x}{:02x}...",
        cat_commitment.as_bytes()[0],
        cat_commitment.as_bytes()[1],
        cat_commitment.as_bytes()[2],
        cat_commitment.as_bytes()[3]);

    if xch_commitment == cat_commitment {
        println!("\n❌ FAILED: commitments are identical (should differ!)");
        std::process::exit(1);
    } else {
        println!("\n✓ PASSED: XCH and CAT commitments are different");
        println!("  this proves asset isolation - can't confuse XCH with CATs");
    }
}
