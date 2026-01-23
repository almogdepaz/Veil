// profile chialisp compilation phases
// run with: cargo run --example profile_compilation --no-default-features --features risc0 --release

use sha2::{Digest, Sha256};
use std::time::Instant;

fn sha2_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn main() {
    let delegated_puzzle = r#"(mod (offered requested maker_pubkey change_amount change_puzzle change_serial change_rand)
  (c
    (c 51 (c change_puzzle (c change_amount (c change_serial (c change_rand ())))))
    (c offered (c requested (c maker_pubkey ())))
  )
)"#;

    println!("profiling compilation of delegated puzzle...\n");

    // warm up
    for _ in 0..5 {
        let _ = clvm_zk_core::compile_chialisp_to_bytecode(sha2_hash, delegated_puzzle);
    }

    // profile 100 runs
    let runs = 100;
    let start = Instant::now();

    for _ in 0..runs {
        let _ = clvm_zk_core::compile_chialisp_to_bytecode(sha2_hash, delegated_puzzle)
            .expect("compilation failed");
    }

    let duration = start.elapsed();
    let avg_micros = duration.as_micros() / runs;

    println!("compilation timing (native, {} runs):", runs);
    println!("  total: {:?}", duration);
    println!("  average: {} µs per compilation", avg_micros);
    println!(
        "  rate: {:.2} compilations/sec",
        1_000_000.0 / avg_micros as f64
    );
}
