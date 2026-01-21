// utility to precompile standard puzzles for guest caching
// run with: cargo run --bin precompile_puzzles

use sha2::{Digest, Sha256};

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

    match clvm_zk_core::compile_chialisp_to_bytecode(sha2_hash, delegated_puzzle) {
        Ok((bytecode, hash)) => {
            println!("// delegated puzzle precompiled bytecode");
            println!("const DELEGATED_PUZZLE_BYTECODE: &[u8] = &{:?};", bytecode);
            println!();
            println!("const DELEGATED_PUZZLE_HASH: [u8; 32] = {:?};", hash);
            println!();
            println!("const DELEGATED_PUZZLE_SOURCE: &str = r#\"{}\"#;", delegated_puzzle);
        }
        Err(e) => {
            eprintln!("compilation failed: {:?}", e);
            std::process::exit(1);
        }
    }
}
