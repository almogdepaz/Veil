// precompile delegated puzzle to get bytecode and hash for guest caching
// run with: cargo run --example precompile_delegated --no-default-features --features risc0

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
            println!("// delegated puzzle precompiled constants for guest");
            println!();
            println!("const DELEGATED_PUZZLE_BYTECODE: &[u8] = &[");
            for (i, byte) in bytecode.iter().enumerate() {
                if i % 16 == 0 {
                    print!("    ");
                }
                print!("0x{:02x}, ", byte);
                if i % 16 == 15 {
                    println!();
                }
            }
            if bytecode.len() % 16 != 0 {
                println!();
            }
            println!("];");
            println!();
            println!("const DELEGATED_PUZZLE_HASH: [u8; 32] = [");
            for (i, byte) in hash.iter().enumerate() {
                if i % 16 == 0 {
                    print!("    ");
                }
                print!("0x{:02x}, ", byte);
                if i % 16 == 15 {
                    println!();
                }
            }
            if hash.len() % 16 != 0 {
                println!();
            }
            println!("];");
            println!();
            println!(
                "const DELEGATED_PUZZLE_SOURCE: &str = r#\"{}\"#;",
                delegated_puzzle
            );
            println!();
            println!("bytecode length: {} bytes", bytecode.len());
            println!("puzzle hash: {}", hex::encode(hash));
        }
        Err(e) => {
            eprintln!("compilation failed: {:?}", e);
            std::process::exit(1);
        }
    }
}
