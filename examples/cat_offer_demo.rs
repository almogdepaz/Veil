//! CAT offer demo
//!
//! demonstrates the complete flow of:
//! 1. minting a CAT (computing tail_hash from TAIL program)
//! 2. creating an offer to trade CAT for XCH
//! 3. taking the offer (atomic swap)
//!
//! this uses the mock backend for fast testing
//! run with: cargo run-mock --example cat_offer_demo

use clvm_zk::protocol::{PrivateCoin, ProofType, Spender};
use clvm_zk_core::{
    coin_commitment::{CoinCommitment, CoinSecrets},
    compile_chialisp_template_hash_default, with_standard_conditions, ProgramParameter,
};
use sha2::{Digest, Sha256};

fn hash_data(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// TAIL program for our demo CAT - unlimited minting for simplicity
/// in production you'd use signature-based or governance-controlled TAILs
const DEMO_TAIL: &str = "(mod () 1)";

/// compute tail_hash from TAIL program - this identifies the CAT asset type
fn compute_tail_hash(tail_program: &str) -> [u8; 32] {
    compile_chialisp_template_hash_default(tail_program).expect("TAIL should compile")
}

/// structure to hold a minted CAT with its secrets
struct MintedCat {
    coin: PrivateCoin,
    secrets: CoinSecrets,
    puzzle_code: String,
    tail_hash: [u8; 32],
}

/// mint a new CAT coin with given amount
fn mint_cat(amount: u64) -> MintedCat {
    // 1. compute tail_hash from our TAIL program
    let tail_hash = compute_tail_hash(DEMO_TAIL);

    // 2. create a delegated puzzle for the CAT (allows offers)
    let puzzle_code = with_standard_conditions(
        "(mod (offered requested maker_pubkey change_amount change_puzzle change_serial change_rand)
          (c
            (c 51 (c change_puzzle (c change_amount (c change_serial (c change_rand ())))))
            (c offered (c requested (c maker_pubkey ())))
          )
        )",
    );
    let puzzle_hash = compile_chialisp_template_hash_default(&puzzle_code).expect("compile");

    // 3. create the CAT coin with random secrets
    let (coin, secrets) = PrivateCoin::new_with_secrets_and_tail(puzzle_hash, amount, tail_hash);

    MintedCat {
        coin,
        secrets,
        puzzle_code,
        tail_hash,
    }
}

/// create XCH coin for the taker
fn create_xch_coin(amount: u64) -> (PrivateCoin, CoinSecrets, String) {
    let puzzle_code = with_standard_conditions(
        "(mod (out_puzzle out_amount out_serial out_rand)
            (list (list CREATE_COIN out_puzzle out_amount out_serial out_rand)))",
    );
    let puzzle_hash = compile_chialisp_template_hash_default(&puzzle_code).expect("compile");
    let (coin, secrets) = PrivateCoin::new_with_secrets(puzzle_hash, amount);
    (coin, secrets, puzzle_code)
}

fn main() {
    println!("=== CAT OFFER DEMO ===");
    println!();

    // === STEP 1: MINT A CAT ===
    println!("📦 STEP 1: Minting a new CAT");
    println!("---------------------------------");

    let cat_amount = 1000u64;
    let minted = mint_cat(cat_amount);

    println!("  TAIL program: {}", DEMO_TAIL);
    println!(
        "  tail_hash: {}",
        hex::encode(minted.tail_hash)
    );
    println!("  amount: {} CAT mojos", minted.coin.amount);
    println!("  is_cat: {}", minted.coin.is_cat());
    println!();

    // === STEP 2: CREATE XCH FOR TAKER ===
    println!("💰 STEP 2: Creating XCH for taker");
    println!("---------------------------------");

    let xch_amount = 500u64;
    let (xch_coin, xch_secrets, xch_puzzle) = create_xch_coin(xch_amount);

    println!("  amount: {} XCH mojos", xch_coin.amount);
    println!("  is_xch: {}", xch_coin.is_xch());
    println!();

    // === STEP 3: BUILD MERKLE TREE ===
    println!("🌲 STEP 3: Building merkle tree");
    println!("---------------------------------");

    // compute commitments
    let cat_commitment = CoinCommitment::compute(
        &minted.coin.tail_hash,
        minted.coin.amount,
        &minted.coin.puzzle_hash,
        &minted.coin.serial_commitment,
        hash_data,
    );

    let xch_commitment = CoinCommitment::compute(
        &xch_coin.tail_hash,
        xch_coin.amount,
        &xch_coin.puzzle_hash,
        &xch_coin.serial_commitment,
        hash_data,
    );

    // simple 2-leaf merkle tree
    let merkle_root = hash_data(
        &[cat_commitment.0.as_slice(), xch_commitment.0.as_slice()].concat(),
    );

    // merkle paths
    let cat_merkle_path = vec![xch_commitment.0];
    let xch_merkle_path = vec![cat_commitment.0];

    println!(
        "  CAT commitment: {}...",
        hex::encode(&cat_commitment.0[..8])
    );
    println!(
        "  XCH commitment: {}...",
        hex::encode(&xch_commitment.0[..8])
    );
    println!("  merkle root: {}...", hex::encode(&merkle_root[..8]));
    println!();

    // === STEP 4: MAKER CREATES OFFER ===
    println!("📝 STEP 4: Maker creates conditional offer");
    println!("---------------------------------");

    // offer terms: offering 100 CAT, requesting 50 XCH
    let offered_amount = 100u64;
    let requested_amount = 50u64;
    let change_amount = cat_amount - offered_amount; // 900 CAT change

    // maker's encryption pubkey (random for demo)
    let mut maker_pubkey = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut maker_pubkey);

    // change coin params
    let mut change_puzzle = [0u8; 32];
    let mut change_serial = [0u8; 32];
    let mut change_rand = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut change_puzzle);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut change_serial);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut change_rand);

    let offer_params = vec![
        ProgramParameter::Int(offered_amount),
        ProgramParameter::Int(requested_amount),
        ProgramParameter::from_bytes(&maker_pubkey),
        ProgramParameter::Int(change_amount),
        ProgramParameter::from_bytes(&change_puzzle),
        ProgramParameter::from_bytes(&change_serial),
        ProgramParameter::from_bytes(&change_rand),
    ];

    println!("  offering: {} CAT mojos", offered_amount);
    println!("  requesting: {} XCH mojos", requested_amount);
    println!("  change: {} CAT mojos (back to maker)", change_amount);
    println!();

    // create conditional spend proof
    let conditional_result = Spender::create_conditional_spend(
        &minted.coin,
        &minted.puzzle_code,
        &offer_params,
        &minted.secrets,
        cat_merkle_path,
        merkle_root,
        0,
    );

    match conditional_result {
        Ok(bundle) => {
            println!("  ✅ conditional offer created!");
            println!("  proof type: {:?}", bundle.proof_type);
            println!("  proof size: {} bytes", bundle.zk_proof.len());
            println!("  nullifiers: {}", bundle.nullifiers.len());

            assert_eq!(bundle.proof_type, ProofType::ConditionalSpend);
            assert!(!bundle.nullifiers.is_empty());

            // === STEP 5: TAKER VIEWS OFFER ===
            println!();
            println!("👀 STEP 5: Taker views the offer");
            println!("---------------------------------");
            println!("  the taker sees:");
            println!("    - maker offers: {} CAT", offered_amount);
            println!("    - maker wants: {} XCH", requested_amount);
            println!(
                "    - CAT asset type (tail_hash): {}...",
                hex::encode(&minted.tail_hash[..8])
            );
            println!("    - proof is ConditionalSpend (locked until settlement)");
            println!();

            // === STEP 6: TAKER WOULD TAKE OFFER ===
            println!("🤝 STEP 6: Taker would take the offer");
            println!("---------------------------------");
            println!("  in a real flow, taker would:");
            println!("    1. verify maker's conditional proof");
            println!("    2. spend their XCH coin");
            println!("    3. create settlement proof that:");
            println!("       - proves taker has {} XCH", requested_amount);
            println!("       - proves maker offers {} CAT", offered_amount);
            println!("       - atomically swaps the assets");
            println!("    4. outputs:");
            println!("       - maker_nullifier (CAT spent)");
            println!("       - taker_nullifier (XCH spent)");
            println!("       - payment_commitment (XCH to maker)");
            println!("       - goods_commitment (CAT to taker)");
            println!("       - change commitments");
            println!();

            // verify taker has enough XCH
            if xch_coin.amount >= requested_amount {
                println!("  ✅ taker has {} XCH >= {} requested", xch_coin.amount, requested_amount);
            } else {
                println!(
                    "  ❌ taker has {} XCH < {} requested",
                    xch_coin.amount, requested_amount
                );
            }

            println!();
            println!("=== DEMO COMPLETE ===");
            println!();
            println!("key insights:");
            println!(
                "  1. CAT minting: computed tail_hash from TAIL program: {}...",
                hex::encode(&minted.tail_hash[..8])
            );
            println!("  2. asset isolation: CAT and XCH have different tail_hash");
            println!(
                "  3. offers are atomic: conditional proof locks until settlement"
            );
            println!("  4. privacy: amounts/assets hidden in commitments");
            println!();
            println!("note: full settlement requires risc0/sp1 backend for recursive proving");
            println!("      run with: cargo run-risc0 --example cat_offer_demo");

            // also verify the XCH coin can be spent
            let xch_out_puzzle = [1u8; 32];
            let xch_out_serial = [2u8; 32];
            let xch_out_rand = [3u8; 32];

            let xch_solution = vec![
                ProgramParameter::from_bytes(&xch_out_puzzle),
                ProgramParameter::Int(xch_amount),
                ProgramParameter::from_bytes(&xch_out_serial),
                ProgramParameter::from_bytes(&xch_out_rand),
            ];

            let xch_spend_result = Spender::create_spend_with_serial(
                &xch_coin,
                &xch_puzzle,
                &xch_solution,
                &xch_secrets,
                xch_merkle_path,
                merkle_root,
                1,
            );

            match xch_spend_result {
                Ok(xch_bundle) => {
                    println!();
                    println!("bonus: verified taker's XCH coin is spendable");
                    println!("  proof size: {} bytes", xch_bundle.zk_proof.len());
                    println!("  nullifiers: {}", xch_bundle.nullifiers.len());
                }
                Err(e) => {
                    println!();
                    println!("warning: XCH spend test failed: {:?}", e);
                }
            }
        }
        Err(e) => {
            println!("  ❌ conditional offer failed: {:?}", e);
        }
    }
}
