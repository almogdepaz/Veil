use crate::protocol::PrivateCoin;
use crate::simulator::{CLVMZkSimulator, CoinMetadata, CoinType};
use crate::wallet::{CLVMHDWallet, Network, WalletError};
use crate::{ClvmZkError, ClvmZkProver, ProgramParameter};
use clap::{Parser, Subcommand};
use clvm_zk_core::compile_chialisp_template_hash_default;
use clvm_zk_core::{atom_to_number, ClvmParser};
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "clvm-zk")]
#[command(about = "A CLVM Zero-Knowledge Proof system with blockchain simulator")]
#[command(version = "0.1.0")]
pub struct Cli {
    /// Data directory for simulator state
    #[arg(long, default_value = "./simulator_data")]
    data_dir: PathBuf,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run demo showing various CLVM programs
    Demo,
    /// Generate ZK proof for a CLVM program
    Prove {
        /// Type of program to create (optional - inferred as 'composite' if --expression is provided)
        #[arg(short, long)]
        program_type: Option<ProgramType>,
        /// First argument for the program (not needed if using --variables)
        #[arg(long)]
        arg1: Option<i64>,
        /// Second argument for the program (if needed)
        #[arg(long)]
        arg2: Option<i64>,
        /// Third argument for the program (if needed)  
        #[arg(long)]
        arg3: Option<i64>,
        /// Expression for composite programs using standard S-expressions (e.g., "(* (+ a b) c)", "(i (> a b) 100 200)")
        #[arg(long)]
        expression: Option<String>,
        /// Variables for composable programs: a,b,c,d,e,f,g,h,i,j (comma-separated)
        #[arg(long)]
        variables: Option<String>,
    },
    /// Verify a ZK proof
    Verify {
        /// Path to proof file
        #[arg(long)]
        proof_file: String,
        /// Program hash (32-byte hex string) - either this or --template is required
        #[arg(long)]
        program_hash: Option<String>,
        /// Program template (alternative to --program-hash) - either this or --program-hash is required
        #[arg(long)]
        template: Option<String>,
        /// Expected output (hex string, optional - will extract from proof if not provided)
        #[arg(long)]
        expected_output: Option<String>,
    },
    /// Benchmark proof generation performance
    Bench {
        /// Number of proofs to generate
        #[arg(short, long, default_value = "10")]
        count: usize,
    },
    /// Simulator commands
    Sim {
        #[command(subcommand)]
        action: SimAction,
    },
    /// Generate puzzle program from password
    #[command(name = "hash-password")]
    HashPassword {
        /// Password to generate puzzle program for
        password: String,
    },
}

#[derive(Subcommand)]
pub enum SimAction {
    /// Initialize simulator
    Init {
        /// Reset existing state
        #[arg(long)]
        reset: bool,
    },
    /// Get coins from faucet
    Faucet {
        /// Wallet name
        wallet: String,
        /// Amount per coin
        #[arg(long, default_value = "10000")]
        amount: u64,
        /// Number of coins
        #[arg(long, default_value = "1")]
        count: u32,
        /// Asset ID (tail_hash) - hex string. Omit for XCH.
        #[arg(long)]
        tail: Option<String>,
        /// Use delegated puzzle (required for offers)
        #[arg(long)]
        delegated: bool,
    },
    /// Wallet operations
    Wallet {
        name: String,
        #[command(subcommand)]
        action: WalletAction,
    },
    /// Show simulator status
    Status,
    /// List wallets
    Wallets,
    /// Send coins between wallets
    Send {
        /// Source wallet name
        from: String,
        /// Destination wallet name
        to: String,
        /// Amount to send
        amount: u64,
        /// Coin indices to spend (comma-separated, e.g. "0,1,2" or "auto" for automatic selection)
        #[arg(long)]
        coins: String,
        /// Stealth address mode: "nullifier" (fast, default) or "signature" (secure)
        #[arg(long, default_value = "nullifier")]
        stealth_mode: String,
    },
    /// Spend coins to create a puzzle-locked coin
    #[command(name = "spend-to-puzzle")]
    SpendToPuzzle {
        /// Source wallet name
        from: String,
        /// Amount to lock
        amount: u64,
        /// CLVM program to lock with (e.g. "(= (sha256 a) b)" for password)
        program: String,
        /// Coin indices to spend (comma-separated or "auto")
        #[arg(long)]
        coins: String,
    },
    /// Spend a puzzle-locked coin to a wallet
    #[command(name = "spend-to-wallet")]
    SpendToWallet {
        /// CLVM program that locks the coin
        program: String,
        /// Program parameters as comma-separated values (e.g. "password" for password puzzle)
        #[arg(long)]
        params: String,
        /// Destination wallet name
        to: String,
        /// Amount to spend (must match available puzzle coin)
        amount: u64,
    },
    /// Scan for encrypted payment notes sent to a wallet
    Scan {
        /// Wallet name to scan for
        wallet: String,
    },
    /// View saved proofs from transactions
    Proofs,
    /// Observer wallet operations (view-only, no spending)
    Observer {
        #[command(subcommand)]
        action: ObserverAction,
    },
    /// Create an unlinkable offer
    #[command(name = "offer-create")]
    OfferCreate {
        /// Maker wallet name
        maker: String,
        /// Amount maker is offering
        #[arg(long)]
        offer: u64,
        /// Amount maker is requesting
        #[arg(long)]
        request: u64,
        /// Asset ID (tail_hash) maker is requesting - hex string. Omit for XCH.
        #[arg(long)]
        request_tail: Option<String>,
        /// Coin indices to use (comma-separated or "auto")
        #[arg(long)]
        coins: String,
    },
    /// Take/fulfill an offer
    #[command(name = "offer-take")]
    OfferTake {
        /// Taker wallet name
        taker: String,
        /// Offer ID to take
        #[arg(long)]
        offer_id: usize,
        /// Coin indices to use (comma-separated or "auto")
        #[arg(long)]
        coins: String,
    },
    /// List pending offers
    #[command(name = "offer-list")]
    OfferList,
}

#[derive(Subcommand)]
pub enum WalletAction {
    /// Create wallet
    Create,
    /// Show wallet details
    Show,
    /// List coins
    Coins,
    /// List only unspent coins with indices
    Unspent,
    /// Show total unspent balance
    Balance,
    /// Export viewing key for observer wallet
    ExportViewingKey,
}

#[derive(Subcommand)]
pub enum ObserverAction {
    /// Create observer wallet from viewing key
    Create {
        /// Name for the observer wallet
        name: String,
        /// Viewing key (hex encoded)
        #[arg(long)]
        viewing_key: String,
        /// Account index
        #[arg(long, default_value = "0")]
        account: u32,
        /// Network (mainnet/testnet)
        #[arg(long, default_value = "testnet")]
        network: String,
    },
    /// Scan for coins belonging to observer wallet
    Scan {
        /// Observer wallet name
        name: String,
        /// Maximum coin index to scan
        #[arg(long, default_value = "100")]
        max_index: u32,
    },
    /// Show observer wallet details
    Show {
        /// Observer wallet name
        name: String,
    },
    /// List all observer wallets
    List,
}

#[derive(clap::ValueEnum, Clone)]
pub enum ProgramType {
    Number,
    Add,
    Multiply,
    Conditional,
    List,
    Composite,
}

pub fn run_cli() -> Result<(), ClvmZkError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Demo => run_demo(),
        Commands::Prove {
            program_type,
            arg1,
            arg2,
            arg3,
            expression,
            variables,
        } => run_prove(program_type, arg1, arg2, arg3, expression, variables),
        Commands::Verify {
            proof_file,
            program_hash,
            template,
            expected_output,
        } => run_verify(
            &proof_file,
            program_hash.as_deref(),
            template.as_deref(),
            expected_output.as_deref(),
        ),
        Commands::Bench { count } => run_benchmark(count),
        Commands::Sim { action } => run_simulator_command(&cli.data_dir, action),
        Commands::HashPassword { password } => run_hash_password(&password),
    }
}

fn run_demo() -> Result<(), ClvmZkError> {
    println!("CLVM ZK Prover - CLI Demo");
    println!("===========================");

    let demos = vec![
        ("Number (42)", "42", Vec::new()),
        (
            "Addition (+ 5 3)",
            "(mod (a b) (+ a b))",
            vec![ProgramParameter::int(5), ProgramParameter::int(3)],
        ),
        (
            "Multiplication (* 4 7)",
            "(mod (a b) (* a b))",
            vec![ProgramParameter::int(4), ProgramParameter::int(7)],
        ),
        (
            "Conditional TRUE",
            "(mod (condition then_val else_val) (i condition then_val else_val))",
            vec![
                ProgramParameter::int(1),
                ProgramParameter::int(100),
                ProgramParameter::int(200),
            ],
        ),
        (
            "List operation",
            "(mod (a b) (f (c a b)))",
            vec![ProgramParameter::int(10), ProgramParameter::int(20)],
        ),
    ];

    for (name, expression, parameters) in demos {
        println!("\nTesting {name}");
        match ClvmZkProver::prove(expression, &parameters) {
            Ok(result) => {
                println!("   Proof generated: {} bytes", result.proof_bytes.len());

                // Extract program hash from proof for verification
                let backend = crate::backends::backend()?;
                let (proof_valid, program_hash, output) =
                    backend.verify_proof(&result.proof_bytes)?;

                if !proof_valid {
                    println!("   ERROR: Proof verification failed");
                    return Ok(());
                }

                println!("   Program hash from proof: {}", hex::encode(program_hash));
                println!(
                    "   Output matches: {}",
                    output == result.proof_output.clvm_res.output
                );

                match ClvmZkProver::verify_proof(
                    program_hash,
                    &result.proof_bytes,
                    Some(&result.proof_output.clvm_res.output),
                ) {
                    Ok((true, _)) => println!("   Proof verified"),
                    Ok((false, _)) => println!("   Proof invalid"),
                    Err(e) => println!("   Verification error: {e}"),
                }
            }
            Err(e) => println!("   Proof generation failed: {e}"),
        }
    }

    println!("\nDemo completed successfully!");
    Ok(())
}

fn run_prove(
    program_type: Option<ProgramType>,
    arg1: Option<i64>,
    arg2: Option<i64>,
    arg3: Option<i64>,
    expression: Option<String>,
    variables: Option<String>,
) -> Result<(), ClvmZkError> {
    println!("Generating ZK Proof");
    println!("=====================");

    // Infer program type if not provided
    let program_type = match program_type {
        Some(pt) => pt,
        None => {
            if expression.is_some() {
                ProgramType::Composite
            } else {
                return Err(ClvmZkError::InvalidProgram(
                    "Must provide either --program-type or --expression".to_string(),
                ));
            }
        }
    };

    let (expression, parameters) = match program_type {
        ProgramType::Number => {
            let arg1 = arg1.ok_or_else(|| {
                ClvmZkError::InvalidProgram("Number programs require --arg1".to_string())
            })?;
            println!("Creating number program: {arg1}");
            (arg1.to_string(), vec![])
        }
        ProgramType::Add => {
            let arg1 = arg1.ok_or_else(|| {
                ClvmZkError::InvalidProgram("Addition programs require --arg1".to_string())
            })?;
            let arg2 = arg2.unwrap_or(0);
            println!("Creating addition program: {arg1} + {arg2}");
            (
                "(mod (a b) (+ a b))".to_string(),
                vec![ProgramParameter::int(arg1), ProgramParameter::int(arg2)],
            )
        }
        ProgramType::Multiply => {
            let arg1 = arg1.ok_or_else(|| {
                ClvmZkError::InvalidProgram("Multiplication programs require --arg1".to_string())
            })?;
            let arg2 = arg2.unwrap_or(1);
            println!("Creating multiplication program: {arg1} * {arg2}");
            (
                "(mod (a b) (* a b))".to_string(),
                vec![ProgramParameter::int(arg1), ProgramParameter::int(arg2)],
            )
        }
        ProgramType::Conditional => {
            let arg1 = arg1.ok_or_else(|| {
                ClvmZkError::InvalidProgram("Conditional programs require --arg1".to_string())
            })?;
            let arg2 = arg2.unwrap_or(42);
            let arg3 = arg3.unwrap_or(99);
            println!("Creating conditional program: if {arg1} then {arg2} else {arg3}");
            (
                "(i a b c)".to_string(),
                vec![
                    ProgramParameter::int(arg1),
                    ProgramParameter::int(arg2),
                    ProgramParameter::int(arg3),
                ],
            )
        }
        ProgramType::List => {
            let arg1 = arg1.ok_or_else(|| {
                ClvmZkError::InvalidProgram("List programs require --arg1".to_string())
            })?;
            let arg2 = arg2.unwrap_or(0);
            println!("Creating list program: first of cons({arg1}, {arg2})");
            (
                "(mod (a b) (f (c a b)))".to_string(),
                vec![ProgramParameter::int(arg1), ProgramParameter::int(arg2)],
            )
        }
        ProgramType::Composite => {
            match expression {
                Some(expr) => {
                    if let Some(vars_str) = variables {
                        // Validate that variables string is not empty
                        if vars_str.trim().is_empty() {
                            return Err(ClvmZkError::InvalidProgram(
                                "Invalid variables format: variables cannot be empty. Either omit --variables or provide valid comma-separated integers".to_string()
                            ));
                        }

                        // Parse variables from comma-separated string
                        let vars: Result<Vec<i64>, _> = vars_str
                            .split(',')
                            .map(|s| s.trim().parse::<i64>())
                            .collect();

                        match vars {
                            Ok(parsed_vars) => {
                                println!("Creating composable program: {expr} with variables: {vars_str}");
                                (
                                    expr,
                                    parsed_vars
                                        .iter()
                                        .map(|&v| ProgramParameter::int(v))
                                        .collect::<Vec<_>>(),
                                )
                            }
                            Err(e) => {
                                return Err(ClvmZkError::InvalidProgram(format!(
                                    "Invalid variables format: {e}"
                                )));
                            }
                        }
                    } else {
                        // No parameters when no variables provided
                        println!("Creating composite program: {expr}");
                        (expr, vec![])
                    }
                }
                None => {
                    return Err(ClvmZkError::InvalidProgram(
                        "Composite programs require --expression parameter".to_string(),
                    ));
                }
            }
        }
    };

    println!("\nGenerating proof...");
    let start_time = std::time::Instant::now();

    match ClvmZkProver::prove(&expression, &parameters) {
        Ok(result) => {
            let duration = start_time.elapsed();
            println!("Proof generated in {duration:?}");

            // Display output in both hex and decoded format
            let output_bytes = &result.proof_output.clvm_res.output;
            let hex_output = hex::encode(output_bytes);
            println!("Output (hex): {}", hex_output);

            // Try to decode as a simple integer
            if let Some(decoded) = decode_clvm_output(output_bytes) {
                println!("Output (decoded): {}", decoded);
            }
            println!("Proof: {} bytes", result.proof_bytes.len());
            println!("Cost: {}", result.proof_output.clvm_res.cost);

            // Save proof to file
            std::fs::write("proof.bin", &result.proof_bytes).map_err(|e| {
                ClvmZkError::SerializationError(format!("Failed to save proof: {e}"))
            })?;

            println!("Saved: proof.bin");
            println!("Program hash and other details are included in the proof's public outputs");
            println!("Note: Use program hash and output hex for verification");
        }
        Err(e) => {
            println!("Proof generation failed: {e}");
            println!("No proof files created due to evaluation failure");
            return Err(e);
        }
    }

    Ok(())
}

fn run_verify(
    proof_file: &str,
    program_hash: Option<&str>,
    template: Option<&str>,
    expected_output: Option<&str>,
) -> Result<(), ClvmZkError> {
    println!("Verifying ZK Proof");
    println!("====================");

    // Security requirement: Either program_hash or template must be provided
    if program_hash.is_none() && template.is_none() {
        return Err(ClvmZkError::InvalidProgram(
            "Security error: Either --program-hash or --template must be provided for verification"
                .to_string(),
        ));
    }

    let proof_bytes = std::fs::read(proof_file)
        .map_err(|e| ClvmZkError::SerializationError(format!("Failed to read proof: {e}")))?;

    // Extract program hash from the proof itself
    let backend = crate::backends::backend()?;
    let (proof_valid, extracted_hash, _extracted_output) = backend.verify_proof(&proof_bytes)?;

    if !proof_valid {
        println!("ERROR: Proof verification failed!");
        return Ok(());
    }

    println!("Program hash from proof: {}", hex::encode(extracted_hash));

    // If user provided a hash, verify it matches what's in the proof
    if let Some(expected_hash_str) = program_hash {
        let expected_hash: [u8; 32] = hex::decode(expected_hash_str)
            .map_err(|e| ClvmZkError::InvalidProgram(format!("Invalid hex hash: {e}")))?
            .try_into()
            .map_err(|_| {
                ClvmZkError::InvalidProgram("Program hash must be exactly 32 bytes".to_string())
            })?;

        if extracted_hash != expected_hash {
            println!("ERROR: Program hash mismatch!");
            println!("  Expected: {}", hex::encode(expected_hash));
            println!("  Got:      {}", hex::encode(extracted_hash));
            return Ok(());
        }
        println!("Program hash matches expected value ✓");
    }

    // If user provided a template, compile it and verify the hash
    if let Some(template_str) = template {
        println!("Compiling template to verify program hash...");

        // Compile the template to get the expected program hash (without parameter values)
        let expected_hash = compile_chialisp_template_hash_default(template_str).map_err(|e| {
            ClvmZkError::InvalidProgram(format!("Template compilation failed: {:?}", e))
        })?;

        if extracted_hash != expected_hash {
            println!("ERROR: Template hash mismatch!");
            println!("  Template: {}", template_str);
            println!("  Expected: {}", hex::encode(expected_hash));
            println!("  Got:      {}", hex::encode(extracted_hash));
            return Ok(());
        }
        println!("Template hash matches proof ✓");
    }

    // Security check: If no explicit program hash was provided, template verification is mandatory
    if program_hash.is_none() && template.is_some() {
        println!("✓ Verification passed: Template matches proof program hash");
    }

    let hash = extracted_hash;

    println!(
        "Program hash: {}, proof ({} bytes)",
        hex::encode(hash),
        proof_bytes.len()
    );

    let start_time = std::time::Instant::now();

    // Parse expected output if provided
    let expected_output_bytes = if let Some(output_str) = expected_output {
        Some(
            hex::decode(output_str)
                .map_err(|e| ClvmZkError::InvalidProgram(format!("Invalid hex output: {e}")))?,
        )
    } else {
        None
    };

    let result = if let Some(expected) = expected_output_bytes {
        // Verify against expected output
        ClvmZkProver::verify_proof(hash, &proof_bytes, Some(&expected))
    } else {
        // Extract output from proof
        ClvmZkProver::verify_proof(hash, &proof_bytes, None)
    };

    match result {
        Ok((true, output)) => {
            let duration = start_time.elapsed();
            println!("Proof verified successfully in {duration:?}");

            // Display the public output in both hex and decoded format
            println!("Proof is VALID");
            println!("Output (hex): {}", hex::encode(&output));

            // Try to decode as a simple integer
            if let Some(decoded) = decode_clvm_output(&output) {
                println!("Output (decoded): {}", decoded);
            }

            // If expected output was provided, confirm it matches
            if expected_output.is_some() {
                println!("Output matches expected value");
            }
        }
        Ok((false, output)) => {
            println!("Proof verification FAILED - invalid proof");
            println!("Output (hex): {}", hex::encode(&output));

            // Try to decode as a simple integer
            if let Some(decoded) = decode_clvm_output(&output) {
                println!("Output (decoded): {}", decoded);
            }

            return Err(ClvmZkError::VerificationError("Invalid proof".to_string()));
        }
        Err(e) => {
            println!("Verification error: {e}");
            return Err(e);
        }
    }

    Ok(())
}

fn run_benchmark(count: usize) -> Result<(), ClvmZkError> {
    println!("Benchmarking ZK Proof Generation");
    println!("==================================");

    let expression = "(mod (a b) (+ a b))";
    let parameters = vec![ProgramParameter::int(123), ProgramParameter::int(456)];

    println!("Running {count} proof generations...");

    let start_time = std::time::Instant::now();
    let mut total_proof_size = 0;
    let mut successful_proofs = 0;

    for i in 0..count {
        match ClvmZkProver::prove(expression, &parameters) {
            Ok(result) => {
                total_proof_size += result.proof_bytes.len();
                successful_proofs += 1;
                if (i + 1) % 10 == 0 {
                    println!("   Completed {}/{} proofs", i + 1, count);
                }
            }
            Err(e) => {
                println!("   Proof {} failed: {}", i + 1, e);
            }
        }
    }

    let total_duration = start_time.elapsed();
    let avg_duration = total_duration / count as u32;
    let avg_proof_size = if successful_proofs > 0 {
        total_proof_size / successful_proofs
    } else {
        0
    };

    println!("\nBenchmark Results:");
    println!("   Total time: {total_duration:?}");
    println!("   Average per proof: {avg_duration:?}");
    println!("   Successful proofs: {successful_proofs}/{count}");
    println!("   Average proof size: {avg_proof_size} bytes");
    println!(
        "   Throughput: {:.2} proofs/second",
        successful_proofs as f64 / total_duration.as_secs_f64()
    );

    Ok(())
}

fn run_hash_password(password: &str) -> Result<(), ClvmZkError> {
    use crate::protocol::create_password_puzzle_program;

    let program = create_password_puzzle_program(password);
    println!("password puzzle program: {}", program);
    println!(
        "use this with: sim spend-to-puzzle <wallet> <amount> \"{}\" --coins <coins>",
        program
    );
    println!(
        "unlock with: sim spend-to-wallet \"{}\" <wallet> <amount> --params \"{}\"",
        program, password
    );

    Ok(())
}

// Simulator state management types
#[derive(Serialize, Deserialize)]
struct SimulatorState {
    wallets: HashMap<String, WalletData>,
    faucet_nonce: u64,
    puzzle_coins: Option<Vec<PuzzleCoin>>,
    #[serde(default)]
    observer_wallets: HashMap<String, ObserverWalletData>,
    #[serde(default)]
    spend_bundles: Vec<crate::protocol::PrivateSpendBundle>,
    #[serde(default)]
    simulator: CLVMZkSimulator,
    #[serde(default)]
    pending_offers: Vec<StoredOffer>,
}

#[derive(Serialize, Deserialize, Clone)]
struct StoredOffer {
    id: usize,
    maker: String,
    offered: u64,
    requested: u64,
    maker_pubkey: [u8; 32], // maker's encryption public key for payment
    maker_bundle: crate::protocol::PrivateSpendBundle,
    created_at: u64,
    // maker's change coin data (for tracking after settlement)
    change_amount: u64,
    change_puzzle: [u8; 32],
    change_serial: [u8; 32],
    change_rand: [u8; 32],
    // asset type identifiers (v2.0)
    #[serde(default)]
    offered_tail_hash: [u8; 32], // asset type maker is offering
    #[serde(default)]
    requested_tail_hash: [u8; 32], // asset type maker is requesting
}

#[derive(Serialize, Deserialize, Clone)]
struct WalletData {
    name: String,
    seed: Vec<u8>, // Real cryptographic seed (16-64 bytes)
    network: Network,
    account_index: u32,
    next_coin_index: u32, // Track next coin index for HD derivation
    coins: Vec<WalletCoinWrapper>,
    // Stealth address pubkeys for receiving payments (33 bytes compressed secp256k1 each)
    // Private keys are derived from seed via StealthKeys
    #[serde(default)]
    stealth_view_pubkey: Option<Vec<u8>>,
    #[serde(default)]
    stealth_spend_pubkey: Option<Vec<u8>>,
    // x25519 encryption keys for nonce encryption in offers (stealth uses hash-based derivation)
    #[serde(default)]
    note_encryption_public: Option<[u8; 32]>,
    #[serde(default)]
    note_encryption_private: Option<[u8; 32]>,
}

/// wrapper around WalletPrivateCoin with additional CLI-specific state
#[derive(Serialize, Deserialize, Clone)]
struct WalletCoinWrapper {
    /// the actual wallet coin with secrets
    wallet_coin: crate::wallet::WalletPrivateCoin,
    /// the chialisp program for this coin
    program: String,
    /// whether this coin has been spent
    spent: bool,
}

impl WalletCoinWrapper {
    /// get coin amount
    fn amount(&self) -> u64 {
        self.wallet_coin.amount()
    }

    /// get coin serial_number
    fn serial_number(&self) -> [u8; 32] {
        self.wallet_coin.serial_number()
    }

    /// get coin puzzle hash
    #[allow(dead_code)]
    fn puzzle_hash(&self) -> [u8; 32] {
        self.wallet_coin.puzzle_hash()
    }

    /// convert to PrivateCoin for spending
    fn to_private_coin(&self) -> PrivateCoin {
        self.wallet_coin.to_protocol_coin()
    }

    /// get coin secrets (needed for spending with serial commitment)
    fn secrets(&self) -> &clvm_zk_core::coin_commitment::CoinSecrets {
        &self.wallet_coin.secrets
    }
}

impl WalletData {
    /// Create HD wallet instance from stored data
    fn get_hd_wallet(&self) -> Result<CLVMHDWallet, WalletError> {
        CLVMHDWallet::from_seed(&self.seed, self.network)
    }

    /// Get next coin index and increment
    fn next_coin_index(&mut self) -> u32 {
        let index = self.next_coin_index;
        self.next_coin_index += 1;
        index
    }

    /// Create new coin using HD derivation
    fn create_coin(
        &mut self,
        puzzle_hash: [u8; 32],
        amount: u64,
        program: String,
    ) -> Result<WalletCoinWrapper, WalletError> {
        self.create_coin_with_tail(puzzle_hash, amount, program, None)
    }

    fn create_coin_with_tail(
        &mut self,
        puzzle_hash: [u8; 32],
        amount: u64,
        program: String,
        tail_hash: Option<[u8; 32]>,
    ) -> Result<WalletCoinWrapper, WalletError> {
        let coin_index = self.next_coin_index();

        let wallet_coin = match tail_hash {
            Some(tail) => crate::wallet::WalletPrivateCoin::new_with_tail(
                puzzle_hash,
                amount,
                self.account_index,
                coin_index,
                tail,
            ),
            None => crate::wallet::WalletPrivateCoin::new(
                puzzle_hash,
                amount,
                self.account_index,
                coin_index,
            ),
        };

        Ok(WalletCoinWrapper {
            wallet_coin,
            program,
            spent: false,
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct PuzzleCoin {
    puzzle_hash: [u8; 32],
    amount: u64,
    program: String,
    secrets: clvm_zk_core::coin_commitment::CoinSecrets,
}

#[derive(Serialize, Deserialize, Clone)]
struct ObserverWalletData {
    name: String,
    viewing_key: [u8; 32],
    account_index: u32,
    network: Network,
    discovered_coins: Vec<DiscoveredCoin>,
}

#[derive(Serialize, Deserialize, Clone)]
struct DiscoveredCoin {
    coin_index: u32,
    viewing_tag: [u8; 4],
    nullifier: Option<[u8; 32]>, // If we can match this to actual coins
}

/// Parse coin indices from CLI string (either "all" or comma-separated indices)
fn parse_coin_indices(
    coin_indices: &str,
    wallet: &WalletData,
) -> Result<Vec<WalletCoinWrapper>, ClvmZkError> {
    let unspent_coins: Vec<&WalletCoinWrapper> = wallet.coins.iter().filter(|c| !c.spent).collect();

    if coin_indices == "all" {
        return Ok(unspent_coins.into_iter().cloned().collect());
    }

    let indices: Result<Vec<usize>, _> = coin_indices
        .split(',')
        .map(|s| s.trim().parse::<usize>())
        .collect();

    let indices = indices
        .map_err(|e| ClvmZkError::InvalidProgram(format!("invalid coin indices format: {}", e)))?;

    let mut result = Vec::new();
    for index in indices {
        if index >= unspent_coins.len() {
            return Err(ClvmZkError::InvalidProgram(format!(
                "coin index {} out of range (0-{})",
                index,
                unspent_coins.len().saturating_sub(1)
            )));
        }
        result.push(unspent_coins[index].clone());
    }

    Ok(result)
}

impl SimulatorState {
    fn new() -> Self {
        Self {
            wallets: HashMap::new(),
            faucet_nonce: 0,
            puzzle_coins: None,
            observer_wallets: HashMap::new(),
            spend_bundles: Vec::new(),
            simulator: CLVMZkSimulator::new(),
            pending_offers: Vec::new(),
        }
    }

    fn load(data_dir: &Path) -> Result<Self, ClvmZkError> {
        let state_file = data_dir.join("state.json");
        if state_file.exists() {
            let data = fs::read_to_string(&state_file).map_err(|e| {
                ClvmZkError::SerializationError(format!("failed to read state file: {e}"))
            })?;
            let mut state: SimulatorState = serde_json::from_str(&data).map_err(|e| {
                ClvmZkError::SerializationError(format!("failed to parse state file: {e}"))
            })?;
            // rebuild merkle tree from persisted leaves
            state.simulator.rebuild_tree();
            Ok(state)
        } else {
            Ok(Self::new())
        }
    }

    fn save(&self, data_dir: &Path) -> Result<(), ClvmZkError> {
        fs::create_dir_all(data_dir).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to create data dir: {e}"))
        })?;
        let state_file = data_dir.join("state.json");
        let data = serde_json::to_string_pretty(self).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to serialize state: {e}"))
        })?;
        fs::write(&state_file, data).map_err(|e| {
            ClvmZkError::SerializationError(format!("failed to write state file: {e}"))
        })?;
        Ok(())
    }
}

// Simulator CLI commands
fn run_simulator_command(data_dir: &Path, action: SimAction) -> Result<(), ClvmZkError> {
    match action {
        SimAction::Init { reset } => {
            if reset && data_dir.exists() {
                fs::remove_dir_all(data_dir).map_err(|e| {
                    ClvmZkError::SerializationError(format!("failed to reset: {e}"))
                })?;
                println!("reset simulator state");
            }

            let state = SimulatorState::new();
            state.save(data_dir)?;
            println!("initialized simulator at {}", data_dir.display());
        }

        SimAction::Faucet {
            wallet,
            amount,
            count,
            tail,
            delegated,
        } => {
            faucet_command(data_dir, &wallet, amount, count, tail, delegated)?;
        }

        SimAction::Wallet { name, action } => {
            wallet_command(data_dir, &name, action)?;
        }

        SimAction::Status => {
            status_command(data_dir)?;
        }

        SimAction::Wallets => {
            wallets_command(data_dir)?;
        }

        SimAction::Send {
            from,
            to,
            amount,
            coins,
            stealth_mode,
        } => {
            send_command(data_dir, &from, &to, amount, &coins, &stealth_mode)?;
        }

        SimAction::SpendToPuzzle {
            from,
            amount,
            program,
            coins,
        } => {
            spend_to_puzzle_command(data_dir, &from, amount, &program, &coins)?;
        }

        SimAction::SpendToWallet {
            program,
            params,
            to,
            amount,
        } => {
            spend_to_wallet_command(data_dir, &program, &params, &to, amount)?;
        }

        SimAction::Scan { wallet } => {
            scan_command(data_dir, &wallet)?;
        }

        SimAction::Proofs => {
            proofs_command(data_dir)?;
        }

        SimAction::Observer { action } => {
            observer_command(data_dir, action)?;
        }

        SimAction::OfferCreate {
            maker,
            offer,
            request,
            request_tail,
            coins,
        } => {
            offer_create_command(
                data_dir,
                &maker,
                offer,
                request,
                request_tail.as_deref(),
                &coins,
            )?;
        }

        SimAction::OfferTake {
            taker,
            offer_id,
            coins,
        } => {
            offer_take_command(data_dir, &taker, offer_id, &coins)?;
        }

        SimAction::OfferList => {
            offer_list_command(data_dir)?;
        }
    }

    Ok(())
}

fn faucet_command(
    data_dir: &Path,
    wallet_name: &str,
    amount: u64,
    count: u32,
    tail_hex: Option<String>,
    use_delegated: bool,
) -> Result<(), ClvmZkError> {
    let mut state = SimulatorState::load(data_dir)?;

    // parse tail_hash if provided
    let tail_hash: Option<[u8; 32]> = match &tail_hex {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str)
                .map_err(|e| ClvmZkError::InvalidProgram(format!("invalid tail hex: {}", e)))?;
            if bytes.len() != 32 {
                return Err(ClvmZkError::InvalidProgram(format!(
                    "tail must be 32 bytes (64 hex chars), got {} bytes",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(arr)
        }
        None => None,
    };

    // ensure wallet exists
    if !state.wallets.contains_key(wallet_name) {
        return Err(ClvmZkError::InvalidProgram(format!(
            "wallet '{}' not found. create it first with: sim wallet {} create",
            wallet_name, wallet_name
        )));
    }

    // create puzzle (faucet or delegated)
    let (program, puzzle_hash) = if use_delegated {
        crate::protocol::create_delegated_puzzle()?
    } else {
        create_faucet_puzzle(amount)
    };

    // generate coins for the wallet
    let wallet = state.wallets.get_mut(wallet_name).unwrap();
    let mut total_funded = 0;

    for _ in 0..count {
        // Use HD wallet to create new coin (with optional tail_hash for CATs)
        let wallet_coin = wallet
            .create_coin_with_tail(puzzle_hash, amount, program.clone(), tail_hash)
            .map_err(|e| ClvmZkError::InvalidProgram(format!("HD wallet error: {}", e)))?;

        // add coin to global simulator state
        let coin = wallet_coin.to_private_coin();
        let secrets = wallet_coin.secrets();
        let coin_type = if tail_hash.is_some() {
            CoinType::Cat
        } else {
            CoinType::Regular
        };
        state.simulator.add_coin(
            coin,
            secrets,
            CoinMetadata {
                owner: wallet_name.to_string(),
                coin_type,
                notes: match &tail_hex {
                    Some(t) => format!("faucet CAT:{}", &t[..8]),
                    None => "faucet".to_string(),
                },
            },
        );

        wallet.coins.push(wallet_coin);
        total_funded += amount;
    }

    state.faucet_nonce += count as u64;
    state.save(data_dir)?;

    let asset_str = match &tail_hex {
        Some(t) => format!("CAT:{}", &t[..8.min(t.len())]),
        None => "XCH".to_string(),
    };
    println!(
        "funded wallet '{}' with {} {} coins of {} each (total: {})",
        wallet_name, count, asset_str, amount, total_funded
    );

    Ok(())
}

fn wallet_command(data_dir: &Path, name: &str, action: WalletAction) -> Result<(), ClvmZkError> {
    let mut state = SimulatorState::load(data_dir)?;

    match action {
        WalletAction::Create => {
            if state.wallets.contains_key(name) {
                return Err(ClvmZkError::InvalidProgram(format!(
                    "wallet '{}' already exists",
                    name
                )));
            }

            // Generate proper cryptographic seed (32 bytes)
            let mut seed = vec![0u8; 32];
            thread_rng().fill_bytes(&mut seed);

            // Derive encryption keys from seed
            let hd_wallet = CLVMHDWallet::from_seed(&seed, Network::Testnet)
                .map_err(|e| ClvmZkError::InvalidProgram(format!("HD wallet error: {}", e)))?;

            let account_keys = hd_wallet.derive_account(0).map_err(|e| {
                ClvmZkError::InvalidProgram(format!("Account derivation error: {}", e))
            })?;

            // Get stealth address from account keys
            let stealth_address = account_keys.stealth_keys.stealth_address();

            // derive x25519 encryption keys from seed (HD wallet compatible)
            // (stealth uses hash-based derivation, x25519 just encrypts the nonce to receiver)
            let note_encryption_private: [u8; 32] = {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(b"note_encryption_v1");
                hasher.update(&seed);
                hasher.finalize().into()
            };
            let note_encryption_public = x25519_dalek::PublicKey::from(
                &x25519_dalek::StaticSecret::from(note_encryption_private),
            )
            .to_bytes();

            let wallet = WalletData {
                name: name.to_string(),
                seed,
                network: Network::Testnet, // Default to testnet for simulator
                account_index: 0,          // Use account 0 for simplicity
                next_coin_index: 0,        // Start from coin index 0
                coins: Vec::new(),
                stealth_view_pubkey: Some(stealth_address.view_pubkey.to_vec()),
                stealth_spend_pubkey: Some(stealth_address.spend_pubkey.to_vec()),
                note_encryption_public: Some(note_encryption_public),
                note_encryption_private: Some(note_encryption_private),
            };

            state.wallets.insert(name.to_string(), wallet);
            state.save(data_dir)?;

            println!("created wallet '{}'", name);
            println!(
                "stealth address: {}",
                hex::encode(stealth_address.to_bytes())
            );
        }

        WalletAction::Show => {
            let wallet = state.wallets.get(name).ok_or_else(|| {
                ClvmZkError::InvalidProgram(format!("wallet '{}' not found", name))
            })?;

            let total_balance: u64 = wallet
                .coins
                .iter()
                .filter(|c| !c.spent)
                .map(|c| c.amount())
                .sum();

            let unspent_count = wallet.coins.iter().filter(|c| !c.spent).count();
            let spent_count = wallet.coins.iter().filter(|c| c.spent).count();

            println!("wallet: {}", name);
            println!("seed: {}", hex::encode(&wallet.seed));
            println!("network: {:?}", wallet.network);
            println!("account: {}", wallet.account_index);
            println!("next_coin_index: {}", wallet.next_coin_index);
            println!("balance: {}", total_balance);
            println!("coins: {} unspent, {} spent", unspent_count, spent_count);
        }

        WalletAction::Coins => {
            let wallet = state.wallets.get(name).ok_or_else(|| {
                ClvmZkError::InvalidProgram(format!("wallet '{}' not found", name))
            })?;

            println!("coins in wallet '{}':", name);
            for (i, coin) in wallet.coins.iter().enumerate() {
                let status = if coin.spent { "spent" } else { "unspent" };
                let serial_number = coin.serial_number();
                println!(
                    "  {}. {} {} (serial: {}...)",
                    i,
                    coin.amount(),
                    status,
                    hex::encode(&serial_number[0..8])
                );
            }
        }

        WalletAction::Unspent => {
            let wallet = state.wallets.get(name).ok_or_else(|| {
                ClvmZkError::InvalidProgram(format!("wallet '{}' not found", name))
            })?;

            let unspent_coins: Vec<(usize, &WalletCoinWrapper)> = wallet
                .coins
                .iter()
                .enumerate()
                .filter(|(_, coin)| !coin.spent)
                .collect();

            if unspent_coins.is_empty() {
                println!("no unspent coins in wallet '{}'", name);
                return Ok(());
            }

            println!(
                "unspent coins in wallet '{}' (use indices for --coins):",
                name
            );
            let mut total = 0u64;
            for (i, coin) in &unspent_coins {
                let serial_number = coin.serial_number();
                println!(
                    "  [{}] {} (serial: {}...)",
                    i,
                    coin.amount(),
                    hex::encode(&serial_number[0..8])
                );
                total += coin.amount();
            }

            println!("total unspent: {}", total);
        }

        WalletAction::Balance => {
            let wallet = state.wallets.get(name).ok_or_else(|| {
                ClvmZkError::InvalidProgram(format!("wallet '{}' not found", name))
            })?;

            let total_balance: u64 = wallet
                .coins
                .iter()
                .filter(|c| !c.spent)
                .map(|c| c.amount())
                .sum();

            let unspent_count = wallet.coins.iter().filter(|c| !c.spent).count();

            println!("{}", total_balance);
            if unspent_count > 0 {
                println!("({} unspent coins)", unspent_count);
            } else {
                println!("(no unspent coins)");
            }
        }

        WalletAction::ExportViewingKey => {
            let wallet = state.wallets.get(name).ok_or_else(|| {
                ClvmZkError::InvalidProgram(format!("wallet '{}' not found", name))
            })?;

            let hd_wallet = wallet
                .get_hd_wallet()
                .map_err(|e| ClvmZkError::InvalidProgram(format!("HD wallet error: {}", e)))?;

            let account = hd_wallet
                .derive_account(wallet.account_index)
                .map_err(|e| {
                    ClvmZkError::InvalidProgram(format!("Account derivation error: {}", e))
                })?;

            let viewing_key = account.export_viewing_key();

            println!(
                "viewing key for wallet '{}' (account {}):",
                name, wallet.account_index
            );
            println!("key: {}", hex::encode(viewing_key.key));
            println!("account: {}", viewing_key.account_index);
            println!("network: {:?}", viewing_key.network);
            println!();
            println!("to create observer wallet:");
            println!(
                "  sim observer create {}_observer --viewing-key {}",
                name,
                hex::encode(viewing_key.key)
            );
        }
    }

    Ok(())
}

fn status_command(data_dir: &Path) -> Result<(), ClvmZkError> {
    let state = SimulatorState::load(data_dir)?;

    println!("simulator status:");
    println!("data directory: {}", data_dir.display());
    println!("wallets: {}", state.wallets.len());
    println!("faucet nonce: {}", state.faucet_nonce);

    let total_coins: usize = state.wallets.values().map(|w| w.coins.len()).sum();
    let total_unspent: usize = state
        .wallets
        .values()
        .flat_map(|w| &w.coins)
        .filter(|c| !c.spent)
        .count();

    println!("total coins: {} ({} unspent)", total_coins, total_unspent);
    println!("saved proofs: {}", state.spend_bundles.len());

    Ok(())
}

fn wallets_command(data_dir: &Path) -> Result<(), ClvmZkError> {
    let state = SimulatorState::load(data_dir)?;

    if state.wallets.is_empty() {
        println!("no wallets found. create one with: sim wallet <name> create");
        return Ok(());
    }

    println!("wallets:");
    for (name, wallet) in &state.wallets {
        let balance: u64 = wallet
            .coins
            .iter()
            .filter(|c| !c.spent)
            .map(|c| c.amount())
            .sum();

        let unspent = wallet.coins.iter().filter(|c| !c.spent).count();

        println!("  {}: balance={}, coins={}", name, balance, unspent);
    }

    Ok(())
}

// Helper functions
fn create_faucet_puzzle(_amount: u64) -> (String, [u8; 32]) {
    let program = "(mod () 1)".to_string();
    let hash =
        compile_chialisp_template_hash_default(&program).expect("faucet puzzle compilation failed");
    (program, hash)
}

fn decode_clvm_output(output_bytes: &[u8]) -> Option<String> {
    // Try to parse the CLVM output and decode it as a number if possible
    let mut parser = ClvmParser::new(output_bytes);
    match parser.parse() {
        Ok(clvm_value) => {
            // Try to convert to a number first
            if let Ok(number) = atom_to_number(&clvm_value) {
                Some(number.to_string())
            } else {
                // If not a simple number, show the structure
                Some(format!("{:?}", clvm_value))
            }
        }
        Err(_) => {
            // If parsing failed, just show as hex
            None
        }
    }
}

fn send_command(
    data_dir: &Path,
    from: &str,
    to: &str,
    amount: u64,
    coin_indices: &str,
    stealth_mode: &str,
) -> Result<(), ClvmZkError> {
    // nullifier mode only (signature mode removed)
    let _ = stealth_mode; // ignored for now, always nullifier
    let mut state = SimulatorState::load(data_dir)?;

    // validate wallets exist
    let from_wallet = state.wallets.get(from).ok_or_else(|| {
        ClvmZkError::InvalidProgram(format!("source wallet '{}' not found", from))
    })?;

    if !state.wallets.contains_key(to) {
        return Err(ClvmZkError::InvalidProgram(format!(
            "destination wallet '{}' not found",
            to
        )));
    }

    // parse coin indices or handle auto selection
    let indices = if coin_indices.trim().to_lowercase() == "auto" {
        // automatic coin selection - find minimal coins to cover amount
        let mut selected_indices = Vec::new();
        let mut selected_amount = 0u64;

        // sort coins by amount (descending) for better selection
        let mut coin_choices: Vec<(usize, &WalletCoinWrapper)> = from_wallet
            .coins
            .iter()
            .enumerate()
            .filter(|(_, coin)| !coin.spent)
            .collect();
        coin_choices.sort_by(|a, b| b.1.amount().cmp(&a.1.amount()));

        // greedily select coins until we have enough
        for (index, coin) in coin_choices {
            if selected_amount >= amount {
                break;
            }
            selected_indices.push(index);
            selected_amount += coin.amount();
        }

        if selected_amount < amount {
            return Err(ClvmZkError::InvalidProgram(format!(
                "insufficient funds: need {}, have {} in unspent coins",
                amount, selected_amount
            )));
        }

        println!(
            "auto-selected coins: {:?} (total: {})",
            selected_indices, selected_amount
        );
        selected_indices
    } else {
        // manual coin selection
        let parsed_indices: Result<Vec<usize>, _> = coin_indices
            .split(',')
            .map(|s| s.trim().parse::<usize>())
            .collect();

        parsed_indices
            .map_err(|e| ClvmZkError::InvalidProgram(format!("invalid coin indices format: {e}")))?
    };

    // validate indices and get coins to spend
    let mut coins_to_spend = Vec::new();
    let mut total_input = 0;

    for &index in &indices {
        if index >= from_wallet.coins.len() {
            return Err(ClvmZkError::InvalidProgram(format!(
                "coin index {} out of range",
                index
            )));
        }

        let coin = &from_wallet.coins[index];
        if coin.spent {
            return Err(ClvmZkError::InvalidProgram(format!(
                "coin {} is already spent",
                index
            )));
        }

        // convert wallet coin to protocol coin for spending, keeping secrets
        let private_coin = coin.to_private_coin();
        let secrets = coin.secrets().clone();
        coins_to_spend.push((private_coin, coin.program.clone(), secrets));
        total_input += coin.amount();
    }

    // validate sufficient balance
    if total_input < amount {
        return Err(ClvmZkError::InvalidProgram(format!(
            "insufficient balance: need {}, have {}",
            amount, total_input
        )));
    }

    println!(
        "spending {} coins with total value {} to send {}",
        indices.len(),
        total_input,
        amount
    );

    // spend coins using persistent simulator (v2.0)
    let tx_result = state.simulator.spend_coins(coins_to_spend);

    match tx_result {
        Ok(tx) => {
            println!("transaction successful: {}", tx);

            // save spend bundles (proofs) to state
            for bundle in &tx.spend_bundles {
                state.spend_bundles.push(bundle.clone());
                println!(
                    "saved proof: {} bytes (nullifier: {})",
                    bundle.proof_size(),
                    &bundle.nullifier_hex()[..16]
                );
            }

            // update wallet states
            let from_wallet_mut = state.wallets.get_mut(from).unwrap();

            // mark spent coins as spent
            for &index in &indices {
                from_wallet_mut.coins[index].spent = true;
            }

            // create new coin for recipient if amount > 0
            if amount > 0 {
                let to_wallet = state.wallets.get_mut(to).unwrap();

                // Get recipient's stealth address
                let recipient_stealth = {
                    let view_pub = to_wallet.stealth_view_pubkey.as_ref().ok_or_else(|| {
                        ClvmZkError::InvalidProgram(format!(
                            "recipient wallet '{}' has no stealth address (old wallet, recreate it)",
                            to
                        ))
                    })?;
                    let spend_pub = to_wallet.stealth_spend_pubkey.as_ref().ok_or_else(|| {
                        ClvmZkError::InvalidProgram(format!(
                            "recipient wallet '{}' has no stealth address",
                            to
                        ))
                    })?;
                    let mut view_arr = [0u8; 32];
                    let mut spend_arr = [0u8; 32];
                    // stealth addresses now use 32-byte hash-based pubkeys
                    if view_pub.len() == 32 {
                        view_arr.copy_from_slice(view_pub);
                    } else {
                        // legacy 33-byte compressed EC pubkey - take first 32 bytes
                        view_arr.copy_from_slice(&view_pub[..32]);
                    }
                    if spend_pub.len() == 32 {
                        spend_arr.copy_from_slice(spend_pub);
                    } else {
                        spend_arr.copy_from_slice(&spend_pub[..32]);
                    }
                    crate::wallet::StealthAddress {
                        view_pubkey: view_arr,
                        spend_pubkey: spend_arr,
                    }
                };

                // create stealth payment (nullifier mode) - derives shared_secret via hash
                let sender_hd = state
                    .wallets
                    .get(from)
                    .unwrap()
                    .get_hd_wallet()
                    .map_err(|e| ClvmZkError::InvalidProgram(format!("hd wallet error: {}", e)))?;
                let sender_account = sender_hd.derive_account(0).map_err(|e| {
                    ClvmZkError::InvalidProgram(format!("account derivation error: {}", e))
                })?;
                let stealth_payment = crate::wallet::create_stealth_payment_hd(
                    &sender_account.stealth_keys,
                    0, // nonce_index
                    &recipient_stealth,
                );

                // derive coin secrets using nullifier mode (fast proving)
                let secrets = crate::wallet::derive_nullifier_secrets_from_shared_secret(
                    &stealth_payment.shared_secret,
                );

                // Create coin with stealth-derived puzzle_hash and deterministic secrets
                let puzzle_hash = stealth_payment.puzzle_hash;
                let serial_commitment =
                    secrets.serial_commitment(crate::crypto_utils::hash_data_default);
                let coin =
                    crate::protocol::PrivateCoin::new(puzzle_hash, amount, serial_commitment);

                // add coin to global simulator state with stealth nonce and puzzle_source
                state.simulator.add_coin_with_stealth_nonce(
                    coin,
                    &secrets,
                    stealth_payment.nonce,
                    stealth_payment.puzzle_source.clone(),
                    CoinMetadata {
                        owner: to.to_string(),
                        coin_type: CoinType::Regular,
                        notes: format!("stealth payment from {} (nullifier mode)", from),
                    },
                );

                // NOTE: coin is NOT added to recipient's wallet directly
                // recipient must run 'sim scan' to discover via stealth scanning
                println!(
                    "created stealth payment for '{}' with amount {} [nullifier mode] (recipient must scan to receive)",
                    to, amount
                );
            }

            // handle change if any
            let change = total_input - amount;
            if change > 0 {
                let from_wallet_mut = state.wallets.get_mut(from).unwrap();
                let (program, puzzle_hash) = create_faucet_puzzle(change);

                // Use HD wallet to create change coin
                let wallet_coin = from_wallet_mut
                    .create_coin(puzzle_hash, change, program)
                    .map_err(|e| ClvmZkError::InvalidProgram(format!("HD wallet error: {}", e)))?;

                // add change coin to global simulator state
                let coin = wallet_coin.to_private_coin();
                let secrets = wallet_coin.secrets();
                state.simulator.add_coin(
                    coin,
                    secrets,
                    CoinMetadata {
                        owner: from.to_string(),
                        coin_type: CoinType::Regular,
                        notes: "change".to_string(),
                    },
                );

                from_wallet_mut.coins.push(wallet_coin);
                println!("created change coin for '{}' with amount {}", from, change);
            }

            // save updated state
            state.save(data_dir)?;

            println!(
                "sent {} from '{}' to '{}' (change: {})",
                amount, from, to, change
            );
        }

        Err(e) => {
            return Err(ClvmZkError::ProofGenerationFailed(format!(
                "transaction failed: {:?}",
                e
            )));
        }
    }

    Ok(())
}

fn scan_command(data_dir: &Path, wallet_name: &str) -> Result<(), ClvmZkError> {
    let mut state = SimulatorState::load(data_dir)?;

    // Get wallet and derive stealth view key
    let (view_key, existing_puzzle_hashes) = {
        let wallet = state.wallets.get(wallet_name).ok_or_else(|| {
            ClvmZkError::InvalidProgram(format!("wallet '{}' not found", wallet_name))
        })?;

        // Derive stealth keys from seed
        let hd_wallet = crate::wallet::CLVMHDWallet::from_seed(&wallet.seed, wallet.network)
            .map_err(|e| ClvmZkError::InvalidProgram(format!("wallet error: {}", e)))?;
        let account_keys = hd_wallet
            .derive_account(wallet.account_index)
            .map_err(|e| ClvmZkError::InvalidProgram(format!("key derivation error: {}", e)))?;

        let view_key = account_keys.stealth_keys.view_only();

        // Get existing puzzle hashes to avoid duplicates
        let existing: std::collections::HashSet<[u8; 32]> =
            wallet.coins.iter().map(|c| c.puzzle_hash()).collect();

        (view_key, existing)
    };

    // Get stealth-scannable coins from simulator (now returns nonces instead of ephemeral pubkeys)
    let scannable_coins = state.simulator.get_stealth_scannable_coins();
    println!(
        "scanning {} stealth coins for wallet '{}'...",
        scannable_coins.len(),
        wallet_name
    );

    // scan each coin using hash-based stealth (try_scan_with_nonce)
    let mut found_count = 0;
    let mut total_amount = 0u64;

    for (puzzle_hash, nonce, info) in &scannable_coins {
        // Skip if already in wallet
        if existing_puzzle_hashes.contains(*puzzle_hash) {
            println!(
                "  found coin {} (already in wallet, skipping)",
                hex::encode(&puzzle_hash[..4])
            );
            continue;
        }

        // try to scan this coin with the nonce
        let scanned = match view_key.try_scan_with_nonce(puzzle_hash, nonce) {
            Some(s) => s,
            None => continue, // not our coin
        };

        // found a coin!
        let coin_info = Some(*info);

        if let Some(info) = coin_info {
            println!(
                "  found stealth coin: {} mojos [nullifier mode]",
                info.coin.amount
            );

            // derive secrets using nullifier mode (fast proving)
            let secrets =
                crate::wallet::derive_nullifier_secrets_from_shared_secret(&scanned.shared_secret);

            // reconstruct the coin for the wallet
            let coin = info.coin.clone();

            // use puzzle_source from stealth scanning
            let program = scanned.puzzle_source.clone();

            let wallet_coin = crate::wallet::WalletPrivateCoin {
                coin,
                secrets,
                account_index: 0, // stealth coins don't have HD derivation path
                coin_index: 0,
            };

            let wrapper = WalletCoinWrapper {
                wallet_coin,
                program,
                spent: false,
            };

            // Add to wallet
            let wallet = state.wallets.get_mut(wallet_name).unwrap();
            wallet.coins.push(wrapper);
            found_count += 1;
            total_amount += info.coin.amount;
        }
    }

    state.save(data_dir)?;

    println!("\nscan complete:");
    println!("  found {} new stealth coins", found_count);
    println!("  total value: {} mojos", total_amount);

    Ok(())
}

fn proofs_command(data_dir: &Path) -> Result<(), ClvmZkError> {
    let state = SimulatorState::load(data_dir)?;

    if state.spend_bundles.is_empty() {
        println!("no proofs saved yet");
        return Ok(());
    }

    println!("saved proofs: {}", state.spend_bundles.len());
    println!();

    for (i, bundle) in state.spend_bundles.iter().enumerate() {
        println!("proof #{}", i);
        println!("  nullifier: {}", bundle.nullifier_hex());
        println!("  proof size: {} bytes", bundle.proof_size());
        println!("  conditions size: {} bytes", bundle.conditions_size());
        println!();
    }

    let total_proof_bytes: usize = state.spend_bundles.iter().map(|b| b.proof_size()).sum();
    println!("total proof data: {} bytes", total_proof_bytes);

    Ok(())
}

// ============================================================================
// General Purpose Puzzle Commands
// ============================================================================

fn spend_to_puzzle_command(
    data_dir: &Path,
    from: &str,
    amount: u64,
    program: &str,
    coins: &str,
) -> Result<(), ClvmZkError> {
    let mut state = SimulatorState::load(data_dir)?;

    // ensure source wallet exists
    if !state.wallets.contains_key(from) {
        return Err(ClvmZkError::ProofGenerationFailed(format!(
            "wallet '{}' not found",
            from
        )));
    }

    // create puzzle hash from the program
    let puzzle_hash = Sha256::digest(program.as_bytes()).into();

    // get spendable coins from source wallet
    let spend_coins = parse_coin_indices(coins, &state.wallets[from])?;

    let total_input: u64 = spend_coins.iter().map(|c| c.amount()).sum();
    if total_input < amount {
        return Err(ClvmZkError::ProofGenerationFailed(format!(
            "insufficient funds: need {}, have {}",
            amount, total_input
        )));
    }

    // spend coins using persistent simulator
    match state.simulator.spend_coins(
        spend_coins
            .iter()
            .map(|wc| {
                // convert wallet coin to protocol coin for spending
                let coin = wc.to_private_coin();
                let secrets = wc.secrets().clone();
                (coin, wc.program.clone(), secrets)
            })
            .collect(),
    ) {
        Ok(tx) => {
            // save spend bundles (proofs) to state
            for bundle in &tx.spend_bundles {
                state.spend_bundles.push(bundle.clone());
                println!(
                    "saved proof: {} bytes (nullifier: {})",
                    bundle.proof_size(),
                    &bundle.nullifier_hex()[..16]
                );
            }

            // mark coins as spent
            let from_wallet = state.wallets.get_mut(from).unwrap();
            for coin in &spend_coins {
                let coin_serial = coin.serial_number();
                if let Some(wallet_coin) = from_wallet
                    .coins
                    .iter_mut()
                    .find(|c| c.serial_number() == coin_serial)
                {
                    wallet_coin.spent = true;
                }
            }

            // create new puzzle coin with proper CoinSecrets
            let (coin, secrets) = PrivateCoin::new_with_secrets(puzzle_hash, amount);

            let puzzle_coin = PuzzleCoin {
                puzzle_hash,
                amount,
                program: program.to_string(),
                secrets: secrets.clone(),
            };

            // add puzzle coin to global simulator state
            state.simulator.add_coin(
                coin,
                &secrets,
                CoinMetadata {
                    owner: "puzzle".to_string(),
                    coin_type: CoinType::Regular,
                    notes: format!("puzzle: {}", program),
                },
            );

            // store puzzle coin in simulator state
            if state.puzzle_coins.is_none() {
                state.puzzle_coins = Some(Vec::new());
            }
            state
                .puzzle_coins
                .as_mut()
                .unwrap()
                .push(puzzle_coin.clone());

            // handle change
            let change = total_input - amount;
            if change > 0 {
                let from_wallet_mut = state.wallets.get_mut(from).unwrap();
                let (change_program, change_puzzle_hash) = create_faucet_puzzle(change);

                // Use HD wallet to create change coin
                let wallet_coin = from_wallet_mut
                    .create_coin(change_puzzle_hash, change, change_program)
                    .map_err(|e| ClvmZkError::InvalidProgram(format!("HD wallet error: {}", e)))?;

                // add change coin to global simulator state
                let coin = wallet_coin.to_private_coin();
                let secrets = wallet_coin.secrets();
                state.simulator.add_coin(
                    coin,
                    secrets,
                    CoinMetadata {
                        owner: from.to_string(),
                        coin_type: CoinType::Regular,
                        notes: "change".to_string(),
                    },
                );

                from_wallet_mut.coins.push(wallet_coin);
                println!("created change coin for '{}' with amount {}", from, change);
            }

            state.save(data_dir)?;
            println!(
                "locked {} in puzzle coin (serial: {}..., program: {})",
                amount,
                hex::encode(&puzzle_coin.secrets.serial_number()[0..8]),
                program
            );
        }

        Err(e) => {
            return Err(ClvmZkError::ProofGenerationFailed(format!(
                "transaction failed: {:?}",
                e
            )));
        }
    }

    Ok(())
}

fn spend_to_wallet_command(
    data_dir: &Path,
    program: &str,
    params: &str,
    to: &str,
    amount: u64,
) -> Result<(), ClvmZkError> {
    let mut state = SimulatorState::load(data_dir)?;

    // ensure destination wallet exists
    if !state.wallets.contains_key(to) {
        return Err(ClvmZkError::ProofGenerationFailed(format!(
            "wallet '{}' not found",
            to
        )));
    }

    // find puzzle coin with matching program and sufficient amount
    let puzzle_coin = {
        let puzzle_coins = state.puzzle_coins.as_ref().ok_or_else(|| {
            ClvmZkError::ProofGenerationFailed("no puzzle coins available".to_string())
        })?;

        puzzle_coins
            .iter()
            .find(|c| c.program == program && c.amount >= amount)
            .cloned()
            .ok_or_else(|| {
                ClvmZkError::ProofGenerationFailed(format!(
                    "no suitable puzzle coin found for program '{}' with amount {}",
                    program, amount
                ))
            })?
    };

    // parse program parameters (simple comma-separated strings for now)
    let param_values: Vec<&str> = params.split(",").map(|s| s.trim()).collect();
    let _program_params: Vec<ProgramParameter> = param_values
        .iter()
        .map(|v| ProgramParameter::from_bytes(v.as_bytes()))
        .collect();

    // reconstruct PrivateCoin from puzzle_coin data
    let coin = PrivateCoin::new(
        puzzle_coin.puzzle_hash,
        puzzle_coin.amount,
        puzzle_coin
            .secrets
            .serial_commitment(crate::crypto_utils::hash_data_default),
    );

    // spend using persistent simulator
    match state.simulator.spend_coins(vec![(
        coin,
        puzzle_coin.program.clone(),
        puzzle_coin.secrets.clone(),
    )]) {
        Ok(tx) => {
            // save spend bundles (proofs) to state
            for bundle in &tx.spend_bundles {
                state.spend_bundles.push(bundle.clone());
                println!(
                    "saved proof: {} bytes (nullifier: {})",
                    bundle.proof_size(),
                    &bundle.nullifier_hex()[..16]
                );
            }

            // remove the spent puzzle coin
            let puzzle_coins = state.puzzle_coins.as_mut().unwrap();
            let spent_serial = puzzle_coin.secrets.serial_number();
            puzzle_coins.retain(|c| c.secrets.serial_number() != spent_serial);

            // create new coin for destination wallet
            let to_wallet = state.wallets.get_mut(to).unwrap();
            let (wallet_program, wallet_puzzle_hash) = create_faucet_puzzle(amount);
            // Use HD wallet to create new coin for destination wallet
            let wallet_coin = to_wallet
                .create_coin(wallet_puzzle_hash, amount, wallet_program)
                .map_err(|e| ClvmZkError::InvalidProgram(format!("HD wallet error: {}", e)))?;

            // add coin to global simulator state
            let coin = wallet_coin.to_private_coin();
            let secrets = wallet_coin.secrets();
            state.simulator.add_coin(
                coin,
                secrets,
                CoinMetadata {
                    owner: to.to_string(),
                    coin_type: CoinType::Regular,
                    notes: "unlocked from puzzle".to_string(),
                },
            );

            to_wallet.coins.push(wallet_coin);

            // handle change if puzzle coin had more than requested amount
            let change = puzzle_coin.amount - amount;
            if change > 0 {
                let change_puzzle_hash = Sha256::digest(puzzle_coin.program.as_bytes()).into();
                let (coin, secrets) = PrivateCoin::new_with_secrets(change_puzzle_hash, change);

                let change_puzzle_coin = PuzzleCoin {
                    puzzle_hash: change_puzzle_hash,
                    amount: change,
                    program: puzzle_coin.program.clone(),
                    secrets: secrets.clone(),
                };

                // add change puzzle coin to global simulator state
                state.simulator.add_coin(
                    coin,
                    &secrets,
                    CoinMetadata {
                        owner: "puzzle".to_string(),
                        coin_type: CoinType::Regular,
                        notes: format!("puzzle change: {}", puzzle_coin.program),
                    },
                );

                puzzle_coins.push(change_puzzle_coin);
                println!("created change puzzle coin with amount {}", change);
            }

            state.save(data_dir)?;
            println!(
                "unlocked {} from puzzle coin to wallet '{}' (program: {})",
                amount, to, program
            );
        }

        Err(e) => {
            return Err(ClvmZkError::ProofGenerationFailed(format!(
                "transaction failed: {:?}",
                e
            )));
        }
    }

    Ok(())
}

fn observer_command(data_dir: &Path, action: ObserverAction) -> Result<(), ClvmZkError> {
    use crate::wallet::Network;

    let mut state = SimulatorState::load(data_dir)?;

    match action {
        ObserverAction::Create {
            name,
            viewing_key,
            account,
            network,
        } => {
            if state.observer_wallets.contains_key(&name) {
                return Err(ClvmZkError::InvalidProgram(format!(
                    "observer wallet \"{}\" already exists",
                    name
                )));
            }

            let viewing_key_bytes = hex::decode(&viewing_key).map_err(|e| {
                ClvmZkError::InvalidProgram(format!("invalid hex viewing key: {}", e))
            })?;

            if viewing_key_bytes.len() != 32 {
                return Err(ClvmZkError::InvalidProgram(
                    "viewing key must be 32 bytes".to_string(),
                ));
            }

            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(&viewing_key_bytes);

            let network = match network.to_lowercase().as_str() {
                "mainnet" => Network::Mainnet,
                "testnet" => Network::Testnet,
                _ => {
                    return Err(ClvmZkError::InvalidProgram(
                        "network must be \"mainnet\" or \"testnet\"".to_string(),
                    ))
                }
            };

            let observer_wallet = ObserverWalletData {
                name: name.clone(),
                viewing_key: key_array,
                account_index: account,
                network,
                discovered_coins: Vec::new(),
            };

            state.observer_wallets.insert(name.clone(), observer_wallet);
            state.save(data_dir)?;

            println!("created observer wallet \"{}\"", name);
        }

        ObserverAction::Show { name } => {
            let observer = state.observer_wallets.get(&name).ok_or_else(|| {
                ClvmZkError::InvalidProgram(format!("observer wallet \"{}\" not found", name))
            })?;

            println!("observer wallet: {}", name);
            println!("viewing key: {}", hex::encode(observer.viewing_key));
            println!("account: {}", observer.account_index);
            println!("network: {:?}", observer.network);
            println!("discovered coins: {}", observer.discovered_coins.len());
        }

        ObserverAction::List => {
            if state.observer_wallets.is_empty() {
                println!("no observer wallets found");
            } else {
                println!("observer wallets:");
                for (name, observer) in &state.observer_wallets {
                    println!(
                        "  {}: {} coins discovered",
                        name,
                        observer.discovered_coins.len()
                    );
                }
            }
        }

        ObserverAction::Scan { name, max_index } => {
            let _ = (name, max_index);

            return Err(ClvmZkError::InvalidProgram(
                "observer scanning not supported - requires coinsecrets backup".to_string(),
            ));
        }
    }

    Ok(())
}

// Offer commands - create conditional spend proof for atomic swaps
fn offer_create_command(
    data_dir: &Path,
    maker_name: &str,
    offered_amount: u64,
    requested_amount: u64,
    request_tail_hex: Option<&str>,
    coins: &str,
) -> Result<(), ClvmZkError> {
    let mut state = SimulatorState::load(data_dir)?;

    // parse requested tail_hash if provided
    let requested_tail_hash: [u8; 32] = match request_tail_hex {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str).map_err(|e| {
                ClvmZkError::InvalidProgram(format!("invalid request-tail hex: {}", e))
            })?;
            if bytes.len() != 32 {
                return Err(ClvmZkError::InvalidProgram(format!(
                    "request-tail must be 32 bytes (64 hex chars), got {} bytes",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        None => [0u8; 32], // default to XCH
    };

    // get wallet
    let wallet = state
        .wallets
        .get(maker_name)
        .ok_or_else(|| ClvmZkError::InvalidProgram(format!("wallet '{}' not found", maker_name)))?;

    // parse coins - for offer creation we need exactly one coin
    let spend_coins = parse_coin_indices(coins, wallet)?;
    if spend_coins.len() != 1 {
        return Err(ClvmZkError::InvalidProgram(
            "offer creation requires exactly one coin (for now)".to_string(),
        ));
    }
    let spend_coin = &spend_coins[0];
    let total_input = spend_coin.amount();

    if total_input < offered_amount {
        return Err(ClvmZkError::InvalidProgram(format!(
            "insufficient funds: coin has {}, offering {}",
            total_input, offered_amount
        )));
    }

    println!("generating conditional offer proof (this may take a moment)...");

    // use maker's static encryption public key for payment
    let maker_pubkey = wallet.note_encryption_public.ok_or_else(|| {
        ClvmZkError::InvalidProgram(format!(
            "maker wallet '{}' has no encryption key (old wallet, recreate it)",
            maker_name
        ))
    })?;

    // compute change amount
    let change_amount = total_input - offered_amount;

    // generate change coin secrets
    let mut change_serial = [0u8; 32];
    let mut change_rand = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut change_serial);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut change_rand);

    // use delegated puzzle for maker's change
    let (_, change_puzzle) = crate::protocol::create_delegated_puzzle()?;

    // get settlement assertion puzzle
    let (_assertion_program, _assertion_hash) =
        crate::protocol::create_settlement_assertion_puzzle().map_err(|e| {
            ClvmZkError::InvalidProgram(format!("failed to create assertion puzzle: {:?}", e))
        })?;

    // create assertion parameters
    let assertion_params = crate::protocol::create_settlement_assertion_params(
        offered_amount,
        requested_amount,
        &maker_pubkey,
        change_amount,
        &change_puzzle,
        &change_serial,
        &change_rand,
    );

    // get delegated puzzle (settlement-specific - directly embeds assertion logic)
    let (delegated_code, delegated_hash) = crate::protocol::create_delegated_puzzle()?;

    // verify coin uses delegated puzzle
    if spend_coin.puzzle_hash() != delegated_hash {
        return Err(ClvmZkError::InvalidProgram(format!(
            "coin must use delegated puzzle for offers. expected: {}, got: {}",
            hex::encode(delegated_hash),
            hex::encode(spend_coin.puzzle_hash())
        )));
    }

    // delegated puzzle takes same 7 params as settlement assertion
    let delegated_params = assertion_params;

    // get merkle path for spend coin
    let (merkle_path, leaf_index) = state
        .simulator
        .get_merkle_path_and_index(&spend_coin.to_private_coin())
        .ok_or_else(|| ClvmZkError::InvalidProgram("coin not in merkle tree".to_string()))?;

    let merkle_root = state
        .simulator
        .get_merkle_root()
        .ok_or_else(|| ClvmZkError::InvalidProgram("merkle tree has no root".to_string()))?;

    // create conditional spend proof using delegated puzzle
    let conditional_proof = crate::protocol::Spender::create_conditional_spend(
        &spend_coin.to_private_coin(),
        &delegated_code,
        &delegated_params,
        &spend_coin.secrets(),
        merkle_path,
        merkle_root,
        leaf_index,
    )
    .map_err(|e| ClvmZkError::InvalidProgram(format!("conditional proof failed: {:?}", e)))?;

    // mark coin as spent
    let serial = spend_coin.serial_number();
    if let Some(w) = state.wallets.get_mut(maker_name) {
        for wc in &mut w.coins {
            if wc.serial_number() == serial {
                wc.spent = true;
            }
        }
    }

    // change secrets are stored in StoredOffer and added to maker's wallet during offer-take

    // store the offer
    let offer_id = state.pending_offers.len();
    state.pending_offers.push(StoredOffer {
        id: offer_id,
        maker: maker_name.to_string(),
        offered: offered_amount,
        requested: requested_amount,
        maker_pubkey,
        maker_bundle: conditional_proof.clone(),
        created_at: 0,
        change_amount,
        change_puzzle,
        change_serial,
        change_rand,
        offered_tail_hash: spend_coin.to_private_coin().tail_hash,
        requested_tail_hash,
    });

    state.save(data_dir)?;

    println!("✅ conditional offer created successfully");
    println!("   offer id: {}", offer_id);
    println!("   maker: {}", maker_name);
    println!("   offering: {} mojos", offered_amount);
    println!("   requesting: {} mojos", requested_amount);
    println!("   change: {} mojos (returned to maker)", change_amount);
    println!("   proof type: ConditionalSpend (locked until settlement)");
    println!(
        "   proof generated: {} bytes",
        conditional_proof.proof_size()
    );
    println!();
    println!("takers can view with: sim offer-list");
    println!(
        "takers can take with: sim offer-take <taker> --offer-id {} --coins <coins>",
        offer_id
    );

    Ok(())
}

fn offer_take_command(
    data_dir: &Path,
    taker_name: &str,
    offer_id: usize,
    coins: &str,
) -> Result<(), ClvmZkError> {
    let mut state = SimulatorState::load(data_dir)?;

    // get offer
    if offer_id >= state.pending_offers.len() {
        return Err(ClvmZkError::InvalidProgram("offer not found".to_string()));
    }

    let offer = state.pending_offers[offer_id].clone();

    // get taker wallet
    let wallet = state
        .wallets
        .get(taker_name)
        .ok_or_else(|| ClvmZkError::InvalidProgram(format!("wallet '{}' not found", taker_name)))?;

    // parse coins - for now require exactly one coin
    let spend_coins = parse_coin_indices(coins, wallet)?;
    if spend_coins.len() != 1 {
        return Err(ClvmZkError::InvalidProgram(
            "offer take requires exactly one coin (for now)".to_string(),
        ));
    }
    let taker_coin = &spend_coins[0];
    let total_input = taker_coin.amount();

    // validate taker's coin matches maker's requested asset type
    if taker_coin.to_private_coin().tail_hash != offer.requested_tail_hash {
        return Err(ClvmZkError::InvalidProgram(format!(
            "asset type mismatch: maker requests {:?}, taker has {:?}",
            offer.requested_tail_hash,
            taker_coin.to_private_coin().tail_hash
        )));
    }

    if total_input < offer.requested {
        return Err(ClvmZkError::InvalidProgram(format!(
            "insufficient funds: need {}, have {}",
            offer.requested, total_input
        )));
    }

    println!("generating settlement proof (this may take a moment)...");

    // generate random nonce for hash-based stealth address
    // payment_puzzle = sha256("stealth_v1" || maker_pubkey || nonce)
    let mut payment_nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut payment_nonce);

    // generate coin secrets for payment, goods, and change
    let mut payment_serial = [0u8; 32];
    let mut payment_rand = [0u8; 32];
    let mut goods_serial = [0u8; 32];
    let mut goods_rand = [0u8; 32];
    let mut change_serial = [0u8; 32];
    let mut change_rand = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut payment_serial);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut payment_rand);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut goods_serial);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut goods_rand);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut change_serial);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut change_rand);

    // use faucet puzzle for taker's goods and change
    let (_, taker_goods_puzzle) = create_faucet_puzzle(offer.offered);
    let (_, taker_change_puzzle) = create_faucet_puzzle(offer.offered);

    // get merkle path for taker's coin
    let (merkle_path, leaf_index) = state
        .simulator
        .get_merkle_path_and_index(&taker_coin.to_private_coin())
        .ok_or_else(|| ClvmZkError::InvalidProgram("coin not in merkle tree".to_string()))?;

    let merkle_root = state
        .simulator
        .get_merkle_root()
        .ok_or_else(|| ClvmZkError::InvalidProgram("merkle tree has no root".to_string()))?;

    // create settlement proof parameters
    let settlement_params = crate::protocol::SettlementParams {
        maker_proof: offer.maker_bundle.clone(),
        taker_coin: taker_coin.to_private_coin(),
        taker_secrets: taker_coin.secrets().clone(),
        taker_merkle_path: merkle_path,
        merkle_root,
        taker_leaf_index: leaf_index,
        payment_nonce,
        taker_goods_puzzle,
        taker_change_puzzle,
        payment_serial,
        payment_rand,
        goods_serial,
        goods_rand,
        change_serial,
        change_rand,
        // v2.0: tail_hash identifies asset type
        // taker coin must match maker's requested asset type
        taker_tail_hash: taker_coin.to_private_coin().tail_hash,
        // goods (what taker receives) match maker's offered asset type
        goods_tail_hash: offer.offered_tail_hash,
    };

    // generate settlement proof
    let settlement_proof = crate::protocol::prove_settlement(settlement_params)
        .map_err(|e| ClvmZkError::InvalidProgram(format!("settlement proof failed: {:?}", e)))?;

    println!("✅ settlement proof generated");

    // V2: validate BOTH proofs concurrently before processing settlement
    println!("validating maker + taker proofs concurrently...");
    #[cfg(feature = "risc0")]
    {
        use std::thread;

        // clone proof data for concurrent verification
        let maker_proof_bytes = offer.maker_bundle.zk_proof.clone();
        let taker_proof_bytes = settlement_proof.zk_proof.clone();

        // spawn verification threads (each deserializes + verifies independently)
        let maker_handle = thread::spawn(move || -> Result<(), ClvmZkError> {
            let receipt: risc0_zkvm::Receipt =
                borsh::from_slice(&maker_proof_bytes).map_err(|e| {
                    ClvmZkError::InvalidProofFormat(format!("maker receipt deserialize: {e}"))
                })?;

            receipt
                .verify(clvm_zk_risc0::CLVM_RISC0_GUEST_ID)
                .map_err(|e| {
                    ClvmZkError::VerificationFailed(format!("maker proof invalid: {e}"))
                })?;

            Ok(())
        });

        let taker_handle = thread::spawn(move || -> Result<(), ClvmZkError> {
            let receipt: risc0_zkvm::Receipt =
                borsh::from_slice(&taker_proof_bytes).map_err(|e| {
                    ClvmZkError::InvalidProofFormat(format!("taker receipt deserialize: {e}"))
                })?;

            receipt.verify(clvm_zk_risc0::SETTLEMENT_ID).map_err(|e| {
                ClvmZkError::VerificationFailed(format!("taker proof invalid: {e}"))
            })?;

            Ok(())
        });

        // wait for both verifications
        maker_handle.join().map_err(|_| {
            ClvmZkError::VerificationFailed("maker verification thread panicked".to_string())
        })??;

        taker_handle.join().map_err(|_| {
            ClvmZkError::VerificationFailed("taker verification thread panicked".to_string())
        })??;

        println!("✅ both proofs verified concurrently");

        // linkage is guaranteed by prove_settlement extracting from maker's verified journal
        // validator should check settlement_proof.output.maker_pubkey matches offer.maker_pubkey
    }

    // process settlement output: add nullifiers and commitments to simulator state
    state.simulator.process_settlement(&settlement_proof.output);

    println!("   added 2 nullifiers and 4 commitments to state");

    // 3. create taker's 3 coins with full secrets (payment, goods, change)

    // compute payment_puzzle via hash-based stealth (same as guest does)
    // payment_puzzle = sha256("stealth_v1" || maker_pubkey || nonce)
    let mut payment_puzzle_data = Vec::new();
    payment_puzzle_data.extend_from_slice(b"stealth_v1");
    payment_puzzle_data.extend_from_slice(&offer.maker_pubkey);
    payment_puzzle_data.extend_from_slice(&payment_nonce);
    let payment_puzzle = crate::crypto_utils::hash_data_default(&payment_puzzle_data);

    // calculate amounts
    let payment_amount = offer.requested;
    let goods_amount = offer.offered;
    let change_amount = taker_coin.amount() - offer.requested;

    // create 3 coins for taker's wallet
    let taker_wallet = state.wallets.get_mut(taker_name).unwrap();

    // 1. payment coin (taker → maker, asset B)
    let payment_serial_commitment = clvm_zk_core::coin_commitment::SerialCommitment::compute(
        &payment_serial,
        &payment_rand,
        crate::crypto_utils::hash_data_default,
    );
    let payment_coin = crate::protocol::PrivateCoin::new(
        payment_puzzle,
        payment_amount,
        payment_serial_commitment,
    );
    let payment_secrets =
        clvm_zk_core::coin_commitment::CoinSecrets::new(payment_serial, payment_rand);
    let payment_wallet_coin = crate::wallet::hd_wallet::WalletPrivateCoin {
        coin: payment_coin,
        secrets: payment_secrets,
        account_index: 0, // non-HD coin
        coin_index: 0,
    };
    taker_wallet.coins.push(crate::cli::WalletCoinWrapper {
        wallet_coin: payment_wallet_coin,
        program: "(mod () (q . ()))".to_string(), // placeholder program
        spent: false,
    });

    // 2. goods coin (maker → taker, asset A)
    let goods_serial_commitment = clvm_zk_core::coin_commitment::SerialCommitment::compute(
        &goods_serial,
        &goods_rand,
        crate::crypto_utils::hash_data_default,
    );
    let goods_coin = crate::protocol::PrivateCoin::new(
        taker_goods_puzzle,
        goods_amount,
        goods_serial_commitment,
    );
    let goods_secrets = clvm_zk_core::coin_commitment::CoinSecrets::new(goods_serial, goods_rand);
    let goods_wallet_coin = crate::wallet::hd_wallet::WalletPrivateCoin {
        coin: goods_coin,
        secrets: goods_secrets,
        account_index: 0,
        coin_index: 0,
    };
    taker_wallet.coins.push(crate::cli::WalletCoinWrapper {
        wallet_coin: goods_wallet_coin,
        program: "(mod () (q . ()))".to_string(),
        spent: false,
    });

    // 3. change coin (taker's leftover, asset B)
    let change_serial_commitment = clvm_zk_core::coin_commitment::SerialCommitment::compute(
        &change_serial,
        &change_rand,
        crate::crypto_utils::hash_data_default,
    );
    let change_coin = crate::protocol::PrivateCoin::new(
        taker_change_puzzle,
        change_amount,
        change_serial_commitment,
    );
    let change_secrets =
        clvm_zk_core::coin_commitment::CoinSecrets::new(change_serial, change_rand);
    let change_wallet_coin = crate::wallet::hd_wallet::WalletPrivateCoin {
        coin: change_coin,
        secrets: change_secrets,
        account_index: 0,
        coin_index: 0,
    };
    taker_wallet.coins.push(crate::cli::WalletCoinWrapper {
        wallet_coin: change_wallet_coin,
        program: "(mod () (q . ()))".to_string(),
        spent: false,
    });

    println!("   added 3 coins to taker's wallet (payment, goods, change)");

    // 4. add maker's coins to maker's wallet
    let maker_wallet = state.wallets.get_mut(&offer.maker).ok_or_else(|| {
        ClvmZkError::InvalidProgram(format!("maker wallet '{}' not found", offer.maker))
    })?;

    // 4a. maker's change coin (returned to maker, asset A)
    let maker_change_serial_commitment = clvm_zk_core::coin_commitment::SerialCommitment::compute(
        &offer.change_serial,
        &offer.change_rand,
        crate::crypto_utils::hash_data_default,
    );
    let maker_change_coin = crate::protocol::PrivateCoin::new(
        offer.change_puzzle,
        offer.change_amount,
        maker_change_serial_commitment,
    );
    let maker_change_secrets =
        clvm_zk_core::coin_commitment::CoinSecrets::new(offer.change_serial, offer.change_rand);
    let maker_change_wallet_coin = crate::wallet::hd_wallet::WalletPrivateCoin {
        coin: maker_change_coin,
        secrets: maker_change_secrets,
        account_index: 0,
        coin_index: 0,
    };
    maker_wallet.coins.push(crate::cli::WalletCoinWrapper {
        wallet_coin: maker_change_wallet_coin,
        program: "(mod () (q . ()))".to_string(),
        spent: false,
    });

    // 4b. maker's payment coin (taker → maker, asset B)
    // the payment_puzzle was derived via hash-based stealth above, amount is offer.requested
    let maker_payment_serial_commitment = clvm_zk_core::coin_commitment::SerialCommitment::compute(
        &payment_serial,
        &payment_rand,
        crate::crypto_utils::hash_data_default,
    );
    let maker_payment_coin = crate::protocol::PrivateCoin::new(
        payment_puzzle,
        payment_amount,
        maker_payment_serial_commitment,
    );
    let maker_payment_secrets =
        clvm_zk_core::coin_commitment::CoinSecrets::new(payment_serial, payment_rand);
    let maker_payment_wallet_coin = crate::wallet::hd_wallet::WalletPrivateCoin {
        coin: maker_payment_coin,
        secrets: maker_payment_secrets,
        account_index: 0,
        coin_index: 0,
    };
    maker_wallet.coins.push(crate::cli::WalletCoinWrapper {
        wallet_coin: maker_payment_wallet_coin,
        program: "(mod () (q . ()))".to_string(),
        spent: false,
    });

    println!("   added 2 coins to maker's wallet (change, payment)");

    // 5. remove offer from pending
    state.pending_offers.remove(offer_id);

    state.save(data_dir)?;

    println!("✅ offer settlement initiated");
    println!("   offer id: {}", offer_id);
    println!(
        "   maker ({}) offered: {} mojos",
        offer.maker, offer.offered
    );
    println!(
        "   taker ({}) paying: {} mojos",
        taker_name, offer.requested
    );
    println!(
        "   maker proof: {} bytes (ConditionalSpend)",
        offer.maker_bundle.proof_size()
    );

    Ok(())
}

fn offer_list_command(data_dir: &Path) -> Result<(), ClvmZkError> {
    let state = SimulatorState::load(data_dir)?;

    if state.pending_offers.is_empty() {
        println!("no pending offers");
        return Ok(());
    }

    println!("pending offers:");
    println!();
    for offer in &state.pending_offers {
        println!("  [{}] {}", offer.id, offer.maker);
        println!("      offering: {} mojos", offer.offered);
        println!("      requesting: {} mojos", offer.requested);
        println!("      proof: {} bytes", offer.maker_bundle.proof_size());
        println!("      created at block: {}", offer.created_at);
        println!();
    }

    println!("take an offer with: sim offer-take <taker> --offer-id <id> --coins <coins>");

    Ok(())
}
