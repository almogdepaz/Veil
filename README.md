# clvm-zk: Zero-Knowledge Privacy Protocol for Chia Blockchain

zero-knowledge proof system for running chia lisp (CLVM) programs privately. you can take a chialisp program, prove it executed correctly, and verify that proof without revealing the inputs or program logic.

general purpose zkvm approach - supports arbitrary chialisp programs instead of hardcoded circuits for specific operations.

## 🚀 getting started

if you're new here, this should get you up and running.

### prerequisites

```bash
# Install dependencies automatically
./install-deps.sh

# Or manually:
rustup target add riscv32im-unknown-none-elf
curl -L https://risczero.com/install | bash && rzup
```

### choosing a zkvm backend

we support both risc0 and sp1 zkvm backends. risc0 is more mature, sp1 is newer and potentially faster:

```bash
# Default: uses risc0 backend (no flags needed)
cargo build
cargo test

# Explicitly use risc0 backend
cargo build --features risc0
cargo test --features risc0

# Use sp1 backend  
cargo build --no-default-features --features sp1
cargo test --no-default-features --features sp1

# Work directly with specific backends
cd backends/risc0 && cargo test      # risc0 backend  
cd backends/sp1 && cargo test        # sp1 backend
```

### benchmarking

want to see how fast the different backends are?

```bash
./run_benchmark.sh
```

### zk proof example

```rust
use clvm_zk::{ClvmZkProver, ProgramParameter};
use clvm_zk_core::chialisp::compile_chialisp_template_hash;

// Guest-side compilation: chialisp source and parameters sent to zkvm guest
let chialisp_source = "(mod (amount fee) (+ amount fee))";
let parameters = &[
    ProgramParameter::int(1000),        // amount
    ProgramParameter::int(50),          // fee
];

// Guest compiles chialisp to bytecode and executes it
let proof_result = ClvmZkProver::prove(chialisp_source, parameters)?;
let output = proof_result.result(); // Using helper method
let proof = proof_result.zk_proof;

// Verify using deterministic program hash (same as guest compilation)
let program_hash = compile_chialisp_template_hash(chialisp_source)?;
let (is_valid, extracted_output) = ClvmZkProver::verify_proof(
    program_hash,
    &proof,
    Some(output)
)?;

// Both integer and byte parameters supported
let byte_params = &[
    ProgramParameter::bytes(b"hello".to_vec()),
    ProgramParameter::int(42),
];
let proof_with_bytes = ClvmZkProver::prove(
    "(mod (message number) (list message number))",
    byte_params
)?;
```

## 📚 how this is organized

this is a cargo workspace with multiple zkvm backends. here's what's where:

### project structure

```
clvm-zk/
├── src/                           # main api and host functionality
│   ├── lib.rs                     # primary api entry point
│   ├── cli.rs                     # command line interface
│   ├── protocol/                  # protocol layer (spender, structures)
│   ├── wallet/                    # wallet functionality (hd_wallet, types)
│   └── backends.rs                # zkvm backend abstraction
│
├── clvm_zk_core/                  # chialisp compilation and clvm execution
│   ├── src/
│   │   ├── lib.rs                 # ClvmEvaluator and all opcode handler methods
│   │   ├── types.rs               # core types (ProgramParameter, etc)
│   │   ├── chialisp/              # chialisp parser and compiler
│   │   ├── operators.rs           # CLVM operator definitions and parsing
│   │   └── parser.rs              # CLVM bytecode parsing utilities
│   └── Cargo.toml                 # no zkvm dependencies, no_std compatible
│
├── backends/                      # zkvm backend implementations  
│   ├── risc0/                     # risc0 backend
│   │   ├── src/lib.rs             # risc0 host integration
│   │   ├── guest/src/main.rs      # risc0 guest wrapper (~170 lines)
│   │   └── Cargo.toml
│   └── sp1/                       # sp1 backend
│       ├── src/lib.rs             # sp1 host integration
│       ├── program/src/main.rs    # sp1 guest wrapper (~170 lines)
│       └── Cargo.toml
│
├── examples/                      # working code examples
│   ├── alice_bob_lock.rs          # ecdsa signature verification
│   ├── performance_profiling.rs   # performance benchmarks
│   └── backend_benchmark.rs       # backend comparison benchmarks
│
├── tests/                         # test suite
│   ├── fuzz_tests.rs              # fuzzing tests (500+ cases)
│   ├── simulator_tests.rs         # simulator tests (10/10 tests pass)
│   ├── expression_tests.rs        # expression parsing tests
│   ├── proof_validation_tests.rs  # security validation tests
│   ├── signature_integration_tests.rs # signature verification tests
│   ├── signature_tests.rs         # additional signature tests
│   ├── bls_signature_tests.rs     # BLS12-381 signature verification tests
│   ├── verification_security_tests.rs # proof verification security
│   ├── parameter_tests.rs         # parameter handling
│   ├── performance_tests.rs       # performance benchmarks
│   ├── security_tests.rs          # security tests
│   ├── test_large_atoms.rs        # large atom handling tests
│   └── test_large_values.rs       # large value tests
│
└── Cargo.toml                     # workspace configuration
```

### what the different parts do

#### `clvm_zk_core/` - backend-agnostic chialisp compilation and CLVM execution
this is the core engine that handles both chialisp compilation and CLVM execution with clean dependency injection:

**compilation pipeline:**
- **`src/chialisp/parser.rs`**: parses chialisp source into S-expressions
- **`src/chialisp/frontend.rs`**: converts S-expressions to abstract syntax tree (AST)
- **`src/chialisp/codegen.rs`**: compiles AST to CLVM bytecode
- **`compile_chialisp_to_bytecode()`**: main compilation function used by guests
- **`compile_chialisp_template_hash()`**: generates deterministic program hashes

**execution engine with dependency injection:**
- **`ClvmEvaluator`**: main evaluation struct with injected backend dependencies
  - `hasher: fn(&[u8]) -> [u8; 32]` - hash function for general operations
  - `bls_verifier: fn(&[u8], &[u8], &[u8]) -> Result<bool, &'static str>` - BLS signature verification
  - `ecdsa_verifier: fn(&[u8], &[u8], &[u8]) -> Result<bool, &'static str>` - ECDSA signature verification
- **`ClvmEvaluator::new()`**: creates evaluator with default implementations
- **`ClvmEvaluator::with_backends()`**: creates evaluator with optimized implementations
- **All opcode handlers as evaluator methods**: `handle_op_add()`, `handle_op_sha256()`, etc.
- **`evaluate_clvm_program_with_params()`**: executes bytecode with parameter substitution

**key features:**
- **clean architecture** - core has no backend dependencies, gets optimizations via injection
- **backend flexibility** - RISC0 gets precompiles, SP1/Mock get defaults, easily extensible
- **no_std compatible** - pure rust, works in risc0, sp1, or any no_std environment
- **complete compilation** - handles mod syntax, function definitions, complex expressions
- **deterministic hashing** - same chialisp source always produces same program hash
- **unified types** - `ProgramParameter`, `Condition`, `ClvmValue` used across host and guest

#### `backends/risc0/` - risc0 zkvm wrapper with optimized precompiles
the risc0-specific code that injects performance optimizations:
- **`guest/src/main.rs`**: guest program using `ClvmEvaluator::with_backends()` for optimized execution
- **`src/lib.rs`**: risc0 host-side integration implementing `ZKCLVMBackend` trait

**RISC0 optimizations (all implemented in guest code):**
- **`risc0_hash_data_guest()`**: uses `risc0_zkvm::sha::Impl::hash_bytes()` for hardware-accelerated SHA-256
- **`risc0_verify_bls_signature_guest()`**: BLS12-381 signature verification using RISC0's zkcrypto-bls12_381 library with pairing precompiles
- **`risc0_verify_ecdsa_signature_guest()`**: optimized ECDSA verification with RISC0-accelerated hashing
- **dual SHA-256 optimization**: RISC0 precompiles for general hashing + standard digest for BLS hash-to-curve compatibility
- **guest injection**: `ClvmEvaluator::with_backends(risc0_hash_data_guest, risc0_verify_bls_signature_guest, risc0_verify_ecdsa_signature_guest)`

**ZKCLVMBackend trait methods:**
- **`prove_program(chialisp_source, program_parameters, legacy_parameters)`**: sends source to guest for compilation and proof generation
- **`prove_with_nullifier(chialisp_source, program_parameters, legacy_parameters, spend_secret)`**: same as prove_program but generates nullifier
- **`verify_proof(proof)`**: verifies proof and extracts program hash and output

#### `backends/sp1/` - sp1 zkvm wrapper with optimized precompiles
same architecture as risc0 with SP1-specific optimizations:
- **`src/lib.rs`**: sp1 host-side integration implementing `ZKCLVMBackend` trait
- **`program/src/main.rs`**: guest program using `ClvmEvaluator::with_backends()` for optimized execution

**SP1 optimizations (all implemented in guest code):**
- **`sp1_hash_data_guest()`**: uses standard SHA-256 with SP1 internal optimizations
- **`sp1_verify_bls_signature_guest()`**: BLS12-381 signature verification using SP1's BLS12-381 precompiles
- **`sp1_verify_ecdsa_signature_guest()`**: optimized ECDSA verification with SP1-accelerated hashing
- **digest compatibility**: uses digest 0.9 for BLS compatibility while maintaining SHA-256 optimizations
- **guest injection**: `ClvmEvaluator::with_backends(sp1_hash_data_guest, sp1_verify_bls_signature_guest, sp1_verify_ecdsa_signature_guest)`

**SP1 approach:**
- **identical compilation**: both backends use the same `compile_chialisp_to_bytecode()` function
- **deterministic consistency**: same chialisp source produces identical program hash on both backends
- **BLS12-381 precompiles**: leverages SP1's patched BLS library for maximum performance

### main library (`src/`)

#### `src/lib.rs` - main API
this is what you actually use:
- **`ClvmZkProver`**: main struct with all public apis
- **`ProgramParameter`**: re-exported from clvm_zk_core crate (supports both Int and Bytes)
- **`ProofResult`**: structured result containing clvm output and zk proof
- **`ResultWithNullifier`**: privacy-focused result including nullifier
- **guest-side compilation flow**: host validates syntax → sends chialisp source to guest → guest compiles and executes → returns proof with program hash
- **backend abstraction**: uses `ZKCLVMBackend` trait for risc0/sp1 compatibility
- **error types**: comprehensive error handling with `ClvmZkError`

#### verification functionality
proof verification is now handled directly in `ClvmZkProver::verify_proof()` in `src/lib.rs`

#### `src/cli.rs` - command line interface
cli with simulator:
- **`demo`**: interactive demonstration
- **`prove`**: generate proofs from command line
- **`verify`**: verify existing proof files
- **`bench`**: performance benchmarking

#### `examples/` - code examples
actual working examples you can run:
- **`alice_bob_lock.rs`**: ECDSA signature verification example
- **`performance_profiling.rs`**: performance benchmarking
- **`backend_benchmark.rs`**: compare different zkvm backends

#### `tests/` - comprehensive test suite
extensive testing to ensure reliability and security:
- **`fuzz_tests.rs`**: fuzzing tests (500+ test cases covering edge cases)
- **`simulator_tests.rs`**: ✅ full simulator functionality (10/10 tests pass)
- **`proof_validation_tests.rs`**: security validation and proof integrity
- **`signature_integration_tests.rs`**: ECDSA signature verification tests
- **`bls_signature_tests.rs`**: ✅ BLS12-381 signature verification tests with RISC0 precompiles
- **`verification_security_tests.rs`**: proof verification security tests
- **`expression_tests.rs`**: Chialisp expression parsing and validation
- **`parameter_tests.rs`**: parameter handling and edge cases
- **`performance_tests.rs`**: performance benchmarking and optimization
- **`security_tests.rs`**: security attack resistance testing
- **`backend_integration/`**: backend-specific integration tests

### basic usage

`ClvmZkProver::prove(expression, parameters)` generates proofs using guest-side compilation and execution. `ClvmZkProver::verify_proof(program_template_hash, output, proof)` verifies them. expressions support named variables and `mod` wrapper syntax. check `examples/` for working code.

**guest-side compilation flow**:
1. host validates syntax using `clvm_zk_core::chialisp::parse_chialisp`
2. host sends chialisp source and `ProgramParameter` structs to guest
3. guest calls `clvm_zk_core::compile_chialisp_to_bytecode` to compile source
4. guest executes compiled bytecode using `clvm_zk_core::evaluate_clvm_program_with_params`
5. guest returns proof with deterministic program hash

**program hashing**: `compile_chialisp_template_hash(expression)` generates deterministic hashes using `clvm_zk_core::compile_chialisp_template_hash` - same compilation process as guest ensures hash consistency

### supported chialisp

**arithmetic**: `+`, `-`, `*`, `divmod`, `modpow`
**comparison**: `=`, `>`, `<`
**control flow**: `i` (if-then-else), `if` (syntax sugar for `i`)
**lists**: `c` (cons), `f` (first), `r` (rest), `l` (length)
**cryptography**: `sha256`, `ecdsa_verify`, `bls_verify` (NEW! BLS12-381 signatures)
**blockchain**: `create_coin`, `agg_sig_unsafe`, `reserve_fee`, etc
**modules**: `mod` wrapper syntax for named parameters

**NEW: BLS signature verification**
- `bls_verify public_key message signature` - BLS12-381 signature verification
- **RISC0 backend**: optimized precompiles with BLS12-381 pairing acceleration using risc0/zkcrypto-bls12_381
- **SP1 backend**: BLS12-381 precompiles using sp1-patches/bls12_381 with digest 0.9 compatibility
- Proper RFC 9380 hash-to-curve implementation with domain separation for both backends
- Graceful fallback with informative error messages when BLS is not available
- Full test coverage in `tests/bls_signature_tests.rs`

supports nested expressions and complex programs. use `(mod (param1 param2) body)` for named parameters. see test files for examples.

## 🛠 development

`cargo test` runs tests. `cargo run --example <name>` runs examples. `cargo run -- demo` for interactive demo.

### CLI commands
```bash
# Interactive demo with examples
cargo run -- demo

# Generate proofs directly
cargo run -- prove --expression "(+ amount fee)" --arg1 5 --arg2 3

# Benchmark performance
cargo run -- bench --count 10

# Start simulator
cargo run -- sim init
cargo run -- sim wallet alice create
cargo run -- sim faucet alice --amount 5000
```

## 🏗 design decisions

uses chia's official parser, borsh serialization (22.5% smaller), risc0/sp1 zkvm backends. ~3s proof generation, 282ms verification.
## 🔐 privacy & security model

**private:** spend secrets, program parameters, execution traces
**public:** program hashes, nullifiers, outputs, proofs

nullifier protocol prevents double-spending. spend secrets stay hidden in zk proofs.

## 💡 privacy examples

```rust
use clvm_zk::{ClvmZkProver, ProgramParameter};
use clvm_zk_core::chialisp::compile_chialisp_template_hash;

// Privacy-preserving coin spending with nullifiers
let spend_secret = [42u8; 32];  // Secret known only to spender
let puzzle_program = "(mod (secret_value) (= secret_value 12345))";
let parameters = &[ProgramParameter::int(12345)];

// Generate proof with nullifier to prevent double-spending
let result = ClvmZkProver::prove_with_nullifier(
    puzzle_program,
    parameters,
    spend_secret
)?;

// Public verification without revealing secret or parameters
let program_hash = compile_chialisp_template_hash(puzzle_program)?;
let (is_valid, output) = ClvmZkProver::verify_proof(
    program_hash,
    &result.proof,
    Some(&result.result)
)?;

// Nullifier prevents double-spending of same coin
println!("Nullifier: {}", hex::encode(result.nullifier));
```

create coins with hidden spend secrets, spend them with zk proofs, verify signatures without revealing them. see `examples/alice_bob_lock.rs` for ECDSA signature verification using guest-side compilation.

## 🏦 blockchain simulator

privacy-preserving blockchain simulator for local testing. create wallets, send private transactions, and generate real zk proofs without setting up a real blockchain.

```bash
# quick start
cargo run -- sim init                           # initialize
cargo run -- sim wallet alice create            # create wallet
cargo run -- sim faucet alice --amount 5000     # fund wallet
cargo run -- sim wallet alice show              # check balance
```

### features
- real HD wallets with crypto seeds
- observer wallets for monitoring without spending
- privacy-preserving transactions with zk proofs
- persistent state between sessions
- supports any chialisp program as spending condition
- double-spend prevention works properly now
- multi-coin transactions and batch processing

the simulator tests all pass now (10/10), so the core functionality is solid.

see **[SIMULATOR.md](SIMULATOR.md)** for documentation, examples, and workflows.

## 📄 more docs

- **[SIMULATOR.md](SIMULATOR.md)**: detailed simulator guide with examples

## 🔌 adding new zkvm backends

want to add support for a new zkvm? here's how the backend system works:

### backend structure
```
backends/
├── risc0/          # risc0 implementation
│   ├── src/lib.rs  # host-side integration  
│   └── guest/      # guest program
└── sp1/            # sp1 implementation
    ├── src/lib.rs  # host-side integration
    └── program/    # guest program
```

### how to add a backend

implement `ZKCLVMBackend` trait in `backends/your_zkvm/src/lib.rs` and create a guest program that uses `clvm_zk_core`. add feature flag to main `Cargo.toml` and update `src/backends.rs`:

```rust
use clvm_zk_core::{ZKClvmResult, ZKClvmNullifierResult, ProgramParameter, ClvmZkError};
use crate::backends::ZKCLVMBackend;

pub struct YourZkvmBackend;

impl ZKCLVMBackend for YourZkvmBackend {
    fn prove_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        _legacy_parameters: &[ProgramParameter],
    ) -> Result<ZKClvmResult, ClvmZkError> {
        // Send chialisp_source and program_parameters to your zkvm guest
        // Guest uses clvm_zk_core::compile_chialisp_to_bytecode and evaluate_clvm_program_with_params
        todo!("Implement for your backend")
    }

    fn prove_with_nullifier(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        _legacy_parameters: &[ProgramParameter],
        spend_secret: [u8; 32],
    ) -> Result<ZKClvmNullifierResult, ClvmZkError> {
        // Same as prove_program but also generate nullifier in guest
        todo!("Implement for your backend")
    }

    fn verify_proof(&self, proof: &[u8]) -> Result<(bool, [u8; 32], Vec<u8>), ClvmZkError> {
        // Verify proof and extract program hash and output
        todo!("Implement for your backend")
    }

    fn backend_name(&self) -> &'static str {
        "your_zkvm"
    }

    fn is_available(&self) -> bool {
        true
    }
}
```

```toml
[features]
your_zkvm = ["clvm-zk-your-zkvm"]
```

see `backends/risc0/` or `backends/sp1/` for reference implementations.

## 🤝 contributing

this is actively developed. areas where help would be useful:
- performance optimizations
- more chialisp operations  
- better error messages
- documentation improvements
- more test cases
- **new zkvm backends**

check the test suite in `tests/` to understand how everything works.# Veil
