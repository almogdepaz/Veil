# Veil

**Work in progress research project**

Zero-knowledge proof system for running Chialisp (CLVM) programs privately. Generates proofs of correct execution without revealing inputs or program logic.

Supports arbitrary Chialisp programs instead of hardcoded circuits.

## What it does

- Run Chialisp programs in zkVM (SP1 by default, RISC0 also supported)
- Generate proofs that hide inputs and program logic
- Verify proofs without revealing private data
- BLS and ECDSA signature verification


## Getting started

### Simulator demo

Run encrypted payment notes demo:

```bash
# install dependencies
./install-deps.sh

# run demo
./sim_demo.sh         # RISC0 backend (default)
./sim_demo.sh sp1     # SP1 backend
```

See **[SIMULATOR.md](SIMULATOR.md)** for details.

### Install dependencies

```bash
# install dependencies
./install-deps.sh

# manual installation
rustup target add riscv32im-unknown-none-elf
curl -L https://risczero.com/install | bash && rzup
```

### Build and test

Use backend-specific cargo aliases to avoid rebuilding when switching backends:

```bash
# build (release)
cargo risc0              # RISC0 backend to target/risc0/
cargo sp1                # SP1 backend to target/sp1/
cargo mock               # mock backend to target/mock/

# test
cargo test-risc0         # run all tests with RISC0
cargo test-sp1           # run all tests with SP1
cargo test-mock          # fast tests without zkVM

# run
cargo run-risc0 -- demo
cargo run-sp1 -- prove --expression "(mod (a b) (+ a b))" --variables "5,3"

# examples
cargo run-risc0 --example alice_bob_lock
cargo run-sp1 --example backend_benchmark

# development
cargo check-risc0        # fast compile check
cargo clippy-risc0       # lints
```

Backend-specific builds prevent clobbering. Each backend uses ~1GB disk space. Aliases defined in `.cargo/config.toml`.

For simulator usage, see **[SIMULATOR.md](SIMULATOR.md)**.



## Supported Chialisp

**Arithmetic**: `+`, `-`, `*`, `divmod`, `modpow`
**Comparison**: `=`, `>`, `<`
**Control flow**: `i` (if-then-else), `if`
**Lists**: `c` (cons), `f` (first), `r` (rest), `l` (length)
**Functions**: Helper functions with recursion support
**Cryptography**: `sha256`, `ecdsa_verify`, `bls_verify`
**Blockchain**: `create_coin`, `agg_sig_unsafe`, `reserve_fee`, etc
**Modules**: `mod` wrapper syntax for named parameters

BLS signature verification (`bls_verify`) works on SP1 and RISC0 backends.

### Program structure

```chialisp
;; Simple expression
(+ 1 2)

;; Named parameters with mod wrapper
(mod (amount fee)
  (+ amount fee))

;; Helper functions
(mod (x)
  (defun double (n) (* n 2))
  (double x))

;; Recursion
(mod (n)
  (defun factorial (x)
    (if (= x 0)
      1
      (* x (factorial (- x 1)))))
  (factorial n))

;; Nested expressions
(mod (threshold values)
  (if (> (length values) threshold)
    (sha256 (c threshold values))
    0))
```

See `tests/` for examples.



## Architecture

### Project structure

```
clvm-zk/
├── src/                           # main api and host functionality
│   ├── lib.rs                     # primary api entry point
│   ├── cli.rs                     # command line interface
│   ├── protocol/                  # protocol layer (spender, structures, puzzles)
│   ├── wallet/                    # wallet functionality (hd_wallet, types)
│   └── backends.rs                # zkvm backend abstraction
│
├── clvm_zk_core/                  # chialisp compilation and clvm execution (no_std)
│   ├── src/
│   │   ├── lib.rs                 # ClvmEvaluator and all opcode handler methods
│   │   ├── types.rs               # core types (ProgramParameter, etc)
│   │   ├── backend_utils.rs       # shared backend utilities
│   │   ├── chialisp/              # chialisp source parser and compiler
│   │   │   ├── parser.rs          # chialisp source → s-expressions
│   │   │   ├── frontend.rs        # s-expressions → ast
│   │   │   └── compiler_utils.rs  # compilation helpers
│   │   ├── operators.rs           # CLVM operator definitions
│   │   └── clvm_parser.rs         # CLVM binary bytecode → ClvmValue
│   └── Cargo.toml                 # no zkvm dependencies, unconditionally no_std
│
├── backends/                      # zkvm backend implementations  
│   ├── risc0/                     # risc0 backend
│   │   ├── src/
│   │   │   ├── lib.rs             # implementation + methods re-exports
│   │   │   └── methods.rs         # generated elf/id constants wrapper
│   │   ├── guest/src/main.rs      # risc0 guest program
│   │   └── Cargo.toml
│   ├── sp1/                       # sp1 backend (default)
│   │   ├── src/
│   │   │   ├── lib.rs             # implementation + methods re-exports
│   │   │   └── methods.rs         # elf loading wrapper
│   │   ├── program/src/main.rs    # sp1 guest program
│   │   └── Cargo.toml
│   └── mock/                      # mock backend for testing
│       ├── src/
│       │   └── backend.rs         # no-zkvm test implementation
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
│   ├── bls_signature_tests.rs     # BLS12-381 signature verification
│   ├── signature_tests.rs         # signature verification tests
│   ├── proof_validation_tests.rs  # security validation tests
│   └── ...                        # additional test files
│
└── Cargo.toml                     # workspace configuration
```


### Core components

#### `clvm_zk_core/` - Backend-agnostic compilation and execution
no_std Chialisp compiler and CLVM executor with dependency injection for zkVM-optimized crypto:

**Compilation:**
- **`compile_chialisp_to_bytecode_with_table()`**: Compiles Chialisp source to CLVM bytecode with function table
- **`compile_chialisp_template_hash()`**: Generates deterministic program hashes for verification
- **Compilation pipeline**: Chialisp source → s-expressions → AST → CLVM bytecode → ClvmValue

**Execution:**
- **`ClvmEvaluator`**: Main evaluation struct with injected backend crypto
  - `hasher: fn(&[u8]) -> [u8; 32]` - Hash function (zkVM-optimized)
  - `bls_verifier: fn(&[u8], &[u8], &[u8]) -> Result<bool, &'static str>` - BLS signature verification
  - `ecdsa_verifier: fn(&[u8], &[u8], &[u8]) -> Result<bool, &'static str>` - ECDSA signature verification
- **`evaluate_clvm_program()`**: Executes bytecode with parameter substitution
- **All CLVM opcodes**: Arithmetic, comparison, list operations, conditionals, crypto, blockchain conditions

#### `backends/` - zkVM implementations
Each backend provides host integration and guest program:
- **RISC0**: Mature backend with optimized precompiles for BLS/ECDSA
- **SP1**: Default backend, potentially faster proving times
- **mock**: No-zkVM testing backend for fast iteration

#### `examples/` - Working code examples
- `alice_bob_lock.rs` - ECDSA signature verification with ZK proofs
- `performance_profiling.rs` - Performance benchmarking suite
- `backend_benchmark.rs` - Backend comparison tool

## Development

### Basic usage

`ClvmZkProver::prove(expression)` generates proofs. `ClvmZkProver::verify_proof()` verifies them. Expressions support named variables and `mod` wrapper syntax. See `examples/` for working code.

### Examples

```rust
use clvm_zk::{ClvmZkProver, ProgramParameter};

// Basic proof generation
let chialisp_source = "(mod (amount fee) (+ amount fee))";
let parameters = &[
    ProgramParameter::int(1000),
    ProgramParameter::int(50),
];

let result = ClvmZkProver::prove(chialisp_source, parameters)?;
```

See `examples/` for complete working code including `alice_bob_lock.rs` for ECDSA signatures.


**Flow**: Host sends Chialisp source to guest → guest compiles and executes → returns proof with program hash.



## Privacy protocols

### Nullifier protocol

Coins use serial commitment scheme to prevent double-spending while hiding which coin was spent:

**Coin creation:**
- Generate random `serial_number` and `serial_randomness`
- `serial_commitment = hash("clvm_zk_serial_v1.0" || serial_number || serial_randomness)`
- `coin_commitment = hash("clvm_zk_coin_v1.0" || amount || puzzle_hash || serial_commitment)`
- Coin commitment added to merkle tree

**Spending:**
- Guest verifies: `puzzle_hash == program_hash` (proves running correct puzzle)
- Guest verifies: `hash(serial_number || serial_randomness) == serial_commitment`
- Guest verifies: `hash(amount || puzzle_hash || serial_commitment) == coin_commitment`
- Guest verifies: Merkle membership of coin_commitment
- Guest computes: `nullifier = hash(serial_number || program_hash)`
- Proof reveals nullifier, hides which coin was spent

**Security properties:**
- Each coin has exactly one valid nullifier
- Nullifier set tracks spent coins
- Double-spending cryptographically impossible
- Merkle proof shows coin exists without revealing which one
- serial_randomness prevents linking nullifier to coin_commitment

### Recovery protocol

Encrypted payment notes enable offline receiving and backup recovery:

**Sending:**
- Alice generates coin with random serial_number and serial_randomness
- Alice encrypts `(serial_number, serial_randomness)` to Bob's x25519 viewing key
- Alice publishes encrypted note on-chain alongside transaction

**Receiving:**
- Bob scans blockchain with x25519 decryption key
- Bob decrypts notes to discover coins sent to him
- Bob stores coin secrets locally

**Recovery:**
- Bob re-scans blockchain with viewing key
- Recovers all coins from encrypted notes
- Works offline - no interaction with sender needed

**Privacy:**
- Alice cannot track Bob's spending after sending
- Encrypted notes unlinkable to coin commitments
- Viewing key enables read-only access

See **[ENCRYPTED_NOTES.md](ENCRYPTED_NOTES.md)** and **[nullifier.md](nullifier.md)** for detailed specifications.

## Blockchain simulator

Local privacy-preserving blockchain simulator with encrypted payment notes, HD wallets, persistent state, and real ZK proofs.

```bash
# run the full demo
./sim_demo.sh         # RISC0 backend (default)
./sim_demo.sh sp1     # SP1 backend
```

See **[SIMULATOR.md](SIMULATOR.md)** for complete documentation and usage examples.


## Adding new zkVM backends

To add a new zkVM backend:

1. Create `backends/your_zkvm/src/lib.rs` implementing the backend
2. Create guest program using `clvm_zk_core` (no_std compatible)
3. Inject zkVM-optimized crypto functions into `ClvmEvaluator`
4. Add feature flag to workspace `Cargo.toml`
5. Implement `ZKCLVMBackend` trait in `src/backends.rs`

See `backends/risc0/` or `backends/sp1/` as reference implementations.

## Contributing

Contributions welcome in these areas:
- Performance optimizations
- Chialisp operations
- Error messages
- Documentation
- Test cases
- zkVM backends

See test suite in `tests/` for implementation patterns.
