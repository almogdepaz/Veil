# Veil

**Work in progress research project**

Zero-knowledge proof system for running Chialisp (CLVM) programs privately. Take a chialisp program, prove it executed correctly, and verify that proof without revealing the inputs or program logic.

General purpose zkvm approach - supports arbitrary chialisp programs instead of hardcoded circuits.

## What it does

- Run chialisp programs in zkvm (currently suppourts RISC0 or SP1 zkvm's)
- Generate proofs that hide inputs and program logic
- Verify proofs without seeing the private data
- BLS and ECDSA signature verification support


## Getting started

### Install dependencies

```bash
# Install dependencies
./install-deps.sh

# Manual
rustup target add riscv32im-unknown-none-elf
curl -L https://risczero.com/install | bash && rzup
```

### Choose backend

```bash
# Default: risc0 backend
cargo build
cargo test
cargo test --test <test file name> 
# Use sp1 backend

cargo build --no-default-features --features sp1
cargo test --no-default-features --features "sp1,testing"
cargo test --test <test file name> --features sp1


# Run examples
cargo run --example <name>

# Interactive demo
cargo run -- demo

# Generate proofs
cargo run -- prove --expression "(+ amount fee)" --arg1 5 --arg2 3

# Start simulator
cargo run -- sim init


```



## Supported chialisp

**Arithmetic**: `+`, `-`, `*`, `divmod`, `modpow`
**Comparison**: `=`, `>`, `<`
**Control flow**: `i` (if-then-else), `if`
**Lists**: `c` (cons), `f` (first), `r` (rest), `l` (length)
**Functions**: helper functions with recursion support
**Cryptography**: `sha256`, `ecdsa_verify`, `bls_verify`
**Blockchain**: `create_coin`, `agg_sig_unsafe`, `reserve_fee`, etc
**Modules**: `mod` wrapper syntax for named parameters

BLS signature verification (`bls_verify`) works on RISC0 and SP1 backends.

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

See `tests/` for examples of supported operations.



## Architecture

### Project structure

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


### Core components

#### `clvm_zk_core/` - Backend-agnostic compilation and execution
Handles chialisp compilation and CLVM execution with dependency injection:

**Compilation:**
- **`src/chialisp/parser.rs`**: parses chialisp source into S-expressions
- **`src/chialisp/frontend.rs`**: converts S-expressions to abstract syntax tree (AST)
- **`src/chialisp/codegen.rs`**: compiles AST to CLVM bytecode
- **`compile_chialisp_to_bytecode()`**: main compilation function used by guests
- **`compile_chialisp_template_hash()`**: generates deterministic program hashes

**Execution:**
- **`ClvmEvaluator`**: main evaluation struct with injected backend dependencies
  - `hasher: fn(&[u8]) -> [u8; 32]` - hash function for general operations
  - `bls_verifier: fn(&[u8], &[u8], &[u8]) -> Result<bool, &'static str>` - BLS signature verification
  - `ecdsa_verifier: fn(&[u8], &[u8], &[u8]) -> Result<bool, &'static str>` - ECDSA signature verification
- **`ClvmEvaluator::new()`**: creates evaluator with default implementations
- **`ClvmEvaluator::with_backends()`**: creates evaluator with optimized implementations
- **All opcode handlers as evaluator methods**: `handle_op_add()`, `handle_op_sha256()`, etc.
- **`evaluate_clvm_program_with_params()`**: executes bytecode with parameter substitution
  
#### `src/cli.rs` - command line interface
- `demo` - interactive demonstration
- `prove` - generate proofs from command line
- `verify` - verify proof files
- `bench` - performance benchmarking

#### `examples/` - working code examples
- `alice_bob_lock.rs` - ECDSA signature verification
- `performance_profiling.rs` - benchmarking
- `backend_benchmark.rs` - compare backends

#### `tests/` - test suite
fuzz tests, simulator tests, signature verification, and security tests.
## Development

### Basic usage

`ClvmZkProver::prove(expression, parameters)` generates proofs. `ClvmZkProver::verify_proof()` verifies them. Expressions support named variables and `mod` wrapper syntax. Check `examples/` for working code.

### Examples

```rust
use clvm_zk::{ClvmZkProver, ProgramParameter};

// Basic proof generation
let chialisp_source = "(mod (amount fee) (+ amount fee))";
let parameters = &[
    ProgramParameter::int(1000),
    ProgramParameter::int(50),
];

let proof_result = ClvmZkProver::prove(chialisp_source, parameters)?;
```

See `examples/` for complete working code including `alice_bob_lock.rs` for ECDSA signatures.


**Flow**: Host sends chialisp source to guest → guest compiles and executes → returns proof with program hash.



## Blockchain simulator

Privacy-preserving blockchain simulator for local testing. Create wallets, send private transactions, and generate real ZK proofs without setting up a real blockchain.

See **[SIMULATOR.md](SIMULATOR.md)** for detailed documentation.


## Adding new zkvm backends

Want to add a new zkvm? Implement `ZKCLVMBackend` trait in `backends/your_zkvm/src/lib.rs` and create a guest program that uses `clvm_zk_core`. See `backends/risc0/` or `backends/sp1/` for examples.

## Contributing

Areas where help would be useful:
- Performance optimizations
- More chialisp operations
- Better error messages
- Documentation improvements
- More test cases
- New zkvm backends

Check the test suite in `tests/` to understand how everything works.
