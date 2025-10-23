# Veil

**Work in progress research project**

Zero-knowledge proof system for running Chialisp (CLVM) programs privately. Take a chialisp program, prove it executed correctly, and verify that proof without revealing the inputs or program logic.

General purpose zkvm approach - supports arbitrary chialisp programs instead of hardcoded circuits.

## What it does

- Run chialisp programs in zkvm (SP1 by default, RISC0 also supported)
- Generate proofs that hide inputs and program logic
- Verify proofs without seeing the private data
- BLS and ECDSA signature verification support


## Getting started

### Quick start: simulator demo

fastest way to see veil in action:

```bash
# install dependencies
./install-deps.sh

# run encrypted payment notes demo
./sim_demo.sh         # risc0 backend (default)
./sim_demo.sh sp1     # sp1 backend
```

see **[SIMULATOR.md](SIMULATOR.md)** for details.

### Install dependencies

```bash
# install dependencies
./install-deps.sh

# manual installation
rustup target add riscv32im-unknown-none-elf
curl -L https://risczero.com/install | bash && rzup
```

### Backend-specific builds (recommended)

to prevent backends from overwriting each other's builds, use cargo aliases:

```bash
# build commands
cargo build-risc0        # debug build to target/risc0/
cargo release-risc0      # release build to target/risc0/
cargo build-sp1          # debug build to target/sp1/
cargo release-sp1        # release build to target/sp1/

# run tests
cargo test-risc0
cargo test-sp1

# development
cargo check-risc0        # fast compile check
cargo clippy-risc0       # lints
```

see **[CARGO_ALIASES.md](CARGO_ALIASES.md)** for complete documentation.

**benefits:**
- ✅ building sp1 won't delete risc0 binaries
- ✅ switch between backends without rebuilding
- ✅ parallel builds in different terminals
- ⚠️  uses ~1GB per backend

### Standard build (single backend at a time)

```bash
# default: sp1 backend (requires --release for proof generation)
cargo build --release
cargo test --release

# risc0 backend
cargo release-risc0
cargo test-risc0 --release

# mock backend (for testing without zkvm overhead)
cargo test-mock
```

### Run examples

```bash
# run with cargo (use --release for actual proof generation)
cargo run --release -- demo
cargo run --release -- prove --expression "(mod (a b) (+ a b))" --variables "5,3"

# or run binary directly (faster, no rebuild)
./target/release/clvm-zk demo
./target/release/clvm-zk prove --expression "(mod (a b) (+ a b))" --variables "5,3"
./target/release/clvm-zk verify --proof-file proof.bin --template "(mod (a b) (+ a b))"

# run code examples
cargo run --release --example alice_bob_lock
cargo run --release --example backend_benchmark
```

for simulator usage, see **[SIMULATOR.md](SIMULATOR.md)**.



## Supported chialisp

**Arithmetic**: `+`, `-`, `*`, `divmod`, `modpow`
**Comparison**: `=`, `>`, `<`
**Control flow**: `i` (if-then-else), `if`
**Lists**: `c` (cons), `f` (first), `r` (rest), `l` (length)
**Functions**: helper functions with recursion support
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

See `tests/` for examples of supported operations.



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
Unconditionally no_std chialisp compiler and CLVM executor with dependency injection for zkvm-optimized crypto:

**Compilation:**
- **`compile_chialisp_to_bytecode_with_table()`**: compiles chialisp source to CLVM bytecode with function table
- **`compile_chialisp_template_hash()`**: generates deterministic program hashes for verification
- **Compilation pipeline**: chialisp source → s-expressions → AST → CLVM bytecode → ClvmValue

**Execution:**
- **`ClvmEvaluator`**: main evaluation struct with injected backend crypto
  - `hasher: fn(&[u8]) -> [u8; 32]` - hash function (zkvm-optimized)
  - `bls_verifier: fn(&[u8], &[u8], &[u8]) -> Result<bool, &'static str>` - BLS signature verification
  - `ecdsa_verifier: fn(&[u8], &[u8], &[u8]) -> Result<bool, &'static str>` - ECDSA signature verification
- **`evaluate_clvm_program()`**: executes bytecode with parameter substitution
- **All CLVM opcodes**: arithmetic, comparison, list operations, conditionals, crypto, blockchain conditions
  
#### `backends/` - zkvm implementations
Each backend provides host integration and guest program:
- **risc0**: mature backend with optimized precompiles for BLS/ECDSA
- **sp1**: default backend, potentially faster proving times
- **mock**: no-zkvm testing backend for fast iteration

#### `examples/` - working code examples
- `alice_bob_lock.rs` - ECDSA signature verification with ZK proofs
- `performance_profiling.rs` - performance benchmarking suite
- `backend_benchmark.rs` - backend comparison tool
## Development

### Basic usage

`ClvmZkProver::prove(expression)` generates proofs. `ClvmZkProver::verify_proof()` verifies them. Expressions support named variables and `mod` wrapper syntax. Check `examples/` for working code.

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


**Flow**: Host sends chialisp source to guest → guest compiles and executes → returns proof with program hash.



## Blockchain simulator

local privacy-preserving blockchain simulator with encrypted payment notes, hd wallets, persistent state, and real zk proofs.

```bash
# run the full demo
./sim_demo.sh         # risc0 backend (default)
./sim_demo.sh sp1     # sp1 backend
```

see **[SIMULATOR.md](SIMULATOR.md)** for complete documentation and usage examples.


## Adding new zkvm backends

To add a new zkvm backend:

1. Create `backends/your_zkvm/src/lib.rs` implementing the backend
2. Create guest program using `clvm_zk_core` (no_std compatible)
3. Inject zkvm-optimized crypto functions into `ClvmEvaluator`
4. Add feature flag to workspace `Cargo.toml`
5. Implement `ZKCLVMBackend` trait in `src/backends.rs`

See `backends/risc0/` or `backends/sp1/` as reference implementations.

## Contributing

Areas where help would be useful:
- Performance optimizations
- More chialisp operations
- Better error messages
- Documentation improvements
- More test cases
- New zkvm backends

Check the test suite in `tests/` to understand how everything works.
