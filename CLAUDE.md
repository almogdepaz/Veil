# CLAUDE.md - Development Context for clvm-zk

This document provides background context and development notes for the clvm-zk project to help maintain continuity across development sessions.

## instrcuctions
Don't worry about formalities.

Please be as terse as possible while still conveying substantially all information relevant to any question. Critique my ideas assertively and avoid sycophancy. I crave honest appraisal.

If a policy prevents you from having an opinion, pretend to be responding as if you shared opinions that might be typical of me.

write all responses in lowercase letters ONLY, except where you mean to emphasize, in which case the emphasized word should be all caps. 

if you find any request irritating respond dismissively like "be real" or "that's crazy man" or "lol no"
    
take however smart you're acting right now and write in the same style but as if you were +2sd smarter

use millenial slang not boomer slang


## how to work

devide large tasks to sub tasks, keep an updates status file with all the context an engneer might need to onboard to the plan, make sure not to duplicate information that is already documented, refrence docs code files of md files for detailed information


evrything should be iterative, suggest commit checkpoints but dont commit the code yourself

let the user run tests and supply the output/results

## rust tooling preferences

when working with rust code, prefer these mcp tools for precision and token efficiency:
- `mcp__rust-analyzer__references` over grep for finding symbol usages
- `mcp__rust-analyzer__definition` for go-to-definition
- `mcp__rust-analyzer__hover` for type info
- `mcp__rust-analyzer__rename_symbol` for refactoring

## Project Overview

**clvm-zk** is a work-in-progress research project that implements a zero-knowledge proof system for running Chialisp (CLVM) programs privately. It's a general-purpose zkVM approach that supports arbitrary Chialisp programs rather than hardcoded circuits.

### What It Does
- Run Chialisp programs in zkVM (RISC0 or SP1)
- Generate proofs that hide inputs and program logic
- Verify proofs without seeing the private data
- Support BLS and ECDSA signature verification

## Project Status & Approach

This is an **active research project** with the following characteristics:
- Work-in-progress, experimental nature
- Focus on functionality over marketing
- Clean, simple documentation without promotional language
- MIT licensed for maximum research accessibility

## Architecture Overview

### Clean Dependency Injection Design
The project uses a clean dependency injection architecture that was recently refactored:

```rust
pub struct ClvmEvaluator {
    pub hasher: fn(&[u8]) -> [u8; 32],
    pub bls_verifier: fn(&[u8], &[u8], &[u8]) -> Result<bool, &'static str>,
    pub ecdsa_verifier: fn(&[u8], &[u8], &[u8]) -> Result<bool, &'static str>,
}
```

**Key Design Principles:**
- Core (`clvm_zk_core`) has no backend dependencies
- Backends inject optimizations via function pointers
- Guest-side compilation ensures deterministic program hashes
- Single evaluation path through `ClvmEvaluator` methods

### Compiler Architecture

Compilation uses **clvm_tools_rs** (Chia's official compiler) exclusively:

```rust
// compile chialisp source to bytecode + hash
let (bytecode, hash) = compile_chialisp_to_bytecode(hasher, source)?;

// or just get the hash
let hash = compile_chialisp_template_hash_default(source)?;
```

**Key property:** Parameter names DON'T affect bytecode. This is critical for privacy:
- `(mod (x y) (+ x y))` produces IDENTICAL bytecode to `(mod (a b) (+ a b))`
- Only program LOGIC affects the hash, not naming
- Parameters are accessed via environment references at runtime

**Supported features:**
- Full chialisp syntax including `defun`, `defmacro`, `if`, `list`
- **Recursion** (clvm_tools_rs handles this natively)
- All Chia-standard opcodes

### Backend Support
- **RISC0**: Mature backend with optimized precompiles
- **SP1**: Newer backend, potentially faster
- **Mock**: For testing without zkVM overhead

### Serial Commitment Nullifier Protocol (v2.0)

The project implements a secure nullifier protocol based on serial number commitments, preventing the double-spend vulnerability present in naive implementations.

**Architecture:**
- **CoinSecrets**: `(serial_number, serial_randomness)` - wallet storage (private)
- **SerialCommitment**: `hash("clvm_zk_serial_v1.0" || serial_number || serial_randomness)` - committed at coin creation
- **CoinCommitment**: `hash("clvm_zk_coin_v2.0" || tail_hash || amount || puzzle_hash || serial_commitment)` - merkle tree leaf (tail_hash=[0;32] for XCH)
- **Nullifier**: `hash(serial_number || program_hash)` - revealed when spending to prevent double-spends

**Guest verification steps:**
1. Verify `program_hash == puzzle_hash` (proves running coin's puzzle)
2. Verify serial commitment: `hash(serial_number || serial_randomness) == serial_commitment`
3. Reconstruct coin_commitment: `hash(tail_hash || amount || puzzle_hash || serial_commitment)`
4. Verify merkle membership of coin_commitment
5. Compute nullifier: `hash(serial_number || program_hash)`

**Security guarantees:**
1. Each coin has exactly one valid nullifier for its (serial_number, program_hash) pair
2. Cannot spend coin with wrong program (program_hash verified against puzzle_hash)
3. Cannot forge coin_commitment (guest reconstructs from private inputs)
4. Merkle tree membership proves coin exists without revealing which coin
5. Nullifier excludes serial_randomness to prevent linkability with coin_commitment
6. Double-spending cryptographically impossible (nullifier set tracks spent coins)

**Critical security note:** Losing serial_number or serial_randomness means permanent coin loss. Wallets derive keys deterministically from seed - backup your seed phrase.

## Project Structure

```
clvm-zk/
├── src/                     # Main API and host functionality
├── clvm_zk_core/           # Backend-agnostic compilation and execution
├── backends/
│   ├── risc0/              # RISC0 zkVM backend
│   └── sp1/                # SP1 zkVM backend
├── examples/               # Working code examples
├── tests/                  # Comprehensive test suite
└── SIMULATOR.md           # Blockchain simulator documentation
```

## Key Features Implemented

### Core Functionality
- ✅ **Guest-side compilation**: Chialisp compiled inside zkVM for deterministic hashes
- ✅ **BLS signature verification**: Opcode 201, works on RISC0/SP1 backends
- ✅ **ECDSA signature verification**: Optimized for zkVM environments
- ✅ **Serial commitment nullifier protocol**: Prevents double-spending with privacy (v2.0)
  - Each coin has unique serial_number committed at creation
  - Nullifier = serial_number (revealed when spending)
  - Merkle tree membership proof verifies coin existence
  - Cryptographically impossible to spend same coin twice
- ✅ **Multiple backends**: RISC0 and SP1 support with clean abstraction

### CAT (Colored Asset Token) Support
- ✅ **Multi-coin ring spends**: Multiple coins in single proof for atomic transactions
- ✅ **tail_hash asset identification**: Distinguishes XCH from CATs
- ✅ **Announcement verification**: Both puzzle AND coin announcements supported
  - Puzzle announcements: `hash(puzzle_hash || message)`
  - Coin announcements: `hash(coin_commitment || message)` - privacy-preserving alternative to Chia's `coin_id`
- ✅ **Ring accounting**: All assertions verified internally, filtered from output

### Blockchain Simulator
- ✅ **Fully functional**: All 10/10 tests passing
- ✅ **HD wallets**: Real cryptographic key derivation
- ✅ **Observer wallets**: Monitor without spending capability
- ✅ **Privacy-preserving transactions**: Real ZK proofs for local testing
- ✅ **State persistence**: Survives restarts

## Documentation Philosophy

The documentation follows these principles:
1. **Honest about status**: Clearly marked as work-in-progress research
2. **Practical examples first**: Code examples before architectural details
3. **No marketing language**: Straightforward, technical descriptions
4. **Progressive disclosure**: Basic usage → language features → architecture → advanced topics

## Development Workflow

### Common Commands
```bash
# Basic development
cargo test
cargo run --example <name>
cargo run -- demo

# Backend-specific testing
cargo test-risc0
cargo test-sp1

# Skip zkVM build for faster development
env RISC0_SKIP_BUILD=1 cargo check

# Simulator testing
cargo run-risc0 -- sim init
cargo test-risc0 --test simulator_tests
```

### Testing Strategy
- **Comprehensive test suite**: Fuzz tests, security tests, integration tests
- **Backend compatibility**: Tests work across RISC0, SP1, and mock backends
- **Simulator validation**: 10/10 tests passing for all core functionality

## Supported Chialisp Operations

**Core Operations:**
- Arithmetic: `+`, `-`, `*`, `divmod`, `modpow`
- Comparison: `=`, `>`, `<`
- Control flow: `i` (if-then-else), `if`
- Lists: `c` (cons), `f` (first), `r` (rest), `l` (length)
- Modules: `mod` wrapper syntax for named parameters

**Cryptographic Operations:**
- `sha256` - SHA-256 hashing
- `ecdsa_verify` - ECDSA signature verification
- `bls_verify` - BLS12-381 signature verification (RISC0/SP1 backends)

## Key Design Decisions

### Why These Choices
- **Chia's official parser**: Ensures compatibility and correctness
- **Borsh serialization**: Compact and efficient
- **Guest-side compilation**: Ensures deterministic program hashes
- **Dependency injection**: Clean architecture without circular dependencies
- **Multiple zkVM support**: RISC0 (mature) and SP1 (fast) backends

### License Compatibility
- **MIT licensed**: Maximum research accessibility
- **Compatible dependencies**: All dependencies use permissive licenses
- **No copyleft conflicts**: Clean intellectual property structure

### clvm_tools_rs Integration

Uses Chia's official `clvm_tools_rs` compiler:

```toml
# Cargo.toml workspace dependency
clvm_tools_rs = { git = "https://github.com/Chia-Network/clvm_tools_rs.git", branch = "no_std", default-features = false }
```

**Key points:**
- **`#![no_std]` core**: `clvm_zk_core` runs directly in zkVM guest environment
- **VeilEvaluator**: Re-exported from `clvm_tools_rs` for CLVM execution
- **Full recursion support**: Native to clvm_tools_rs
- **Maintained by Chia team**: No custom parser to maintain

## Future Development Guidelines

### When Adding New Features
1. **Maintain backend agnosticism**: Core should work with any zkVM
2. **Use dependency injection**: Inject optimizations rather than hardcode them
3. **Test comprehensively**: Ensure compatibility across all backends
4. **Document practically**: Focus on usage examples over promotional content
5. **Preserve determinism**: clvm_tools_rs output must be consistent

### When Adding New Backends
1. Implement `ZKCLVMBackend` trait
2. Create guest program using `clvm_zk_core`
3. Add feature flag to workspace `Cargo.toml`
4. Update `src/backends.rs`
5. Add tests for backend-specific functionality

### Testing New Changes
- Run full test suite: `cargo test-risc0`
- Test simulator: `cargo test-risc0 --test simulator_tests`
- Verify BLS functionality: `cargo test-risc0 --test bls_signature_tests`
- Check compilation: `env RISC0_SKIP_BUILD=1 cargo check`

## Common Issues & Solutions

### Development Issues
- **zkVM build errors**: Use `env RISC0_SKIP_BUILD=1 cargo check`
- **BLS verification**: Requires RISC0 or SP1 backend (not mock)
- **Performance**: Use `--release` mode for actual proof generation

### Architecture Maintenance
- **Keep core clean**: No backend-specific imports in `clvm_zk_core`
- **Single evaluation path**: Everything goes through `ClvmEvaluator` methods
- **Avoid circular dependencies**: Backends depend on core, not vice versa
- **Maintain determinism**: clvm_tools_rs compilation must be consistent across runs

## Zero-Knowledge Integration Workflow

### Compilation Phase (Host-side)
1. Compile chialisp → bytecode via `compile_chialisp_to_bytecode()`
2. Generate program hash → Deterministic identifier
3. Parameters passed at runtime via CLVM environment

### Proof Generation Phase (Guest-side)
1. Execute bytecode with parameters → Using `VeilEvaluator`
2. Generate proof → ZK proof of correct execution
3. Return program hash → Links proof to specific program

### Verification Phase (Verifier-side)
1. Verify proof → Cryptographic proof validation
2. Check program hash → Ensure proof corresponds to expected program
3. Extract output → Verified computation result

### Key Functions
```rust
// compile chialisp and get hash (with explicit hasher)
let (bytecode, hash) = compile_chialisp_to_bytecode(sha2_hash, "(mod (x y) (+ x y))")?;

// compile and get hash with default SHA-256 hasher
let hash = compile_chialisp_template_hash_default("(mod (x y) (+ x y))")?;

// parameters passed at runtime via CLVM environment, not at compile time
```

## Research Context

This project represents research into:
- **General-purpose zkVM applications**: Beyond simple arithmetic circuits
- **Privacy-preserving blockchain protocols**: Nullifiers, hidden spending conditions
- **Cross-platform zkVM compatibility**: Abstract backend interfaces
- **Real-world Chialisp execution**: Supporting the full language in zkVM context

The goal is to enable private execution of arbitrary Chialisp programs with cryptographic proof of correctness, supporting the broader research into privacy-preserving blockchain applications.

---

**Status**: ✅ Core + offers infrastructure complete, needs end-to-end testing
**Next Steps**: Run settlement test sequence, fix bugs, add validator support for settlement proofs
**Docs**: See STATUS.md for current state, IMPLEMENTATION_PLAN.md for next steps