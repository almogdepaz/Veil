# Veil

Zero-knowledge proof system for Chialisp. Compiles and executes arbitrary Chialisp programs inside zkVM (SP1/RISC0), generating proofs of correct execution without revealing inputs or program logic.

## Quick start

```bash
./install-deps.sh
./sim_demo.sh         # sp1 (default)
./sim_demo.sh risc0   # risc0
```

## Build

Backend-specific builds to separate target directories:

```bash
cargo risc0            # build to target/risc0/
cargo sp1              # build to target/sp1/
cargo mock             # build to target/mock/

cargo test-risc0       # test with risc0
cargo test-sp1         # test with sp1
cargo test-mock        # fast tests, no zkvm

cargo run-risc0 -- demo
cargo run-sp1 -- prove --expression "(mod (a b) (+ a b))" --variables "5,3"
```

Aliases in `.cargo/config.toml`. Each backend ~1GB disk.

## Architecture

```
veil/
├── clvm_zk_core/           # no_std chialisp compiler + clvm executor
│   └── src/
│       ├── lib.rs          # main exports, VeilEvaluator wrapper
│       ├── chialisp/mod.rs # clvm_tools_rs wrapper + with_standard_conditions()
│       ├── types.rs        # Input, ProofOutput, ProgramParameter, Condition
│       ├── coin_commitment.rs  # commitment schemes
│       └── merkle.rs       # merkle tree
│
├── backends/
│   ├── risc0/guest/        # risc0 guest program
│   ├── sp1/program/        # sp1 guest program
│   └── mock/               # no-zkvm testing
│
├── src/
│   ├── protocol/           # spender, puzzles, structures
│   ├── wallet/             # hd_wallet, stealth addresses
│   └── simulator.rs        # blockchain simulator
│
└── tests/
```

### Core flow

1. Host sends `Input` (chialisp source + parameters + optional coin data) to guest
2. Guest compiles chialisp via `clvm_tools_rs` → bytecode + program_hash
3. Guest executes bytecode via `VeilEvaluator` with injected crypto (sha256, bls, ecdsa)
4. Guest transforms CREATE_COIN conditions (4-arg → commitment)
5. Guest verifies coin commitments and merkle proofs if spending
6. Guest outputs `ProofOutput` (program_hash, nullifiers, clvm_res, public_values)

### Key types

```rust
// clvm_zk_core/src/types.rs
pub struct Input {
    pub chialisp_source: String,
    pub program_parameters: Vec<ProgramParameter>,
    pub serial_commitment_data: Option<SerialCommitmentData>,  // for spending
    pub tail_hash: Option<[u8; 32]>,  // asset type ([0;32] for XCH)
    pub additional_coins: Option<Vec<AdditionalCoinInput>>,  // ring spends
}

pub struct ProofOutput {
    pub program_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub clvm_res: ClvmResult,
    pub proof_type: u8,
    pub public_values: Vec<Vec<u8>>,
}

pub enum ProgramParameter {
    Int(u64),
    Bytes(Vec<u8>),
}
```

### clvm_tools_rs integration

Uses Chia's official compiler (`clvm_tools_rs` no_std branch) for full chialisp support including recursion. The `VeilEvaluator` wraps clvmr with injectable crypto handlers.

**zkvm limitation**: no filesystem, so `(include condition_codes.clib)` doesn't work. Use the helper:

```rust
use clvm_zk_core::with_standard_conditions;

let program = with_standard_conditions(
    "(mod (recipient amount)
        (list (list CREATE_COIN recipient amount)))"
);
// prepends defconstant for CREATE_COIN, AGG_SIG_ME, etc.
```

## Privacy protocols

### Nullifiers

Prevents double-spend without revealing which coin:

```
coin creation:
  serial_commitment = hash("clvm_zk_serial_v1.0" || serial_number || serial_randomness)
  coin_commitment = hash("clvm_zk_coin_v2.0" || tail_hash || amount || puzzle_hash || serial_commitment)

spending:
  guest verifies: program_hash == puzzle_hash
  guest verifies: serial_commitment, coin_commitment, merkle proof
  guest computes: nullifier = hash(serial_number || program_hash || amount)
  proof reveals: nullifier (not which coin)
```

### CREATE_COIN transformation

Inside zkvm, chialisp outputs 4-arg CREATE_COIN:
```chialisp
(list CREATE_COIN puzzle_hash amount serial_number serial_randomness)
```

Guest transforms to 1-arg before output:
```
CREATE_COIN(coin_commitment)  // hides puzzle_hash, amount, serial
```

### Stealth addresses

Hash-based unlinkable receiving. Sender derives shared_secret from receiver's pubkey + random nonce. Receiver scans with view key. ~200x faster than ECDH in zkVM.

## Simulator

Local blockchain with HD wallets, stealth addresses, merkle trees, real ZK proofs.

```bash
./sim_demo.sh
```

## Documentation

See [DOCUMENTATION.md](DOCUMENTATION.md) for detailed technical docs on:
- Nullifier protocol (double-spend prevention)
- Stealth addresses (unlinkable payments)
- CAT protocol (colored asset tokens)
- Simulator usage

## Adding backends

1. Create `backends/your_zkvm/` with guest program using `clvm_zk_core`
2. Inject crypto via `create_veil_evaluator(hasher, bls_verifier, ecdsa_verifier)`
3. Add feature flag to workspace `Cargo.toml`
4. Implement `ZKCLVMBackend` trait in `src/backends.rs`

See `backends/risc0/guest/src/main.rs` for reference.

## Examples

```bash
./run_examples.sh risc0    # run all examples with risc0
./run_examples.sh sp1      # run all examples with sp1
./run_examples.sh mock     # run all examples with mock

cargo run-risc0 --example alice_bob_lock  # run single example
```

## Tests

```bash
cargo test-mock                              # fast
cargo test-risc0 --test simulator_tests      # simulator
cargo test-risc0 --test bls_signature_tests  # bls
```
