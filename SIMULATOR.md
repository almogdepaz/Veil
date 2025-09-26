# CLVM-ZK Blockchain Simulator

Local privacy-preserving blockchain simulator that generates real zero-knowledge proofs. Create wallets, send private transactions, and test ZK applications without setting up a real blockchain.

## Quick start

```bash
# Initialize the simulator
cargo run -- sim init

# Create wallet
cargo run -- sim wallet alice create

# Fund it from the faucet
cargo run -- sim faucet alice --amount 5000

# Check your balance
cargo run -- sim wallet alice show
```

Run tests with:
```bash
cargo test --test simulator_tests --release
```

## How it works

Everything gets saved to `./simulator_data/state.json`:
- HD wallets with real cryptographic keys
- Observer wallets for monitoring
- Coins and transaction history
- Puzzle-locked coins

**Full wallets** can spend and view. **Observer wallets** can only view.

**Privacy**: spend secrets, program parameters, execution traces stay private. Program hashes, nullifiers, outputs, proofs are public.

## Examples

### Basic setup
```bash
# Initialize simulator
cargo run -- sim init

# Create wallets
cargo run -- sim wallet alice create
cargo run -- sim wallet bob create

# Fund wallet from faucet
cargo run -- sim faucet alice --amount 5000 --count 3

# Check wallet status
cargo run -- sim wallet alice show
cargo run -- sim status
```

### Private transactions
```bash
# Generate password puzzle program
cargo run -- hash-password mysecret
# Output: (= (sha256 password) 0x652c7dc687d98c9889304ed2e408c74b611e86a40caa51c4b43f1dd5913c5cd0)

# Alice locks coins with password
cargo run -- sim spend-to-puzzle alice 3000 \
  "(= (sha256 password) 0x652c7dc687d98c9889304ed2e408c74b611e86a40caa51c4b43f1dd5913c5cd0)" \
  --coins "0"

# Bob unlocks with password
cargo run -- sim spend-to-wallet \
  "(= (sha256 password) 0x652c7dc687d98c9889304ed2e408c74b611e86a40caa51c4b43f1dd5913c5cd0)" \
  bob 3000 --params "mysecret"
```

### More examples
```bash
# Send between wallets
cargo run -- sim send alice bob 2000 --coins "0,1"

# Custom puzzle programs
cargo run -- sim spend-to-puzzle alice 1000 "(> minimum_amount 100)" --coins "auto"
cargo run -- sim spend-to-wallet "(> minimum_amount 100)" bob 1000 --params "150"

# Using mod wrapper syntax for named parameters
cargo run -- sim spend-to-puzzle alice 1000 "(mod (threshold) (> threshold 100))" --coins "auto"
cargo run -- sim spend-to-wallet "(mod (threshold) (> threshold 100))" bob 1000 --params "150"

# Wallet management
cargo run -- sim wallets                    # List all wallets
cargo run -- sim wallet alice coins         # Show all coins
cargo run -- sim wallet alice unspent       # Show unspent coins
cargo run -- sim wallet alice balance       # Show balance only
```

## Features

- Real ZK proof generation using RISC0/SP1 backends
- Custom chialisp programs compiled inside zkvm guests
- HD wallets with cryptographic seeds
- Nullifier protocol prevents double-spending
- Observer mode for auditing without spending access
- Multi-coin transactions with batch ZK proof generation

### Choose zk backend
```bash
# Default: risc0 backend
cargo run -- sim init

# Use sp1 backend
cargo run --no-default-features --features sp1 -- sim init

# Skip zk proof generation for faster testing
RISC0_SKIP_BUILD=1 cargo run -- sim init
```

## Troubleshooting

Use `RISC0_SKIP_BUILD=1` for faster development (skips proof generation).
Reset corrupted state with `cargo run -- sim init`.
Switch backends with `--features sp1`.
Use `--release` mode for large operations.

## Use cases

Perfect for:
- Privacy application development - test guest-side compilation locally before mainnet
- Custom puzzle program development - rapid iteration with real guest-compiled ZK proofs
- Observer functionality prototyping - monitoring without spending access
- Compliance and auditing - transparent monitoring with privacy preservation
- Escrow and multi-sig services - complex spending conditions with deterministic program hashes
- Research and education - understand zero-knowledge privacy protocols and guest compilation
- Backend testing - verify risc0 and sp1 compilation consistency