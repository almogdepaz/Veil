# CLVM-ZK Blockchain Simulator

Local privacy-preserving blockchain simulator that generates real zero-knowledge proofs. Create wallets, send private transactions, and test ZK applications without setting up a real blockchain.


### program hash mechanism

how programmable spending conditions work with privacy:

**locking coins**: when you create a puzzle-locked coin
```bash
cargo run -- sim spend-to-puzzle alice 1000 "(> secret_amount 500)"
```

1. simulator compiles chialisp in TEMPLATE mode
2. strips parameter names, keeps logic structure only
3. generates deterministic program hash = sha256(template_bytecode)
4. coin gets locked to this SPECIFIC program hash

**spending coins**: to unlock later
1. compile same program in INSTANCE mode with actual secret values
2. generate zk proof: "i executed program X with hidden inputs"
3. proof links to original program hash but hides the actual values
4. verifier confirms proof matches the program hash without seeing logic

**privacy guarantee**: verifier only sees "valid proof for program ABC123..." but never sees:
- the actual spending condition logic
- the secret parameters used
- how the computation worked

**nullifier protocol**: prevents double-spending using serial number commitments

when creating a coin:
```
serial_number = random(32 bytes)
serial_randomness = random(32 bytes)
serial_commitment = hash("clvm_zk_serial_v1.0" || serial_number || serial_randomness)
coin_commitment = hash("clvm_zk_coin_v1.0" || amount || puzzle_hash || serial_commitment)
```

when spending a coin:
```
// Guest verifies:
verify: hash(serial_number || serial_randomness) == serial_commitment
verify: coin_commitment exists in merkle tree

// Guest computes and reveals:
nullifier = hash(serial_number || program_hash)
```

**security properties:**
- each coin has exactly one valid nullifier for its (serial_number, program_hash) pair
- nullifier = hash(serial_number || program_hash) - uniquely identifies spent coin
- serial_randomness excluded from nullifier to prevent linkability with coin_commitment
- double-spend impossible: same nullifier can only be revealed once
- merkle membership proves coin exists without revealing which coin

**critical:** losing serial_number or serial_randomness = permanent coin loss. see [ENCRYPTED_NOTES.md](ENCRYPTED_NOTES.md) for backup procedures.

## Quick start

### Demo script

Run the full encrypted payment notes demo:

```bash
./sim_demo.sh         # RISC0 backend (default)
./sim_demo.sh sp1     # SP1 backend
```

**What it does:**
1. Builds backend if needed (`target/risc0/` or `target/sp1/`)
2. Resets simulator state
3. Creates alice and bob wallets with HD keys
4. Funds alice from faucet
5. Alice sends to bob (bob offline, doesn't receive yet)
6. Bob scans blockchain and discovers payments via encrypted notes
7. Bob sends back to alice
8. Shows timing and final balances


- Scan operations: instant (decryption only, no zkVM)

**Output:** Persistent state in `simulator_data/state.json` with all ZK proofs.

### manual commands

```bash
# Initialize the simulator (use --release for actual proof generation)
cargo run-sp1 --release -- sim init

# Create wallet
cargo run-sp1 --release -- sim wallet alice create

# Fund it from the faucet
cargo run-sp1 --release -- sim faucet alice --amount 5000

# Check your balance
cargo run-sp1 --release -- sim wallet alice show
```

Run tests with:
```bash
cargo test-sp1 --release --test simulator_tests
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
# Initialize simulator (use --release for actual proof generation)
cargo run-sp1 --release -- sim init

# Create wallets
cargo run-sp1 --release -- sim wallet alice create
cargo run-sp1 --release -- sim wallet bob create

# Fund wallet from faucet
cargo run-sp1 --release -- sim faucet alice --amount 5000 --count 3

# Check wallet status
cargo run-sp1 --release -- sim wallet alice show
cargo run-sp1 --release -- sim status
```

### Private transactions
```bash
# Generate password puzzle program
cargo run-sp1 --release -- hash-password mysecret
# Output: (= (sha256 password) 0x652c7dc687d98c9889304ed2e408c74b611e86a40caa51c4b43f1dd5913c5cd0)

# Alice locks coins with password
cargo run-sp1 --release -- sim spend-to-puzzle alice 3000 \
  "(= (sha256 password) 0x652c7dc687d98c9889304ed2e408c74b611e86a40caa51c4b43f1dd5913c5cd0)" \
  --coins "0"

# Bob unlocks with password
cargo run-sp1 --release -- sim spend-to-wallet \
  "(= (sha256 password) 0x652c7dc687d98c9889304ed2e408c74b611e86a40caa51c4b43f1dd5913c5cd0)" \
  bob 3000 --params "mysecret"
```

### More examples
```bash
# Send between wallets
cargo run-sp1 --release -- sim send alice bob 2000 --coins "0,1"

# Custom puzzle programs
cargo run-sp1 --release -- sim spend-to-puzzle alice 1000 "(> minimum_amount 100)" --coins "auto"
cargo run-sp1 --release -- sim spend-to-wallet "(> minimum_amount 100)" bob 1000 --params "150"

# Using mod wrapper syntax for named parameters
cargo run-sp1 --release -- sim spend-to-puzzle alice 1000 "(mod (threshold) (> threshold 100))" --coins "auto"
cargo run-sp1 --release -- sim spend-to-wallet "(mod (threshold) (> threshold 100))" bob 1000 --params "150"

# Wallet management
cargo run-sp1 --release -- sim wallets                    # List all wallets
cargo run-sp1 --release -- sim wallet alice coins         # Show all coins
cargo run-sp1 --release -- sim wallet alice unspent       # Show unspent coins
cargo run-sp1 --release -- sim wallet alice balance       # Show balance only
```

## encrypted payment notes

- alice sends to bob → creates encrypted note (bob doesn't receive coin yet)
- bob runs `sim scan bob` → decrypts notes, discovers payments
- uses x25519 ecdh + chacha20-poly1305 authenticated encryption
- supports memos (e.g., "payment from alice")

see [ENCRYPTED_NOTES.md](ENCRYPTED_NOTES.md) for full documentation.

**quick test:**
```bash
./TEST_ENCRYPTED_NOTES.sh
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
# Default: SP1 backend (requires --release)
cargo run-sp1 --release -- sim init

# Use RISC0 backend (requires --release)
cargo run-risc0 --release -- sim init

# Use mock backend for fast testing (no real proofs, no --release needed)
cargo run-mock -- sim init
```

## Troubleshooting

**Always use `--release` for SP1 and RISC0 backends** - they require release mode for proof generation.
Use mock backend for fast testing without real proofs: `cargo run-mock -- sim init`
Reset corrupted state with `cargo run-sp1 --release -- sim init --reset`
Switch backends using cargo aliases: `cargo run-risc0`, `cargo run-sp1`

## Use cases

Perfect for:
- Privacy application development - test guest-side compilation locally before mainnet
- Custom puzzle program development - rapid iteration with real guest-compiled ZK proofs
- Observer functionality prototyping - monitoring without spending access
- Compliance and auditing - transparent monitoring with privacy preservation
- Escrow and multi-sig services - complex spending conditions with deterministic program hashes
- Research and education - understand zero-knowledge privacy protocols and guest compilation
- Backend testing - verify risc0 and sp1 compilation consistency