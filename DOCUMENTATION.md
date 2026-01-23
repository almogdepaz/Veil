# veil documentation

comprehensive technical documentation for veil's privacy-preserving chialisp zkvm.

**quick links:**
- [nullifier protocol](#nullifier-protocol) - double-spend prevention
- [stealth addresses](#stealth-addresses) - unlinkable payments
- [CAT protocol](#cat-protocol) - colored asset tokens
- [simulator](#simulator) - local testing environment
- [clvm opcodes](#clvm-opcodes) - chia-standard opcode reference

---

## nullifier protocol

the nullifier protocol prevents double-spending in veil's privacy-preserving transactions.

### overview

each coin has a unique serial number that generates a deterministic nullifier when spent. the nullifier is public and stored on-chain - if someone tries to spend the same coin twice, the same nullifier would be revealed, and the blockchain rejects the second spend.

### key concepts

| term | definition |
|------|------------|
| **serial_number** | 32-byte secret tied to a specific coin |
| **serial_randomness** | 32-byte random value for hiding serial in commitment |
| **serial_commitment** | `hash("clvm_zk_serial_v1.0" \|\| serial_number \|\| serial_randomness)` |
| **coin_commitment** | `hash("clvm_zk_coin_v2.0" \|\| tail_hash \|\| amount \|\| puzzle_hash \|\| serial_commitment)` |
| **nullifier** | `hash(serial_number \|\| program_hash \|\| amount)` - revealed when spending |

### protocol flow

**1. coin creation:**
```
1. generate random serial_number (32 bytes)
2. generate random serial_randomness (32 bytes)
3. compute serial_commitment = hash("clvm_zk_serial_v1.0" || serial_number || serial_randomness)
4. compute coin_commitment = hash("clvm_zk_coin_v2.0" || tail_hash || amount || puzzle_hash || serial_commitment)
5. add coin_commitment to merkle tree (public)
6. store serial_number, serial_randomness privately (CRITICAL: losing these = losing funds)
```

**2. coin spending:**
```
1. prove knowledge of (serial_number, serial_randomness) that matches serial_commitment
2. prove coin_commitment is in merkle tree (membership proof)
3. prove program_hash matches the coin's puzzle_hash
4. compute nullifier = hash(serial_number || program_hash || amount)
5. reveal nullifier publicly (checked by blockchain)
6. execute puzzle program and reveal conditions
```

**3. blockchain validation:**
- checks nullifier hasn't been used before
- verifies zk proof is valid
- adds nullifier to spent set
- applies output conditions (CREATE_COIN, etc.)

### security guarantees

| guarantee | mechanism |
|-----------|-----------|
| **double-spend prevention** | each coin has exactly one valid nullifier |
| **program binding** | program_hash in nullifier prevents puzzle swaps |
| **amount binding** | amount in nullifier prevents amount-hiding attacks |
| **unlinkability** | serial_randomness excluded from nullifier |
| **hiding** | serial_number hidden inside ZK proof |

### domain separation

| operation | domain prefix |
|-----------|---------------|
| serial_commitment | `"clvm_zk_serial_v1.0"` |
| coin_commitment | `"clvm_zk_coin_v2.0"` |
| nullifier | (no prefix, direct concatenation) |

### code references

```
clvm_zk_core/src/lib.rs:
  - compute_serial_commitment()
  - compute_coin_commitment()
  - compute_nullifier()

clvm_zk_core/src/coin_commitment.rs:
  - SerialCommitment
  - CoinCommitment
  - CoinSecrets

backends/risc0/guest/src/main.rs:
  - nullifier verification in guest
```

### wallet requirements

**CRITICAL: losing serial_number or serial_randomness means permanent coin loss.**

wallets must:
1. derive secrets deterministically from seed (for recovery)
2. backup seed phrase securely
3. track which indices have been used

for stealth addresses, secrets are derived from `shared_secret`:
```
coin_secret = hash("veil_stealth_nullifier_v1" || shared_secret)
serial_number = hash(coin_secret || "serial")
serial_randomness = hash(coin_secret || "rand")
```

---

## stealth addresses

dual-key stealth address protocol using hash-based derivation for zkVM efficiency.

### security warning

**in nullifier mode (the only implemented mode), anyone with your view key CAN SPEND YOUR COINS.**

this is a fundamental design tradeoff for ~200x faster zkVM proving:
- serial secrets derive from shared_secret
- shared_secret derives from view_privkey + nonce
- view key holder can compute shared_secret → derive serial secrets → spend

**implications:**
- DO NOT give view key to auditors if you want audit-only access
- DO NOT share view key with anyone you wouldn't trust with your funds

### overview

stealth addresses allow a sender to create a payment that only the intended receiver can find and spend, without requiring any interaction. the receiver publishes a single stealth address and can receive unlimited unlinkable payments to it.

**key design choice:** uses hash-based derivation instead of ECDH for ~200x faster proving in zkVM (no elliptic curve math).

### key structure

each wallet has two keypairs (hash-based, not EC):

| keypair | private | public | purpose |
|---------|---------|--------|---------|
| view | `v` (32 bytes) | `V = sha256("stealth_pubkey_v1" \|\| v)` | scan for incoming payments |
| spend | `s` (32 bytes) | `S = sha256("stealth_pubkey_v1" \|\| s)` | derive spending authorization |

**stealth address** (published): `(V, S)` - 64 bytes total

### protocol

**sender creates payment:**
```
INPUT:
  - receiver's stealth address: (V, S)
  - amount, tail_hash, nonce_index

DERIVE:
  1. nonce = sha256("stealth_nonce_v1" || sender_privkey || nonce_index)
  2. shared_secret = sha256("stealth_v1" || V || nonce)
  3. coin_secret = sha256("veil_stealth_nullifier_v1" || shared_secret)
  4. serial_number = sha256(coin_secret || "serial")
  5. serial_randomness = sha256(coin_secret || "rand")

OUTPUT:
  - coin with puzzle_hash = STEALTH_NULLIFIER_PUZZLE_HASH
  - nonce (32 bytes, stored on-chain or transmitted to receiver)
```

**receiver scans for payments:**
```
FOR EACH (coin, nonce):
  1. shared_secret = sha256("stealth_v1" || V || nonce)
  2. check if coin.puzzle_hash == STEALTH_NULLIFIER_PUZZLE_HASH
  3. IF match: save (coin, shared_secret, nonce) to wallet
```

**receiver spends coin:**
```
1. shared_secret = sha256("stealth_v1" || V || nonce)
2. derive serial_number, serial_randomness from shared_secret
3. create ZK proof with nullifier protocol
4. reveal nullifier = hash(serial_number || program_hash || amount)
```

### hash-based vs ECDH

| aspect | ECDH (old) | hash-based (current) |
|--------|------------|----------------------|
| shared_secret derivation | `ephemeral * V` (EC math) | `sha256(V \|\| nonce)` |
| on-chain data | ephemeral_pubkey (33 bytes) | nonce (32 bytes) |
| proving cost in zkVM | ~2M cycles | ~10K cycles |
| receiver derives from pubkey | yes | needs nonce |

### privacy properties

| property | guarantee |
|----------|-----------|
| receiver unlinkability | different nonce per payment |
| sender anonymity | nonce doesn't reveal sender identity |
| amount hiding | hidden in coin_commitment |
| forward secrecy | compromise one shared_secret reveals only that payment |
| scanning privacy | only view_key holder can compute shared_secret |

### implementation

```rust
// create payment with HD-derived nonce
let payment = create_stealth_payment_hd(&sender_keys, nonce_index, &recipient_address);

// scan for payments
let scanned = view_key.try_scan_with_nonce(&puzzle_hash, &nonce);

// derive spending authorization
let spend_auth = receiver_keys.get_spend_auth(&shared_secret);
```

---

## CAT protocol

chia asset tokens (CATs) in veil's privacy-preserving system.

### asset identification

| asset type | tail_hash |
|------------|-----------|
| XCH (native) | `[0u8; 32]` (all zeros) |
| CAT | `hash(TAIL_program)` |

coins with different `tail_hash` values cannot be mixed in the same ring spend.

### commitment scheme (v2)

```
coin_commitment = hash(
    "clvm_zk_coin_v2.0" ||
    tail_hash ||           // 32 bytes - asset identifier
    amount ||              // 8 bytes
    puzzle_hash ||         // 32 bytes
    serial_commitment      // 32 bytes
)
```

### ring spends

multiple coins can be spent atomically in a single proof:
- all coins must share the same `tail_hash`
- each coin produces its own nullifier
- announcements are verified across all coins in the ring

### announcement handling

**chia vs veil coin_id:**
- chia: `coin_id = hash(parent_coin_id || puzzle_hash || amount)` - creates public transaction graph
- veil: `coin_commitment` as coin identifier - preserves privacy

| opcode | condition | hash formula |
|--------|-----------|--------------|
| 60 | CREATE_COIN_ANNOUNCEMENT | `hash(coin_commitment \|\| message)` |
| 61 | ASSERT_COIN_ANNOUNCEMENT | verifies hash exists in set |
| 62 | CREATE_PUZZLE_ANNOUNCEMENT | `hash(puzzle_hash \|\| message)` |
| 63 | ASSERT_PUZZLE_ANNOUNCEMENT | verifies hash exists in set |

### privacy properties

| property | how achieved |
|----------|--------------|
| hidden amounts | commitment hides amount |
| hidden asset type | commitment hides tail_hash |
| hidden transaction graph | no parent_coin_id reference |
| unlinkable spends | nullifier doesn't link to commitment |
| ring anonymity | can't determine coin boundaries in proof |

### differences from chia CAT2

| aspect | chia CAT2 | veil |
|--------|-----------|------|
| announcements | public on-chain | verified in zkVM, hidden |
| coin_id | `hash(parent \|\| puzzle \|\| amount)` | `coin_commitment` |
| ring accounting | public delta verification | private delta verification |
| CREATE_COIN output | public (puzzle, amount) | commitment only |
| transaction graph | fully visible | broken by nullifiers |

### data flow

```
Host constructs Input:
  - primary coin (puzzle, solution, secrets, merkle proof)
  - additional_coins[] for ring spends
  - tail_hash (None = XCH)

Guest processes:
  1. Compile and execute each coin's puzzle
  2. Verify merkle membership for each coin
  3. Compute nullifier for each coin
  4. Collect and verify announcements across ring
  5. Transform CREATE_COIN → commitments
  6. Filter announcement conditions

Output:
  - program_hash (primary coin)
  - nullifiers[] (one per coin)
  - transformed conditions (commitments only)
```

---

## simulator

local privacy-preserving blockchain simulator that generates real zero-knowledge proofs.

### quick start

```bash
./sim_demo.sh         # sp1 backend (default)
./sim_demo.sh risc0   # risc0 backend
```

**what it does:**
1. builds backend if needed
2. resets simulator state
3. creates wallets with stealth addresses
4. funds wallets from faucet
5. sends via stealth payment
6. receiver scans and discovers payments
7. shows timing and final balances

### manual commands

```bash
# initialize
cargo run-sp1 -- sim init

# create wallet
cargo run-sp1 -- sim wallet alice create

# fund from faucet
cargo run-sp1 -- sim faucet alice --amount 5000

# check balance
cargo run-sp1 -- sim wallet alice show
```

### program hash mechanism

**locking coins:**
```bash
cargo run -- sim spend-to-puzzle alice 1000 "(> secret_amount 500)"
```

1. simulator compiles chialisp in TEMPLATE mode
2. strips parameter names, keeps logic structure only
3. generates deterministic program hash = sha256(template_bytecode)
4. coin gets locked to this SPECIFIC program hash

**spending coins:**
1. compile same program in INSTANCE mode with actual secret values
2. generate zk proof: "i executed program X with hidden inputs"
3. proof links to original program hash but hides the actual values
4. verifier confirms proof matches the program hash without seeing logic

**privacy guarantee:** verifier only sees "valid proof for program ABC123..." but never sees:
- the actual spending condition logic
- the secret parameters used
- how the computation worked

### examples

**basic setup:**
```bash
cargo run-sp1 -- sim init
cargo run-sp1 -- sim wallet alice create
cargo run-sp1 -- sim wallet bob create
cargo run-sp1 -- sim faucet alice --amount 5000 --count 3
cargo run-sp1 -- sim wallet alice show
cargo run-sp1 -- sim status
```

**private transactions:**
```bash
# generate password puzzle
cargo run-sp1 -- hash-password mysecret
# Output: (= (sha256 password) 0x652c7dc...)

# alice locks coins with password
cargo run-sp1 -- sim spend-to-puzzle alice 3000 \
  "(= (sha256 password) 0x652c7dc...)" --coins "0"

# bob unlocks with password
cargo run-sp1 -- sim spend-to-wallet \
  "(= (sha256 password) 0x652c7dc...)" bob 3000 --params "mysecret"
```

**stealth payments:**
```bash
cargo run-mock -- sim init --reset
cargo run-mock -- sim wallet alice create
cargo run-mock -- sim wallet bob create
cargo run-mock -- sim faucet alice
cargo run-mock -- sim send alice bob 5000 --coins 0
cargo run-mock -- sim scan bob  # bob finds the payment
```

**more commands:**
```bash
cargo run-sp1 -- sim send alice bob 2000 --coins "0,1"
cargo run-sp1 -- sim wallets                    # list all
cargo run-sp1 -- sim wallet alice coins         # all coins
cargo run-sp1 -- sim wallet alice unspent       # unspent only
cargo run-sp1 -- sim wallet alice balance       # balance only
```

### choosing backend

```bash
cargo run-sp1 -- sim init      # sp1 backend
cargo run-risc0 -- sim init    # risc0 backend
cargo run-mock -- sim init     # mock (fast, no real proofs)
```

note: both `sim_demo.sh` and cargo default to sp1.

### features

- real ZK proof generation using RISC0/SP1 backends
- custom chialisp programs compiled inside zkvm guests
- HD wallets with cryptographic seeds
- nullifier protocol prevents double-spending
- observer mode for auditing without spending access
- multi-coin transactions with batch ZK proof generation

### troubleshooting

- use mock backend for fast testing: `cargo run-mock -- sim init`
- reset corrupted state: `cargo run-sp1 -- sim init --reset`
- `run-risc0` and `run-sp1` aliases include `--release` automatically

### use cases

- privacy application development
- custom puzzle program development
- observer functionality prototyping
- compliance and auditing
- escrow and multi-sig services
- research and education
- backend testing

---

## security considerations

### critical warnings

1. **losing serial_number or serial_randomness = permanent coin loss**
   - wallets derive keys deterministically from seed
   - backup your seed phrase

2. **view key = spend key in nullifier mode**
   - do not share view key with anyone you wouldn't trust with funds
   - no true view/spend separation currently

3. **nonce uniqueness**
   - reuse breaks unlinkability
   - HD derivation via `derive_nonce(index)` ensures uniqueness

4. **merkle tree attacks**
   - tree depth bounded (max 64) to prevent DoS

5. **front-running**
   - nullifier revealed in mempool could be front-run
   - use commit-reveal or encrypted mempool

### comparison to other systems

| system | nullifier scheme | hiding |
|--------|------------------|--------|
| zcash | `hash(note_commitment)` | yes |
| tornado cash | `hash(secret \|\| nullifier_secret)` | yes |
| veil | `hash(serial_number \|\| program_hash \|\| amount)` | yes |

veil's scheme includes program_hash to bind nullifier to specific puzzle logic, enabling programmable spending conditions.

---

## clvm opcodes

veil uses chia-standard clvm opcodes for compatibility with `clvmr` (the reference rust clvm implementation).

### core operators

| operator | symbol | opcode | description |
|----------|--------|--------|-------------|
| quote | q | 1 | return argument unevaluated |
| apply | a | 2 | apply function to arguments |
| if | i | 3 | conditional branch |
| cons | c | 4 | construct pair |
| first | f | 5 | get first element of pair |
| rest | r | 6 | get rest of pair |
| listp | l | 7 | check if value is a pair |

### comparison operators

| operator | symbol | opcode | description |
|----------|--------|--------|-------------|
| equal | = | 9 | equality comparison |
| greater | > | 21 | greater than comparison |

### arithmetic operators

| operator | symbol | opcode | description |
|----------|--------|--------|-------------|
| add | + | 16 | addition |
| subtract | - | 17 | subtraction |
| multiply | * | 18 | multiplication |
| divide | / | 19 | division |
| divmod | divmod | 20 | division with modulo |
| modulo | % | 61 | modulo operation |

### cryptographic operators

| operator | opcode | description |
|----------|--------|-------------|
| sha256 | 11 | SHA-256 hash |
| bls_verify | 59 | BLS signature verification |
| ecdsa_verify | 200 | ECDSA signature verification |

### condition opcodes

these are chia condition opcodes used in puzzle outputs:

| condition | opcode | description |
|-----------|--------|-------------|
| AGG_SIG_UNSAFE | 49 | aggregate signature (unsafe) |
| AGG_SIG_ME | 50 | aggregate signature (with coin ID) |
| CREATE_COIN | 51 | create new coin |
| RESERVE_FEE | 52 | reserve transaction fee |
| CREATE_COIN_ANNOUNCEMENT | 60 | create coin announcement |
| ASSERT_COIN_ANNOUNCEMENT | 61 | assert coin announcement |
| CREATE_PUZZLE_ANNOUNCEMENT | 62 | create puzzle announcement |
| ASSERT_PUZZLE_ANNOUNCEMENT | 63 | assert puzzle announcement |

### bytecode format

clvm bytecode encoding:
- `0x00-0x7F`: small atoms (literal values 0-127)
- `0x80`: nil (empty atom)
- `0x81-0xBF`: atom with 1-64 byte length prefix
- `0xFF`: cons pair marker

example bytecode for `(+ 5 3)`:
```
[255, 16, 255, 255, 1, 5, 255, 255, 1, 3, 128]
[cons, +, cons, cons, q, 5, cons, cons, q, 3, nil]
```

### references

- [chia clvm reference](https://chialisp.com/docs/ref/clvm)
- [clvmr repository](https://github.com/Chia-Network/clvm_rs)
