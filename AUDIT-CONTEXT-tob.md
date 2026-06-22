# Veil (clvm-zk) -- Deep Audit Context

**Prepared for**: Trail of Bits security audit
**Date**: 2026-03-23
**Scope**: Full codebase at `/Users/home/Dev/Veil`
**Status**: Pure context building -- no vulnerability findings, no fix recommendations

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Architecture & Module Map](#2-architecture--module-map)
3. [Actors & Trust Boundaries](#3-actors--trust-boundaries)
4. [Phase 2 -- Ultra-Granular Function Analysis](#4-phase-2----ultra-granular-function-analysis)
   - 4.1 [clvm_zk_core -- Core Engine](#41-clvm_zk_core----core-engine)
   - 4.2 [Guest Programs (SP1 / RISC0)](#42-guest-programs-sp1--risc0)
   - 4.3 [Mock Backend](#43-mock-backend)
   - 4.4 [Protocol Layer](#44-protocol-layer)
   - 4.5 [Wallet & Stealth Addresses](#45-wallet--stealth-addresses)
   - 4.6 [Simulator](#46-simulator)
   - 4.7 [Settlement / Offers](#47-settlement--offers)
   - 4.8 [Recursive Aggregation](#48-recursive-aggregation)
5. [Phase 3 -- Global System Understanding](#5-phase-3----global-system-understanding)
   - 5.1 [State & Invariant Reconstruction](#51-state--invariant-reconstruction)
   - 5.2 [End-to-End Workflow Reconstruction](#52-end-to-end-workflow-reconstruction)
   - 5.3 [Trust Boundary Mapping](#53-trust-boundary-mapping)
   - 5.4 [Complexity & Fragility Clustering](#54-complexity--fragility-clustering)

---

## 1. System Overview

Veil is a privacy-preserving zero-knowledge proof system for Chialisp. It compiles and executes arbitrary Chialisp programs inside a zkVM (SP1 or RISC0), generating proofs of correct execution without revealing inputs or program logic. The system implements:

- **Nullifier-based double-spend prevention**: each coin has a serial number; spending reveals `nullifier = hash(serial_number || program_hash || amount)` without revealing which coin was spent.
- **Coin commitments**: `hash(domain || tail_hash || amount || puzzle_hash || serial_commitment)` -- leaves in a sparse Merkle tree.
- **CREATE_COIN transformation**: inside the zkVM, 4-arg CREATE_COIN conditions are transformed into single-arg coin commitments before output, hiding puzzle_hash, amount, and serial data.
- **CAT (Colored Asset Token) support**: `tail_hash` in coin commitments identifies asset types; TAIL programs authorize spending.
- **Ring spends**: multiple coins spent atomically in a single proof with balance enforcement.
- **Settlement / Offers**: maker creates conditional spend proof; taker creates settlement proof that validates trade logic.
- **Stealth addresses**: hash-based unlinkable payments (not ECDH).
- **Recursive proof aggregation**: N transaction proofs compressed into 1.

The workspace crate name is `clvm-zk` (library: `clvm_zk`). The core engine (`clvm_zk_core`) is `no_std` compatible for execution inside zkVM guests.

---

## 2. Architecture & Module Map

```
veil/
├── clvm_zk_core/                    # no_std core engine (runs in both host and guest)
│   └── src/
│       ├── lib.rs                   # Chialisp compilation, CLVM evaluation, commitment/nullifier
│       │                              computation, Merkle verification, balance enforcement,
│       │                              CLVM serialization/deserialization, condition processing,
│       │                              announcement handling
│       ├── types.rs                 # Input, ProofOutput, CoinMode, SerialCommitmentData,
│       │                              MintData, GenesisSpend, AdditionalCoinInput, ProgramParameter,
│       │                              ClvmZkError, ClvmResult, AggregatedOutput
│       ├── coin_commitment.rs       # SerialCommitment, CoinCommitment, CoinSecrets, XCH_TAIL,
│       │                              build_coin_commitment_preimage
│       ├── merkle.rs                # SparseMerkleTree, MerkleProof (sparse tree with empty-hash optimization)
│       ├── operators.rs             # ClvmOperator enum with opcode mapping (Chia-standard)
│       ├── clvm_parser.rs           # Binary CLVM bytecode parser (ClvmParser)
│       └── backend_utils.rs         # convert_proving_error, validate_proof_output,
│                                      validate_nullifier_proof_output
│
├── backends/
│   ├── risc0/
│   │   ├── src/lib.rs               # Risc0Backend host-side (prove, verify, host-side guards)
│   │   ├── src/recursive.rs         # RecursiveAggregator for RISC0
│   │   ├── guest/src/main.rs        # RISC0 guest: compile + execute + verify + commit
│   │   ├── guest_recursive/src/main.rs  # RISC0 recursive guest
│   │   └── guest_settlement/src/main.rs # RISC0 settlement guest
│   ├── sp1/
│   │   ├── src/lib.rs               # Sp1Backend host-side (prove, verify, host-side guards)
│   │   ├── src/recursive.rs         # RecursiveAggregator for SP1
│   │   ├── program/src/main.rs      # SP1 guest: compile + execute + verify + commit
│   │   ├── program_recursive/src/main.rs  # SP1 recursive guest
│   │   └── program_settlement/src/main.rs # SP1 settlement guest
│   └── mock/
│       ├── src/lib.rs               # MockBackend re-exports
│       └── src/backend.rs           # MockBackend: same logic as guest, no actual ZK proof
│
├── src/
│   ├── lib.rs                       # Top-level exports, ClvmZkProver (prove, verify, ring_spend),
│   │                                  Condition struct, condition_opcodes
│   ├── backends.rs                  # ZKCLVMBackend trait, backend() factory, trait impls
│   ├── protocol/
│   │   ├── mod.rs                   # Re-exports
│   │   ├── structures.rs            # PrivateCoin, PrivateSpendBundle, ProofType, ProtocolError,
│   │   │                              CreatedCoinOutput
│   │   ├── spender.rs               # Spender: create_spend_with_serial, create_ring_spend,
│   │   │                              create_conditional_spend, verify_nullifier
│   │   ├── puzzles.rs               # Puzzle factories: signature, password, delegated, settlement
│   │   ├── settlement.rs            # prove_settlement, SettlementOutput, SettlementProof,
│   │   │                              parse_maker_clvm_output
│   │   └── recursive.rs             # AggregatedProof (host-side type)
│   ├── wallet/
│   │   ├── mod.rs                   # Re-exports
│   │   ├── types.rs                 # Network, WalletError
│   │   ├── hd_wallet.rs             # CLVMHDWallet (BIP32), AccountKeys, ViewingKey,
│   │   │                              ViewOnlyWallet, WalletPrivateCoin
│   │   ├── stealth.rs               # StealthKeys, StealthAddress, StealthPayment,
│   │   │                              hash-based stealth address derivation, nullifier mode
│   │   └── tests.rs                 # Wallet unit tests
│   ├── simulator.rs                 # CLVMZkSimulator: blockchain state, nullifier set,
│   │                                  Merkle tree, UTXO tracking, spend_coins, process_settlement
│   ├── crypto_utils.rs              # hash_data_default, viewing tag generation
│   ├── payment_keys.rs              # PaymentKey, derive_stealth_puzzle_hash
│   ├── internal.rs                  # is_real_elf_available, serialization_error
│   ├── testing_helpers.rs           # CoinFactory, TestScenarios
│   ├── cli.rs                       # CLI interface (prove, verify, simulator commands)
│   └── main.rs                      # Entry point
│
└── tests/                           # Integration tests (~30 test files)
```

### Key Dependencies

| Dependency | Purpose |
|---|---|
| `clvm_tools_rs` (Chia no_std branch) | Chialisp compilation inside zkVM |
| `risc0-zkvm` | RISC0 zkVM prover/verifier |
| `sp1-zkvm` / `sp1-sdk` | SP1 zkVM prover/verifier |
| `bls12_381` (risc0 fork) | BLS signature verification in guest |
| `k256` | ECDSA (secp256k1) signature verification |
| `sha2` | SHA-256 hashing |
| `blst` | BLS verification in mock backend |
| `bip32` | HD wallet key derivation |
| `rs_merkle` | Host-side Merkle tree (for examples) |
| `borsh` | Proof serialization (RISC0 receipts) |
| `bincode` | Proof serialization (SP1 proofs) |

### Feature Flags (Mutually Exclusive Backends)

- `sp1` (default): SP1 zkVM backend
- `risc0`: RISC0 zkVM backend
- `mock`: No real ZK -- executes logic directly, serializes output as "proof"
- `testing`: Enables SHA-256 hasher for host-side testing
- `debug-logging`: Optional debug output

---

## 3. Actors & Trust Boundaries

### Actors

| Actor | Capabilities | Trust Level |
|---|---|---|
| **Coin Owner** | Holds serial_number + serial_randomness (CoinSecrets). Can spend coins by providing correct secrets to the zkVM guest. | Trusted with own funds |
| **Prover (Host)** | Constructs `Input` struct, invokes zkVM, receives proof. Has access to all private data. | Fully trusted (local) |
| **zkVM Guest** | Executes Chialisp, verifies commitments/Merkle proofs, emits ProofOutput. Cannot be influenced after ELF is compiled. | Trusted (deterministic) |
| **Verifier** | Checks zkVM proof validity and extracts public values (program_hash, nullifiers, conditions). Does NOT have private inputs. | Untrusted (external) |
| **Maker** (settlement) | Creates conditional spend proof with offer terms. | Semi-trusted |
| **Taker** (settlement) | Creates settlement proof accepting maker's offer. Receives maker's proof as public input. | Semi-trusted |
| **Validator** (L1 blockchain) | Checks nullifiers not previously spent, verifies proofs, adds coin commitments to Merkle tree. | External, assumed correct |
| **View Key Holder** | Can scan for stealth payments. In nullifier mode, CAN SPEND coins (documented security trade-off). | Trust-equivalent to spender in nullifier mode |

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│                    HOST (Prover)                         │
│  Full access to: private keys, serial numbers,           │
│  Chialisp source, parameters, Merkle paths               │
│                                                          │
│  ┌───────────────────────────────────────────────┐       │
│  │              zkVM GUEST                       │       │
│  │  Receives: Input (serialized)                 │       │
│  │  Compiles: Chialisp → bytecode                │       │
│  │  Executes: CLVM program                       │       │
│  │  Verifies: commitments, Merkle proofs         │       │
│  │  Outputs: ProofOutput (public)                │       │
│  │                                               │       │
│  │  TRUST BOUNDARY: guest code is fixed (ELF)    │       │
│  │  Host CANNOT influence guest logic             │       │
│  └───────────────────────────────────────────────┘       │
│                                                          │
│  Output: ZKClvmResult { proof_bytes, proof_output }      │
└──────────────────────────┬──────────────────────────────┘
                           │ proof_bytes (opaque)
                           ▼
┌─────────────────────────────────────────────────────────┐
│                    VERIFIER                               │
│  Receives: proof_bytes                                   │
│  Extracts: program_hash, nullifiers, CLVM output         │
│  Checks: proof valid, nullifiers not spent               │
│  CANNOT see: private inputs, serial numbers, source code │
└─────────────────────────────────────────────────────────┘
```

### Important Storage / State

| State | Location | Scope |
|---|---|---|
| `nullifier_set: HashSet<[u8; 32]>` | `CLVMZkSimulator` | Global (simulated blockchain) |
| `utxo_set: HashMap<[u8; 32], CoinInfo>` | `CLVMZkSimulator` | Global (keyed by serial_number) |
| `coin_tree: SparseMerkleTree` | `CLVMZkSimulator` | Global (Merkle tree of coin commitments) |
| `commitment_to_index: HashMap<[u8; 32], usize>` | `CLVMZkSimulator` | Lookup: commitment → leaf index |
| `CoinSecrets { serial_number, serial_randomness }` | Wallet / user | Per-coin private state |
| `AccountKeys { spending_key, viewing_key, nullifier_key, stealth_keys }` | `CLVMHDWallet` | Per-account derived keys |

---

## 4. Phase 2 -- Ultra-Granular Function Analysis

### 4.1 clvm_zk_core -- Core Engine

**File**: `clvm_zk_core/src/lib.rs`

#### 4.1.1 `compile_chialisp_to_bytecode(hasher, source) -> Result<(Vec<u8>, [u8; 32]), CompileError>`

**Purpose**: Compile Chialisp source to CLVM bytecode and compute its program hash.

**Inputs**:
- `hasher: fn(&[u8]) -> [u8; 32]` -- hash function (backend-specific SHA-256)
- `source: &str` -- raw Chialisp source code

**Outputs**:
- `(bytecode, program_hash)` where `program_hash = hasher(bytecode)`

**Invariants**:
1. Same source always produces identical bytecode (deterministic compilation via `clvm_tools_rs`)
2. Parameter names do NOT affect bytecode -- only program logic does
3. Program hash is the hash of the compiled bytecode, not the source

**Assumptions**:
1. `clvm_tools_rs::compile_chialisp` is deterministic across platforms
2. `clvm_tools_rs` no_std branch matches standard Chia compilation behavior
3. The hasher function is collision-resistant (SHA-256)
4. Source string encoding is consistent (UTF-8)
5. No side effects from compilation (pure function)

**Risk Considerations**:
1. If `clvm_tools_rs` compilation differs between host and guest (different platforms/versions), program_hash will mismatch, breaking spending
2. Compilation is expensive inside zkVM (~500-570s for complex programs, mitigated by precompiled bytecode for known puzzles)
3. No source code validation beyond what `clvm_tools_rs` provides

**First Principles**: The fundamental guarantee is that program_hash binds a coin to a specific spending program. If compilation is non-deterministic, this binding breaks.

**5 Whys (Why hash the bytecode, not the source?)**:
1. Source can have different whitespace/formatting → same logic
2. Parameter names don't affect semantics → shouldn't affect hash
3. Bytecode is the canonical representation after compilation
4. This matches Chia's approach (puzzle hashes are bytecode hashes)
5. Enables precompiled bytecode optimization without hash mismatch

#### 4.1.2 `compute_serial_commitment(hasher, serial_number, serial_randomness) -> [u8; 32]`

**Purpose**: Compute `hash("clvm_zk_serial_v1.0" || serial_number || serial_randomness)`.

**Invariants**:
1. Domain separator "clvm_zk_serial_v1.0" (19 bytes) prevents cross-protocol hash collisions
2. Total preimage is exactly 83 bytes (19 + 32 + 32)
3. Uses fixed-size array allocation (no heap, efficient in zkVM)
4. Changing either serial_number or serial_randomness changes the commitment

**Assumptions**:
1. serial_number is unique per coin (generated randomly or via HD derivation)
2. serial_randomness provides hiding (prevents brute-force of serial_number from commitment)
3. Domain separator "v1.0" won't conflict with future versions
4. 32-byte serial_number provides 256 bits of entropy (sufficient for collision resistance)
5. Hasher is SHA-256 (second-preimage resistant)

**Risk Considerations**:
1. If serial_randomness is predictable, serial_number can be brute-forced from the commitment
2. No minimum entropy check on serial_number or serial_randomness
3. The "v1.0" domain is hardcoded -- version migration requires careful handling

#### 4.1.3 `compute_coin_commitment(hasher, tail_hash, amount, puzzle_hash, serial_commitment) -> [u8; 32]`

**Purpose**: Compute `hash("clvm_zk_coin_v2.0" || tail_hash || amount_be || puzzle_hash || serial_commitment)`.

**Invariants**:
1. Domain separator "clvm_zk_coin_v2.0" (17 bytes)
2. Total preimage is exactly 121 bytes (17 + 32 + 8 + 32 + 32)
3. Amount is big-endian encoded (8 bytes)
4. tail_hash = [0u8; 32] for XCH (native currency)
5. Changing any component changes the commitment

**Assumptions**:
1. All fields are correctly populated (no validation in this function)
2. Amount fits in u64 (max ~18.4 exacoins)
3. puzzle_hash is the hash of compiled bytecode (not source)
4. serial_commitment is correctly computed from serial_number + serial_randomness
5. tail_hash correctly identifies the asset type

**Risk Considerations**:
1. No overflow check on amount (u64 max is the limit)
2. No validation that puzzle_hash is a valid program hash
3. If tail_hash is manipulated, coins of different asset types could be confused (mitigated by TAIL enforcement in guest)

#### 4.1.4 `compute_nullifier(hasher, serial_number, program_hash, amount) -> [u8; 32]`

**Purpose**: Compute `hash(serial_number || program_hash || amount_be)`.

**Invariants**:
1. NO domain separator (unlike serial and coin commitments) -- preimage is 72 bytes
2. Nullifier is unique per (serial_number, program_hash, amount) triple
3. Revealing the nullifier does NOT reveal which coin was spent (serial_number is private)
4. serial_randomness is NOT included (would allow linking commitment to nullifier)

**Assumptions**:
1. serial_number is kept secret until spending
2. program_hash and amount are known to the verifier (they're public in the proof)
3. The same serial_number with different program_hash/amount produces different nullifiers (cross-puzzle replay prevention)
4. No domain separator is intentional (backward compatibility)
5. 72-byte preimage is sufficiently distinct from other hash inputs

**Risk Considerations**:
1. Missing domain separator: could theoretically collide with other 72-byte hash inputs in the system (serial commitment preimage is 83 bytes, coin commitment is 121 bytes, so collision is unlikely but not formally prevented)
2. Including program_hash in nullifier means the same serial_number under different puzzles produces different nullifiers -- this is a security feature but also means nullifier uniqueness depends on the puzzle being correct
3. Amount inclusion prevents amount-manipulation attacks but means spending at different amounts produces different nullifiers

**5 Hows (How does double-spend prevention work?)**:
1. Coin owner knows serial_number (kept secret)
2. When spending, guest computes nullifier = hash(serial_number || program_hash || amount)
3. Nullifier is included in proof output (public)
4. Validator checks nullifier not in nullifier_set
5. If not present, adds to nullifier_set; if present, rejects (double-spend)

#### 4.1.5 `verify_merkle_proof(hasher, leaf_hash, merkle_path, leaf_index, expected_root) -> Result<(), &str>`

**Purpose**: Verify a Merkle authentication path from leaf to root.

**Invariants**:
1. Path length bounded by MAX_MERKLE_PROOF_DEPTH (64) -- DoS prevention
2. Left/right ordering determined by `leaf_index % 2` at each level
3. Index is halved at each level (`current_index /= 2`)
4. Concatenation order: even index = `hash(current || sibling)`, odd = `hash(sibling || current)`

**Assumptions**:
1. leaf_hash is the correct commitment for the coin being verified
2. merkle_path contains correct sibling hashes at each level
3. expected_root matches the current Merkle tree state
4. The tree uses binary Merkle structure (not N-ary)
5. Hasher is the same one used to build the tree

**Risk Considerations**:
1. `current_index.is_multiple_of(2)` is used for even/odd check -- this is equivalent to `current_index % 2 == 0` but uses a nightly-ish API (actually stable since 1.73.0, but worth noting)
2. No check that merkle_path length matches expected tree depth -- a shorter path would compute a different root (which would fail the root comparison), but this is implicit rather than explicit
3. The guest uses `usize::try_from(leaf_index)` which will fail on 32-bit platforms for indices > u32::MAX -- host-side guards in SP1/RISC0 backends catch this

#### 4.1.6 `enforce_ring_balance(private_inputs, conditions) -> Result<(u64, u64), &str>`

**Purpose**: Verify that sum(input amounts) >= sum(output CREATE_COIN amounts) and all coins have the same tail_hash.

**Invariants**:
1. MUST run BEFORE CREATE_COIN transformation (which replaces 4-arg with 1-arg, losing amount info)
2. Inflation prevention: `total_output_amount > input_sum` is rejected
3. Deflation is allowed (burning/fees): `total_output_amount < input_sum` is OK
4. All ring coins must share the same tail_hash (single-asset ring)
5. CoinMode::Execute has no balance constraint (no coin input)
6. CoinMode::Mint is explicitly rejected (must use dedicated mint validation)

**Assumptions**:
1. Amount parsing from conditions is correct (handles variable-length big-endian encoding)
2. CREATE_COIN conditions with 2 or 4 args contain amount in args[1]
3. Checked arithmetic prevents overflow (uses `checked_add().expect()`)
4. Primary coin amount from `commitment_data.amount` is trustworthy (it was committed in coin_commitment)
5. Additional coins' amounts from their `serial_commitment_data.amount` are trustworthy

**Risk Considerations**:
1. `checked_add().expect()` panics on overflow rather than returning an error -- in guest this is OK (panic = invalid proof), but in mock backend this crashes the test
2. CREATE_COIN conditions with args.len() != 2 and != 4 contribute 0 to output sum -- a malformed condition could bypass balance checking
3. The "allows deflation" design means value can be destroyed -- this is intentional for fees but could be misused
4. Balance enforcement only runs in Spend mode; Execute mode has no checks

#### 4.1.7 `atom_to_number(value: &ClvmValue) -> Result<i64, &str>`

**Purpose**: Convert CLVM atom to i64.

**Assumptions**:
1. Multi-byte numbers are big-endian
2. No sign bit handling (all bytes interpreted as positive contribution via shift-or)
3. Numbers larger than i64 will silently wrap/truncate

**Risk Considerations**:
1. No sign handling: negative CLVM integers (high bit set) will be misinterpreted as large positive numbers
2. Numbers > 8 bytes will overflow i64 silently (no error, just wrapping)
3. This function is used in condition parsing -- if amounts are misinterpreted, balance enforcement could be wrong

#### 4.1.8 `number_to_atom(num: i64) -> ClvmValue`

**Purpose**: Convert i64 to CLVM atom with proper signed encoding.

**Invariants**:
1. 0 encodes as empty atom (nil)
2. 1-127 encode as single byte
3. Positive numbers with high bit set get leading 0x00 (prevents sign interpretation)
4. Negative numbers have high bit set in first byte
5. i64::MIN handled specially to avoid overflow on `.unsigned_abs()`

**Risk Considerations**:
1. The special case for i64::MIN is necessary but adds complexity
2. Large negative numbers encode correctly but the reverse path (`atom_to_number`) doesn't handle sign -- asymmetric encoding/decoding

#### 4.1.9 `process_announcements(conditions, puzzle_hash, coin_id, hasher) -> Result<Vec<Condition>, &str>`

**Purpose**: Verify announcement assertions are satisfied and filter announcement conditions from output.

**Invariants**:
1. CREATE_PUZZLE_ANNOUNCEMENT: `hash = sha256(puzzle_hash || message)`
2. CREATE_COIN_ANNOUNCEMENT: `hash = sha256(coin_id || message)` (only if coin_id provided)
3. All ASSERT_*_ANNOUNCEMENT conditions must match a previously created announcement
4. Announcement conditions are removed from output (privacy: don't leak cross-coin validation)

**Assumptions**:
1. `puzzle_hash` is the correct hash for the coin being spent
2. `coin_id` may be None (coin announcements skipped)
3. Announcements and assertions can appear in any order in conditions
4. Linear scan for matching (O(n*m) where n=assertions, m=announcements)
5. Same announcement can satisfy multiple assertions

**Risk Considerations**:
1. If coin_id is None, CREATE_COIN_ANNOUNCEMENT is silently ignored but ASSERT_COIN_ANNOUNCEMENT still requires a match -- this could cause unexpected failures
2. No deduplication: the same announcement hash could be created multiple times
3. O(n*m) matching could be slow for large condition sets (unlikely in practice)

#### 4.1.10 `parse_variable_length_amount(bytes: &[u8]) -> Result<u64, &str>`

**Purpose**: Parse variable-length big-endian amount to u64.

**Invariants**:
1. Empty bytes = 0
2. Max 8 bytes (u64 limit)
3. Shorter byte sequences are left-padded with zeros

**Assumptions**:
1. CLVM uses compact big-endian encoding for amounts
2. Leading zeros are not significant
3. No sign bit handling (all values treated as unsigned)

**Risk Considerations**:
1. A value like `[0x80]` (1 byte) would be parsed as 128, but in CLVM this is nil (empty atom encoded as 0x80). However, this function receives the already-parsed atom bytes, not raw CLVM encoding, so this should not be an issue.

#### 4.1.11 `is_clvm_nil(output: &[u8]) -> bool`

**Purpose**: Check if serialized CLVM output represents nil (false/zero/empty).

**Invariants**:
1. Empty slice = nil
2. `[0x80]` = nil (empty atom encoding in CLVM)

**Assumptions**:
1. Used to check TAIL program authorization (nil = not authorized)
2. Any non-nil value is considered "truthy" (TAIL authorization success)

**Risk Considerations**:
1. TAIL programs that return `0` will have their output serialized as `[0x80]` (nil), correctly detected
2. TAIL programs that return any non-zero/non-nil value are considered authorized -- there's no validation of WHAT they return, only that it's truthy

#### 4.1.12 CLVM Serialization (`encode_clvm_value`, `ClvmParser::parse`)

**Purpose**: Encode/decode CLVM values to/from binary format.

**Invariants**:
1. 0xFF prefix = cons pair
2. 0x00-0x7F = single-byte atom
3. 0x80 = nil (empty atom)
4. 0x81-0xBF = atom with size in lower 6 bits (1-63 bytes)
5. 0xC0-0xDF = 2-byte size encoding
6. 0xE0-0xEF = 3-byte size encoding
7. 0xF0-0xF7 = 4-byte size encoding
8. 0xF8-0xFF = 5-byte size encoding (uses u64 for size to handle 32-bit platforms)

**Assumptions**:
1. Encoding follows Chia's standard CLVM serialization format
2. Recursive parsing for cons pairs (stack depth limited by input size)
3. No circular structures possible (tree, not graph)

**Risk Considerations**:
1. Deep nesting of cons pairs could cause stack overflow (no explicit depth limit in parser)
2. The 5-byte size encoding supports atoms up to ~1 GB -- could cause memory exhaustion in zkVM guest
3. No maximum total size limit on parsed input

### 4.2 Guest Programs (SP1 / RISC0)

**Files**: `backends/sp1/program/src/main.rs`, `backends/risc0/guest/src/main.rs`

Both guests follow an identical structure (code is nearly identical between SP1 and RISC0, differing only in I/O and hashing APIs).

#### 4.2.1 Guest Main Flow

```
1. Read Input from host
2. Compile Chialisp → bytecode + program_hash
   (or use precompiled bytecode for known puzzles)
3. Create VeilEvaluator with backend-specific crypto
4. Serialize parameters to CLVM args
5. Execute CLVM bytecode → (output_bytes, conditions)
6. BALANCE ENFORCEMENT (enforce_ring_balance)
7. Transform CREATE_COIN conditions (4-arg → 1-arg commitment)
8. If CoinMode::Spend:
   a. Verify program_hash == commitment_data.program_hash
   b. Verify serial commitment
   c. Verify coin commitment
   d. Verify Merkle proof
   e. If CAT (tail_hash != [0;32]):
      - Compile TAIL source
      - Verify TAIL hash matches committed tail_hash
      - Execute TAIL program
      - Assert TAIL output is non-nil
   f. Compute nullifier
9. Process additional coins (ring spend):
   a. Same verification as primary for each
   b. Each produces its own nullifier
10. Commit ProofOutput { program_hash, nullifiers, clvm_res, proof_type, public_values }
```

**Invariants (enforced by guest)**:
1. Program hash is computed from compiled bytecode, not provided by host
2. Serial commitment is recomputed and verified against provided value
3. Coin commitment is recomputed and verified against provided value
4. Merkle proof is verified against provided root
5. TAIL hash is verified by compiling TAIL source and comparing hash
6. Balance enforcement runs before CREATE_COIN transformation
7. Nullifier is computed inside guest (not provided by host)

**Assumptions**:
1. Host provides correct Merkle path (if wrong, proof generation fails)
2. Host provides correct serial_number and serial_randomness (if wrong, commitment verification fails)
3. clvm_tools_rs produces identical bytecode on host (64-bit) and guest (32-bit RISC-V)
4. SHA-256 implementation is consistent between host and guest
5. TAIL program source is the same as what was used when the coin was created

**Risk Considerations**:
1. Precompiled bytecode optimization: `DELEGATED_PUZZLE_BYTECODE` and `DELEGATED_PUZZLE_HASH` are hardcoded constants. If they don't match the actual compilation output of `DELEGATED_PUZZLE_SOURCE`, the optimization is broken silently. No runtime verification of this invariant.
2. The guest uses `assert!` and `panic!` for error conditions, which causes the proof to be invalid (not a security issue per se, but error messages are lost)
3. Both guests handle `CoinMode::Mint` with `panic!("not yet implemented")` -- there's a host-side guard, but if somehow bypassed, the guest panics
4. `max_cost = 1_000_000_000` is hardcoded -- no way for host to configure

#### 4.2.2 Guest BLS Verification (SP1 and RISC0)

**Purpose**: Verify BLS12-381 signatures inside zkVM.

**Implementation**: min_sig variant (pk in G2 = 96 bytes, sig in G1 = 48 bytes).

**Invariants**:
1. Public key bytes are left-padded to 96 bytes
2. Signature bytes are left-padded to 48 bytes
3. Uses DST `CLVM_ZK_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_`
4. Pairing check: `e(sig, G2_gen) == e(H(msg), pk)`

**Assumptions**:
1. Short key/signature bytes should be left-padded (convention for big-endian field elements)
2. The DST matches what was used for signing
3. `bls12_381` crate (risc0 fork) is correct

**Risk Considerations**:
1. Left-padding short keys with zeros: if a key is short because leading bytes are zero (legitimate), this is correct. But if a key is short because it's truncated, padding produces a different (invalid) key -- the verification will fail (not a security issue, but could cause confusing errors)
2. No minimum size check on key/signature bytes (a 1-byte input would be padded to 96/48 bytes and likely fail decompression)

#### 4.2.3 Guest ECDSA Verification

**Purpose**: Verify secp256k1 ECDSA signatures.

**Implementation**: Delegates to `verify_ecdsa_signature_with_hasher` in `clvm_zk_core`.

**Invariants**:
1. Accepts compressed (33 bytes) or uncompressed (65 bytes) public keys
2. Signature must be exactly 64 bytes (compact r||s format)
3. If message is 32 bytes, treated as pre-hashed
4. If message is not 32 bytes, hashed with SHA-256

**Assumptions**:
1. Short signatures are NOT padded (security: prevents accepting truncated signatures)
2. 32-byte message pre-hash convention is correct for the caller's use case

**Risk Considerations**:
1. The 32-byte pre-hash assumption means a legitimate 32-byte message won't be hashed, while a 31-byte or 33-byte message will be. This is a common convention but callers must be aware.
2. No domain separation for ECDSA message hashing -- the hash is just SHA-256(message) without any prefix

### 4.3 Mock Backend

**File**: `backends/mock/src/backend.rs`

**Purpose**: Executes the same logic as the guest programs but without generating actual ZK proofs. Used for testing.

**Key Difference from Real Backends**:
1. No actual proof generation -- output is Borsh-serialized ProofOutput
2. `verify_proof_and_extract` always returns `(true, ...)` -- no verification
3. BLS verification uses `blst` crate instead of `bls12_381` (different library, same algorithm)

**Invariants**:
1. Performs all the same checks as guest: serial commitment, coin commitment, Merkle proof, TAIL enforcement, balance enforcement
2. Signature validation (AGG_SIG conditions) uses ECDSA verification
3. CREATE_COIN transformation is identical to guest

**Assumptions**:
1. Mock backend behavior matches real backends for all non-proof-related logic
2. Tests passing with mock backend indicate correctness of protocol logic
3. Differences in hashing between mock (sha2 crate) and guest (platform-specific SHA-256) don't affect results

**Risk Considerations**:
1. Mock backend verification always succeeds -- any test relying on verification is not testing real verification
2. Mock uses different BLS library (blst vs bls12_381) -- subtle behavioral differences could exist
3. Mock serializes ProofOutput with Borsh; RISC0 uses Borsh for Receipt, SP1 uses bincode -- format differences

### 4.4 Protocol Layer

#### 4.4.1 `Spender::create_spend_with_serial`

**File**: `src/protocol/spender.rs`

**Purpose**: Create a single-coin spend proof.

**Flow**:
1. Validate coin (puzzle_hash and serial_commitment not all-zeros)
2. Compute coin_commitment from coin fields
3. Determine tail_hash (None for XCH, Some for CATs)
4. Call `ClvmZkProver::prove_with_serial_commitment`
5. Verify at least one nullifier in proof output
6. Construct and validate `PrivateSpendBundle`

**Invariants**:
1. Coin commitment is recomputed on host side (must match guest computation)
2. Single-coin spend produces exactly one nullifier
3. PrivateSpendBundle is validated before return

**Assumptions**:
1. `coin.serial_commitment` was computed with the same hasher as the guest will use
2. `crypto_utils::hash_data_default` (SHA-256) matches the backend's hasher
3. puzzle_code matches coin.puzzle_hash (if not, guest will reject)

#### 4.4.2 `Spender::create_ring_spend`

**Purpose**: Spend multiple coins atomically in a single proof.

**Flow**:
1. Verify all coins have same tail_hash
2. Validate each coin
3. Compute coin_commitment for each
4. Construct AdditionalCoinInput for each non-primary coin
5. Call `ClvmZkProver::prove_ring_spend`
6. Verify N nullifiers in output (one per coin)
7. Construct and validate PrivateSpendBundle

**Invariants**:
1. All coins must share the same tail_hash (enforced on host side AND in guest via enforce_ring_balance)
2. Number of nullifiers in proof must equal number of input coins
3. Primary coin is first; additional coins follow

**Risk Considerations**:
1. If host provides coins with different tail_hashes but claims they're the same, guest's enforce_ring_balance will catch it
2. The order of additional_coins matters for nullifier ordering -- no explicit ordering guarantee

#### 4.4.3 `Spender::create_conditional_spend`

**Purpose**: Create a ConditionalSpend proof (for offers -- not directly submittable).

**Identical to `create_spend_with_serial` except**:
1. ProofType is set to ConditionalSpend (not Transaction)
2. Only first nullifier is used (single nullifier for conditional spend)
3. Bundle is NOT directly submittable -- must be wrapped in Settlement proof

#### 4.4.4 `PrivateSpendBundle::extract_created_coins`

**Purpose**: Parse CREATE_COIN outputs from proof conditions.

**Handles three cases**:
1. 1 arg: Private coin (commitment only)
2. 2 args: Transparent coin (puzzle_hash + amount)
3. 4 args: Transparent coin (puzzle_hash + amount + serial data)

**Risk Considerations**:
1. 4-arg CREATE_COIN conditions should have been transformed to 1-arg by the guest -- if they appear in output, something is wrong
2. `parse_variable_length_amount` failure returns 0 (via `unwrap_or(0)`) -- silent amount loss

### 4.5 Wallet & Stealth Addresses

#### 4.5.1 `CLVMHDWallet::derive_account`

**File**: `src/wallet/hd_wallet.rs`

**Purpose**: Derive account keys from BIP32 master key.

**Derivation Path**: `m/44'/{coin_type}'/{account_index}'/0'`
- Mainnet coin_type: 8444 (Chia)
- Testnet coin_type: 1

**Derived Keys**:
1. `spending_key = SHA-256("clvm_zk_spend_auth_v1" || account_bytes || network_byte)`
2. `viewing_key = SHA-256("clvm_zk_view_key_v1" || spending_key)`
3. `stealth_keys = StealthKeys::from_seed(SHA-256("clvm_zk_stealth_seed_v1" || account_bytes))`
4. `nullifier_key = SHA-256("clvm_zk_nullifier_key_v1" || spending_key)`

**Invariants**:
1. Seed must be 16-64 bytes
2. Non-32-byte seeds are SHA-256 hashed to 32 bytes before BIP32
3. All derivation is hardened (preventing public key derivation attacks)
4. Different networks produce different keys

**Assumptions**:
1. Domain separators prevent cross-purpose key reuse
2. SHA-256 is a sufficient KDF for deriving keys from BIP32 output
3. viewing_key derived from spending_key means compromised spending_key compromises viewing_key (but not vice versa... except stealth_keys are derived from different seed)

**Risk Considerations**:
1. `viewing_key` is derived from `spending_key`, creating a one-way dependency. BUT stealth_keys are derived from account_bytes directly -- meaning even without spending_key, the stealth seed could be derived if account_bytes are known
2. `nullifier_key` is derived from spending_key -- its purpose is unclear (not used in the nullifier computation, which uses serial_number)
3. The KDF is a single SHA-256 hash -- no key stretching. This is likely OK since the input (BIP32 derived key) already has full entropy

#### 4.5.2 Stealth Address System

**File**: `src/wallet/stealth.rs`

**CRITICAL SECURITY MODEL**: View key holders CAN spend coins in nullifier mode. This is documented and intentional (performance trade-off: ~200x faster than ECDH in zkVM).

**Stealth Payment Flow**:
1. Sender derives nonce deterministically: `hash("veil_stealth_nonce_v1" || view_privkey || index_le)`
2. Sender computes `shared_secret = hash("stealth_v1" || recipient.view_pubkey || nonce)`
3. Sender uses `STEALTH_NULLIFIER_PUZZLE_HASH` as puzzle_hash (trivial puzzle `(mod () ())`)
4. Sender encrypts nonce to receiver (out of band)
5. Receiver decrypts nonce, derives same shared_secret
6. Receiver derives spending secrets: `coin_secret = hash("veil_stealth_nullifier_v1" || shared_secret)`, then `serial_number = hash(coin_secret || "serial")`, `serial_randomness = hash(coin_secret || "rand")`

**Invariants**:
1. All nullifier-mode stealth coins share the same puzzle_hash (trivial puzzle)
2. Security comes from nullifier protocol, not puzzle logic
3. Nonces are deterministic (wallet recovery from seed + indices)
4. Different nonces produce different shared_secrets (unlinkability)

**Assumptions**:
1. Nonce is successfully transmitted to receiver (if lost, funds are still spendable by anyone who can derive the nonce)
2. Hash-based "pubkey" derivation (`hash("stealth_pubkey_v1" || privkey)`) is one-way
3. Domain separators prevent cross-protocol derivation

**Risk Considerations**:
1. **View key = spend key in nullifier mode**: Anyone with the view key can derive shared_secret, then derive coin_secrets, then spend. This is a fundamental design trade-off.
2. Trivial puzzle `(mod () ())` means there's NO puzzle-level security -- all security relies on the nullifier protocol. If the nullifier set is compromised (e.g., reset), all stealth coins are double-spendable.
3. Deterministic nonce derivation means an attacker who knows `view_privkey` and a nonce index can compute all past and future nonces
4. `privkey_to_pubkey` uses `hash("stealth_pubkey_v1" || privkey)` -- this is NOT an elliptic curve operation. The "pubkey" is just a hash of the privkey. This means there's no EC math involved, which is simpler but also means standard EC assumptions don't apply.
5. Tag-based scanning (4-byte tags) has ~1/2^32 false positive rate per scanned coin

### 4.6 Simulator

**File**: `src/simulator.rs`

**Purpose**: Local blockchain simulator for testing. Maintains nullifier set, UTXO set, and Merkle tree.

#### 4.6.1 `CLVMZkSimulator::spend_coins_with_params_and_outputs`

**Purpose**: Execute spend transactions with proof generation.

**Flow**:
1. Get current Merkle root
2. Check if all coins have same tail_hash (ring spend optimization)
3. If ring-eligible: single `create_ring_spend` call
4. Otherwise: separate `create_spend_with_serial` for each coin
5. Check nullifiers not already spent
6. Extract CREATE_COIN commitments from proof output
7. Add nullifiers to nullifier_set
8. Add new commitments to Merkle tree
9. If output_coins provided: validate commitment match, add to UTXO set
10. Remove spent coins from UTXO set
11. Increment block height

**Invariants**:
1. Double-spend detected by checking nullifier_set BEFORE adding new nullifiers
2. Coin commitments from proof output are added to Merkle tree
3. Block height increments with each transaction
4. UTXO set is keyed by serial_number (not commitment)

**Assumptions**:
1. Proof generation is correct (simulator trusts the ZK backend)
2. Output coin validation checks commitment match but doesn't verify the proof itself
3. Ring spend optimization is transparent to the protocol

**Risk Considerations**:
1. UTXO set keyed by serial_number: if two coins somehow have the same serial_number, only one is tracked
2. `coin_tree` is not serialized (marked `#[serde(skip)]`) -- must be rebuilt from `merkle_leaves` after deserialization
3. CREATE_COIN conditions with args.len() != 1 are rejected -- this means transparent coins (2-arg) can't be created through spend_coins

### 4.7 Settlement / Offers

**File**: `src/protocol/settlement.rs`

#### 4.7.1 `prove_settlement(params: SettlementParams) -> Result<SettlementProof, ProtocolError>`

**Purpose**: Taker creates a settlement proof that accepts maker's offer.

**V2 Optimization**: No recursive verification of maker's proof inside taker's guest. Instead:
1. Host deserializes maker's proof to extract settlement terms
2. Settlement terms are passed as public inputs to taker's settlement guest
3. Validator must verify BOTH proofs separately (atomicity preserved)

**Flow (RISC0/SP1)**:
1. Verify maker's proof is ConditionalSpend type
2. Deserialize maker's receipt/proof to extract journal/public_values
3. Parse maker's CLVM output to get: maker_change_commitment, offered, requested, maker_pubkey
4. Compute taker's serial commitment
5. Build SettlementInput with all data
6. Generate settlement proof via settlement guest
7. Decode settlement output from proof
8. Return SettlementProof

**Settlement Guest Logic** (both RISC0 and SP1 guests):
1. Read SettlementInput
2. Verify taker's coin ownership (serial commitment, coin commitment, Merkle proof)
3. Assert taker has sufficient funds (amount >= requested)
4. Compute payment puzzle via hash-based stealth: `hash("stealth_v1" || maker_pubkey || nonce)`
5. Create 4 coin commitments:
   - payment (taker → maker, requested amount)
   - taker_goods (maker → taker, offered amount)
   - taker_change (taker's leftover)
   - maker_change (passed through from maker's proof)
6. Compute taker's nullifier
7. Commit SettlementOutput

**Invariants**:
1. Maker's proof must be ConditionalSpend type
2. Taker must have amount >= requested
3. taker_change_amount = taker_coin.amount - requested (no underflow check -- amount >= requested asserted above)
4. Settlement creates exactly 4 coin commitments
5. maker_pubkey is echoed in output for validator verification

**Assumptions**:
1. Maker's proof is valid (host extracts terms; validator verifies proof separately)
2. Maker's journal/public_values are honestly extracted by host (taker's host)
3. Payment nonce is transmitted to maker out of band (encrypted)
4. tail_hash correctly identifies asset types for cross-asset trades

**Risk Considerations**:
1. **Host-side parsing of maker's proof**: The taker's host deserializes the maker's proof and extracts settlement terms. A malicious taker host could provide fake terms to the settlement guest. However, the validator checks the maker's proof independently, so fake terms would result in an invalid settlement.
2. **No recursive verification**: The settlement guest does NOT verify the maker's proof. This is the V2 optimization. Security relies on the validator checking both proofs. If the validator is buggy, a taker could create a settlement with fake maker terms.
3. `parse_maker_clvm_output` does deep pattern matching on CLVM structure -- if the maker's puzzle outputs a different structure, parsing fails with generic errors
4. The settlement guest doesn't verify that maker_change_commitment was correctly computed -- it accepts it as a pass-through. The validator must verify this independently.

### 4.8 Recursive Aggregation

**Files**: `backends/risc0/src/recursive.rs`, `backends/sp1/src/recursive.rs`

**Purpose**: Aggregate N base proofs into a single recursive proof.

**RISC0 approach**:
1. Deserialize all child receipts
2. Extract journal bytes
3. Add receipts as assumptions (`env_builder.add_assumption`)
4. Run recursive guest that verifies all assumptions
5. Output aggregated nullifiers + conditions + commitments

**SP1 approach**:
1. Deserialize all child proofs
2. Decode ProofOutput from public values
3. Build recursive input with expected outputs
4. Run recursive guest
5. Output aggregated data

**Invariants**:
1. At least 1 proof required
2. All input proofs must be valid base proofs
3. Aggregated output contains ALL nullifiers and conditions from children
4. RISC0 uses `env::verify()` inside recursive guest (cryptographic verification)

**Risk Considerations**:
1. SP1 recursive aggregation passes expected outputs as input data (not cryptographically verified inside guest) -- the structure of the recursive guest determines security
2. The recursive guest programs were not fully analyzed (source in `guest_recursive/` and `program_recursive/`)
3. Aggregation changes the proof structure -- verifiers must handle aggregated proofs differently

---

## 5. Phase 3 -- Global System Understanding

### 5.1 State & Invariant Reconstruction

#### Global Invariants

| ID | Invariant | Where Enforced | Failure Mode |
|---|---|---|---|
| G1 | Each nullifier appears at most once in nullifier_set | Simulator.spend_coins, Validator | Double-spend |
| G2 | Coin commitment in Merkle tree proves coin existence | Guest Merkle verification | Spend of non-existent coin |
| G3 | program_hash == hash(compiled_bytecode) | Guest (compiles and hashes) | Wrong puzzle spending |
| G4 | serial_commitment == hash(domain \|\| serial_number \|\| serial_randomness) | Guest recomputation | Invalid commitment |
| G5 | coin_commitment == hash(domain \|\| tail_hash \|\| amount \|\| puzzle_hash \|\| serial_commitment) | Guest recomputation | Invalid commitment |
| G6 | nullifier == hash(serial_number \|\| program_hash \|\| amount) | Guest computation | Incorrect nullifier |
| G7 | sum(outputs) <= sum(inputs) for Spend mode | enforce_ring_balance (guest + mock) | Inflation attack |
| G8 | All ring coins share same tail_hash | enforce_ring_balance + Spender | Cross-asset ring |
| G9 | TAIL program hash matches committed tail_hash | Guest TAIL enforcement | Wrong TAIL authorization |
| G10 | TAIL program returns non-nil (authorization) | Guest TAIL execution | Unauthorized CAT spend |
| G11 | Backends are mutually exclusive (compile-time) | lib.rs compile_error! | Build failure |
| G12 | Parameter names don't affect bytecode hash | clvm_tools_rs behavior | Privacy property |

#### State Transitions

```
COIN LIFECYCLE:

Created (add_coin)                    →  coin_commitment in Merkle tree
                                         serial_number → CoinInfo in UTXO set

Spent (spend_coins)                   →  nullifier added to nullifier_set
                                         serial_number removed from UTXO set
                                         new coin_commitments added to Merkle tree

Settlement (process_settlement)       →  2 nullifiers added (maker + taker)
                                         4 coin_commitments added to Merkle tree
```

### 5.2 End-to-End Workflow Reconstruction

#### Workflow 1: Simple XCH Spend

```
1. SETUP:
   - Create PrivateCoin with puzzle_hash, amount, serial_commitment
   - Store CoinSecrets (serial_number, serial_randomness)
   - Compute coin_commitment and insert into Merkle tree

2. SPEND:
   Host:
   - Get Merkle path for coin
   - Construct Input with CoinMode::Spend
   - Invoke backend.prove_with_input(input)

   Guest:
   - Compile Chialisp → bytecode + program_hash
   - Execute CLVM with parameters → conditions
   - enforce_ring_balance (output <= input)
   - Transform CREATE_COIN conditions (4-arg → commitment)
   - Verify program_hash matches commitment_data.program_hash
   - Verify serial_commitment
   - Verify coin_commitment
   - Verify Merkle proof
   - Compute nullifier
   - Commit ProofOutput

3. VALIDATE:
   - Check nullifier not in nullifier_set
   - Add nullifier to nullifier_set
   - Add new coin_commitments to Merkle tree
```

#### Workflow 2: CAT Ring Spend

```
1. SETUP:
   - Create N coins with same tail_hash (CAT)
   - Each has unique CoinSecrets
   - All in same Merkle tree

2. SPEND:
   Host:
   - Get Merkle paths for all coins
   - First coin is "primary", rest are "additional_coins"
   - For each coin: provide tail_source (TAIL program source)
   - Invoke backend.prove_ring_spend

   Guest:
   - Compile + execute primary coin's Chialisp
   - enforce_ring_balance (all coins same tail_hash, output <= input)
   - Transform CREATE_COIN conditions
   - Verify primary coin (serial, coin commitment, Merkle, TAIL)
   - For each additional coin:
     - Compile + verify program_hash
     - Verify serial, coin commitment, Merkle
     - Compile TAIL, verify hash matches tail_hash, execute TAIL
     - Compute nullifier
   - Commit ProofOutput with N nullifiers

3. VALIDATE:
   - Check all N nullifiers not in set
   - Add all N nullifiers
   - Add new commitments to tree
```

#### Workflow 3: Offer Settlement

```
1. MAKER creates offer:
   - Create PrivateCoin for asset A
   - Use settlement_assertion_puzzle (outputs: CREATE_COIN change + offer terms)
   - Call Spender::create_conditional_spend → ConditionalSpend proof
   - Publish proof (maker's journal/public_values are visible)

2. TAKER accepts offer:
   - Create PrivateCoin for asset B
   - Call prove_settlement with:
     - maker_proof (ConditionalSpend)
     - taker's coin data
     - payment nonce, puzzle hashes, serial data for new coins

   Settlement Guest:
   - Accepts maker's terms as public input (extracted by host)
   - Verifies taker's coin ownership
   - Asserts taker.amount >= requested
   - Derives payment puzzle (stealth: hash("stealth_v1" || maker_pubkey || nonce))
   - Creates 4 commitments: payment, goods, taker_change, maker_change
   - Computes taker nullifier
   - Commits SettlementOutput

3. VALIDATOR processes:
   - Verifies maker's ConditionalSpend proof
   - Verifies taker's Settlement proof
   - Checks maker_pubkey in settlement matches offer
   - Adds both nullifiers to set
   - Adds all 4 commitments to tree
   - Atomicity: both proofs must be valid or entire tx rejected
```

### 5.3 Trust Boundary Mapping

#### Input Path Analysis

| Input | Source | Validated Where | What Could Go Wrong |
|---|---|---|---|
| `chialisp_source` | Host (user/wallet) | Guest (compilation) | Malicious program → guest compiles and runs it (sandboxed by zkVM cost limit) |
| `program_parameters` | Host | Guest (CLVM execution) | Oversized params → cost exceeded; wrong values → wrong output |
| `serial_number` | Host (wallet secret) | Guest (recomputes commitments) | Wrong value → commitment mismatch → proof fails |
| `serial_randomness` | Host (wallet secret) | Guest (recomputes commitments) | Same as above |
| `merkle_path` | Host (from simulator/blockchain) | Guest (verify_merkle_proof) | Wrong path → root mismatch → proof fails |
| `merkle_root` | Host (from simulator/blockchain) | Guest (comparison) | Stale root → proof valid for old state but validator rejects |
| `tail_source` | Host | Guest (compile + verify hash) | Source doesn't match committed tail_hash → guest rejects |
| `tail_params` | Host | Guest (TAIL execution) | Wrong params → TAIL rejects authorization |
| `maker_proof` (settlement) | Maker (public) | Host deserializes; Validator verifies proof | Fake proof → validator catches; Fake terms → mismatch with proof |

#### Output Path Analysis

| Output | From | To | What's Revealed |
|---|---|---|---|
| `program_hash` | Guest | Verifier | Hash of the puzzle bytecode (NOT source code) |
| `nullifiers` | Guest | Verifier → nullifier_set | Hash of (serial_number \|\| program_hash \|\| amount) -- does NOT reveal which coin |
| `clvm_res.output` | Guest | Verifier | Transformed conditions (CREATE_COIN → commitment only) |
| `proof_bytes` | Backend | Verifier | ZK proof (no private data leakage) |

### 5.4 Complexity & Fragility Clustering

#### High-Complexity Areas

1. **Settlement proof construction** (`src/protocol/settlement.rs`):
   - Deeply nested CLVM pattern matching (`extract_create_coin_commitment_host`)
   - Two parallel implementations (RISC0 and SP1) with duplicated struct definitions
   - Host-side parsing of maker's proof output is fragile (depends on exact CLVM structure)
   - Multiple inline struct definitions within feature-gated blocks

2. **Guest programs** (both backends):
   - ~400 lines of critical security logic duplicated between SP1 and RISC0
   - Precompiled bytecode constants must be kept in sync with source
   - Complex interleaving of compilation, execution, verification, and transformation

3. **CLVM serialization/deserialization** (`clvm_zk_core/src/lib.rs`):
   - 5 size encoding ranges in both encoder and parser
   - Recursive parsing without depth limits
   - Edge cases around nil encoding (0x80), single-byte atoms, sign bits

4. **Balance enforcement + CREATE_COIN transformation ordering**:
   - Balance enforcement MUST run before CREATE_COIN transformation
   - If ordering is wrong, amount information is lost before balance check
   - This ordering constraint is documented in comments but not enforced structurally

#### High-Assumption Areas

1. **Cross-platform compilation determinism**: clvm_tools_rs must produce identical bytecode on host (x86_64) and guest (rv32im/rv32imac). Any difference breaks program_hash matching.

2. **Hasher consistency**: SHA-256 is implemented differently per backend:
   - RISC0 guest: `risc0_zkvm::sha::Impl::hash_bytes` (accelerated)
   - SP1 guest: `sha2::Sha256` (software)
   - Mock: `sha2::Sha256` (software)
   - Host: `sha2::Sha256` (software)
   All must produce identical output for identical input.

3. **Serialization format compatibility**:
   - `Input` uses both serde and borsh derive macros
   - Host serializes via serde; guest deserializes via serde
   - RISC0 uses borsh for Receipt serialization
   - SP1 uses bincode for proof serialization
   - `ProofOutput` has `#[borsh(skip)]` on `proof_type` field -- this means proof_type is NOT included in borsh serialization

4. **Stealth address nonce transmission**: The protocol assumes nonces are encrypted and transmitted out of band. If nonce transmission fails, the receiver cannot derive spending secrets (funds are locked until nonce is recovered or brute-forced, which is computationally infeasible).

#### Fragility Points

1. **`ProofOutput.proof_type` is `#[borsh(skip)]`**: When RISC0 serializes the proof (borsh), proof_type is omitted. When deserializing, it defaults to 0 (Transaction). This means the proof_type field is NOT committed in RISC0 proofs -- it's only meaningful on the host side.

2. **`DELEGATED_PUZZLE_BYTECODE` / `DELEGATED_PUZZLE_HASH` hardcoded constants**: These must exactly match `compile_chialisp_to_bytecode(hasher, DELEGATED_PUZZLE_SOURCE)`. If clvm_tools_rs is updated and compilation output changes, the precompiled constants become stale. No CI check enforces this.

3. **`atom_to_number` does not handle signed integers**: CLVM uses signed big-endian encoding, but this function treats all bytes as unsigned. This could cause incorrect amount parsing in edge cases with large values.

4. **`nullifier_key` in AccountKeys**: Derived from spending_key but never used in the codebase for nullifier computation. Nullifiers are computed from serial_number, not nullifier_key. This key may be vestigial or planned for future use.

5. **`MintData` and `CoinMode::Mint`**: Fully defined in types but not implemented in any backend (all backends reject or panic). Guest programs panic on Mint mode. Host-side guards in RISC0 and SP1 backends prevent reaching the guest. Mock backend returns an error.

6. **Simulator `coin_tree` is `#[serde(skip)]`**: After deserialization, `rebuild_tree()` must be called manually. The serialization format (`simulator_data/state.json`) persists `merkle_leaves` but not the tree itself. If `rebuild_tree()` is forgotten, the tree is empty and all Merkle proofs fail.

---

*End of audit context. This document covers pure context building only -- no vulnerability findings, fix recommendations, or exploit reasoning are included.*
