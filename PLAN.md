# Veil PR Implementation Plan

**Project:** Privacy-preserving zkVM for Chialisp. WIP research, MIT licensed.
**Target:** `main`
**Current state (2026-03-29):** PRs 1–4 are complete and pushed. PRs 5 and 6+7 remain.

## Essential reading before starting

- `CLAUDE.md` — project rules, dev tips, architecture invariants (scope discipline, test-first, etc.)
- `DOCUMENTATION.md` — protocol details: nullifiers, stealth addresses, CATs, simulator, CLVM opcodes
- `.context/full-context.md` — complete architecture context: commitment scheme, TAIL flow, ring spend, settlement
- `.context/issues.md` — all known bugs and coverage gaps; cross-reference when implementing tests

## Codebase orientation

```
clvm_zk_core/src/     — no_std core: types, commitments, merkle, CLVM eval (shared by host + guest)
src/                  — host: ClvmZkProver facade, simulator, protocol, wallet, CLI
backends/mock/        — mock backend: full logic, no ZK (used for all tests via `cargo test-mock`)
backends/risc0/guest/ — RISC-0 zkVM guest: the actual ZK circuit
backends/sp1/program/ — SP1 zkVM guest: mirrors risc0 guest
```

**How proof generation works (critical for PR5):**
1. CLI calls `state.simulator.spend_coins(...)` or `simulator.mint_cat(...)` (new)
2. Simulator calls `Spender::create_spend_with_serial(...)` from `src/protocol/spender.rs`
3. Spender calls `ClvmZkProver::prove_with_serial_commitment(...)` — a static method in `src/lib.rs`
4. `ClvmZkProver` builds an `Input` struct and calls `backend.prove_with_input(input)`
5. Backend (mock/risc0/sp1) executes the circuit and returns `ZKClvmResult { proof_output, proof_bytes }`

For Mint: same chain, but use `ClvmZkProver::prove_with_input(Input { coin_mode: CoinMode::Mint(mint_data), ... })` directly (no existing `Spender` method for mint yet — add one or call prover directly from simulator).

**Key types (all in `clvm_zk_core/src/types.rs`):**
- `CoinMode` — `Execute` | `Spend(SerialCommitmentData)` | `Mint(MintData)` — exclusively selects proof type
- `MintData` — contains `tail_source`, `tail_params`, `output_puzzle_hash`, `output_amount`, `output_serial`, `output_rand`, `genesis_coin: Option<GenesisSpend>`
- `GenesisSpend` — serial, randomness, puzzle_hash, amount, merkle_path, merkle_root, leaf_index for the genesis coin
- `ProofOutput` — what the guest commits: `program_hash`, `nullifiers: Vec<[u8;32]>`, `clvm_res`, `public_values: Vec<Vec<u8>>`
- `SimulatorError` — defined at `src/simulator.rs:775`: `DoubleSpend`, `ProgramHashMismatch`, `ProofGeneration`, `TestFailed`, `Protocol`

**Test command aliases (defined in `.cargo/config.toml`):**
```
cargo test-mock    — runs all tests with mock backend (fast, no ZK)
cargo run-risc0    — runs with real RISC-0 proofs (slow, needs --release)
```

## Key concepts (read before touching guest code in PR5)

**TAIL program:** a Chialisp program that controls who can mint or melt a CAT asset. Its SHA256 hash is the asset's identifier (`tail_hash`). A coin's `tail_hash` is permanently bound at creation — you can't substitute a different TAIL program at spend time without detection.

**TAIL-on-delta:** when a CAT spend burns/melts tokens (`total_input > total_output`), the zkVM guest must run the TAIL program to authorize the supply change. The guest also verifies that `hash(tail_source) == coin.tail_hash` — this is the F-01 fix. Without it an attacker could substitute `(mod () 1)` for any restrictive TAIL.

**Ring spend:** multiple coins spent in a single ZK proof. Only the primary coin's puzzle runs for conditions; additional coins contribute their amounts as inputs and reveal their nullifiers. Because of this, `total_input` (sum of all ring coins) intentionally exceeds `total_output` (primary puzzle only) — this is NOT a melt. The TAIL-on-delta check must not fire for ring spends; it only fires when `tail_source` is explicitly provided by the caller.

**Stealth addresses:** sender encrypts a random nonce to the recipient's x25519 public key (80-byte note: ephemeral_pk || ChaCha20Poly1305 ciphertext). Recipient scans by decrypting with their private key and checking if the derived puzzle hash matches any coin on-chain. See `src/crypto_utils.rs` for the implementation and `DOCUMENTATION.md` for the full protocol.

---

## Status

| PR | Branch | Status | Notes |
|----|--------|--------|-------|
| 1 | `pr/01-core-types` | ✅ merged PR #20 | |
| 2 | `pr/02-simulator-migration` | ✅ pushed | |
| 3 | `pr/03-offer-fixes` | ✅ pushed | NM-001, FIX-02/05/06, offer indexing |
| 4 | `pr/04-stealth-nonce-encryption` | ✅ pushed | x25519+ChaCha20Poly1305, FIX-04 |
| 5 | `pr/05-cat-minting` | ✅ pushed | CoinMode::Mint, genesis nullifier, mint_cat, CLI, 6 tests |
| 6+7 | `pr/06-e2e-docs` | ☐ todo | combined: nullifier v2, e2e tests, docs |

---

> PRs 1–4 below are **complete and pushed** — documented for reference only.
> Start implementation at [PR 5](#pr-5-cat-minting--guests--mock--cli--tests).

---

## PR 1: Core types + security hardening ✅ MERGED

**Branch:** `pr/01-core-types`
**Base:** `main`
**Depends on:** nothing
**Description:** Additive-only changes to shared types and security hardening of arithmetic. No behavior change in existing code paths.

**Files:**
- `clvm_zk_core/src/lib.rs` — `checked_add` overflow fix in `enforce_ring_balance`, `modular_pow` zero-modulus guard
- `clvm_zk_core/src/types.rs` — new types: `MintData`, `GenesisSpend`; new fields on `Input`: `tail_source`, `mint_data`
- `src/protocol/structures.rs` — `ProofType::Mint = 3`
- `backends/risc0/src/lib.rs` — add `mint_data: None, tail_source: None` to `Input` construction
- `backends/risc0/src/recursive.rs` — same
- `backends/sp1/src/lib.rs` — same
- `backends/sp1/src/recursive.rs` — same

**Test commands:**
```
cargo check --no-default-features --features mock,testing
cargo test-mock
```

---

## PR 2: Simulator — SparseMerkleTree migration + settlement double-spend ✅ PUSHED

**Branch:** `pr/02-simulator-migration`
**Base:** `pr/01-core-types` (or main after PR 1 merged)
**Depends on:** PR 1
**Description:** Swap `rs_merkle::MerkleTree` for `clvm_zk_core::merkle::SparseMerkleTree` (fixed depth 20). Aligns simulator with what zkVM guests use internally. Adds settlement double-spend guard (`process_settlement` now returns `Result`). Adds state versioning (F-03).

**Files:**
- `src/simulator.rs` — full migration, `process_settlement` → `Result`, `state_version` field
- `tests/test_settlement_api.rs` — update callers of `process_settlement`
- `tests/test_settlement_recursive.rs` — compilation fix
- `tests/recursive_aggregation_tests.rs` — compilation fix
- `tests/test_conditional_spend.rs` — compilation fix
- `tests/signature_integration_tests.rs` — compilation fix

**Test commands:**
```
cargo test-mock   # all existing tests must still pass
cargo test-mock --test test_settlement_api
```

---

## PR 3: Offer system bugfixes ✅ PUSHED

**Branch:** `pr/03-offer-fixes`
**Base:** `pr/02-simulator-migration` (or main after PR 2 merged)
**Depends on:** PR 1 (for `tail_source` field on `Input`)
**Description:** Six independent bug fixes — all existed on main before this branch. See `VEIL_DIFFERENTIAL_REVIEW_2026-03-15.md` §"Positive Fixes" for original bug descriptions.

**Fixes included:**
- FIX-02: stable offer ID indexing (`offer_take_command` used vec index as ID; now uses `.position(|o| o.id == offer_id)`)
- FIX-06: taker coin marked spent after `offer-take` (wallet state was desynchronized from on-chain state)
- NM-002: maker pubkey linkage enforcement in `create_conditional_spend`
- correct per-output `tail_hash` assignment in offer settlement path
- FIX-05: scan dedup by `serial_commitment` not `puzzle_hash` (NOTE: this may overlap with PR 4 stealth scan changes — confirm which PR owns it when splitting)

**cli.rs functions changed (apply only these hunks):**
- `offer_take_command` — all changes (~lines 2459–2978 in `stealth_addresses_new`)
- no changes to `send_command`, `scan_command`, `faucet_command`, or `mint_command`

**Other files:**
- `src/protocol/spender.rs` — add `tail_source: Option<String>` param to `create_conditional_spend`; plumb it through to `Input`

**Test commands:**
```
cargo test-mock
cargo test-mock --test test_settlement_api
```

---

## PR 4: Stealth address nonce encryption ✅ PUSHED

**Branch:** `pr/04-stealth-nonce-encryption`
**Base:** `pr/03-offer-fixes` (or main after PR 3 merged)
**Depends on:** nothing (crypto_utils is independent; cli.rs stealth hunks don't touch offer or mint code)
**Description:** Replace plaintext 32-byte nonces with x25519 ECDH + ChaCha20Poly1305 encrypted notes (80 bytes: ephemeral_pk || ciphertext). Also fixes FIX-04 (nonce collision via per-recipient counters) and FIX-05 (scan dedup by `serial_commitment` not `puzzle_hash`). See "Key concepts" above for the stealth address protocol overview.

**Files:**
- `src/crypto_utils.rs` — full addition: `encrypt_stealth_nonce`, `decrypt_stealth_nonce`, and two unit tests (`test_stealth_nonce_encrypt_decrypt_roundtrip`, `test_stealth_nonce_wrong_key_fails`). No existing code changed.

**cli.rs functions changed (apply only these hunks):**
- `faucet_command` — encrypts the nonce before storing it (`encrypt_stealth_nonce(&nonce, &recipient_pubkey)`)
- `send_command` — per-recipient nonce counters (`stealth_nonce_counters` map) to prevent FIX-04 collision; passes encrypted nonce to simulator
- `scan_command` — decrypts encrypted notes with `decrypt_stealth_nonce`; dedup by `serial_commitment` (FIX-05); signature updated: `get_stealth_scannable_coins` now returns `&Vec<u8>` (encrypted bytes) instead of `[u8; 32]` (raw nonce)
- `wallet_command` — minor: display update for encrypted note format

**Do NOT touch in this PR:**
- `offer_take_command` (that's PR 3)
- `mint_command`, `SimAction`, `run_simulator_command` (that's PR 5)

**Test commands:**
```
cargo test-mock
cargo test-mock -- crypto_utils::tests
```

---

## ~~PR 5: CAT minting — guests + mock + CLI + tests~~

**Branch:** `pr/05-cat-minting`
**Base:** `pr/04-stealth-nonce-encryption`
**Depends on:** PR 1 (MintData/GenesisSpend types), PR 4 (base branch)

**Description:** Full CAT minting stack. `CoinMode::Mint` currently panics in all backends. This PR
implements mint in mock, risc0, and sp1 — including genesis coin one-time-use enforcement.

### What Mint proves (in-guest)

1. Compile `tail_source` → verify `hash(bytecode) == tail_hash` (F-01 same TAIL-hash check as Spend)
2. Execute TAIL with `tail_params` → assert `!is_clvm_nil(output)` (TAIL authorizes the mint)
3. If `genesis_coin` present:
   - Verify `serial_commitment = hash(serial || rand)`
   - Verify `coin_commitment = hash(tail_hash || amount || puzzle_hash || serial_commitment)` matches merkle leaf
   - Verify merkle proof (genesis coin is in tree)
   - Compute `genesis_nullifier = SHA256("clvm_zk_genesis_v1.0" || genesis_serial_number || genesis_tail_hash)`
   - Emit genesis_nullifier in `ProofOutput.nullifiers` — validator adds to nullifier set → prevents re-minting
4. Compute output `serial_commitment = hash(output_serial || output_rand)`
5. Compute output `coin_commitment = hash(tail_hash || output_amount || output_puzzle_hash || serial_commitment)`
6. Emit: `ProofOutput { nullifiers: [genesis_nullifier?], public_values: [output_coin_commitment] }`

Note: minted coin commitment goes in `public_values[0]` (not nullifiers) — it's an output not a spend.

### enforce_ring_balance guard

`enforce_ring_balance` checks `Σ(inputs) ≥ Σ(outputs)`. For Mint there's no input coin — balance
is not applicable. Add a guard in both mock and guests:
```rust
if !matches!(inputs.coin_mode, CoinMode::Mint(_)) {
    enforce_ring_balance(&inputs, &conditions)?;
}
```

### Files

- `clvm_zk_core/src/lib.rs` — add:
  ```rust
  pub const GENESIS_NULLIFIER_DOMAIN: &[u8] = b"clvm_zk_genesis_v1.0";
  pub fn compute_genesis_nullifier<H>(hasher: H, serial: &[u8;32], tail_hash: &[u8;32]) -> [u8;32]
  ```
  Note: genesis nullifier intentionally binds `tail_hash` (unlike spend nullifier — see ZK-01 in PR6+7).

- `backends/mock/src/backend.rs` — replace `CoinMode::Mint(_) => Err(...)` with full mint path (steps 1–6 above). Add `enforce_ring_balance` guard before Spend path.

- `backends/risc0/guest/src/main.rs` — same mint logic using `risc0_hasher`. Add Mint guard before `enforce_ring_balance`. CoinMode::Mint arm replaces the existing `panic!`.

- `backends/sp1/program/src/main.rs` — mirror risc0 guest changes.

- `backends/risc0/src/lib.rs`, `backends/sp1/src/lib.rs` — remove the host-side guard that rejects `CoinMode::Mint` before reaching guest (no longer needed).

- `src/simulator.rs` — add `mint_cat` method. **Do NOT add a `prover` parameter** — the simulator
  uses `ClvmZkProver` static methods internally (see `spend_coins_with_params_and_outputs` as the
  pattern, which calls `Spender::create_spend_with_serial` → `ClvmZkProver::prove_with_serial_commitment`).
  For mint, call `ClvmZkProver::prove_with_input` directly with `CoinMode::Mint(mint_data)`:
  ```rust
  pub fn mint_cat(
      &mut self,
      tail_source: &str,
      tail_params: Vec<ProgramParameter>,
      output_puzzle_hash: [u8; 32],
      output_puzzle_source: &str,   // needed to record WalletCoinWrapper.program
      output_amount: u64,
      output_serial: [u8; 32],
      output_rand: [u8; 32],
      genesis_coin: Option<GenesisSpend>,
  ) -> Result<([u8; 32], [u8; 32]), SimulatorError>
  // returns (coin_commitment, tail_hash)
  ```
  Implementation:
  1. Compile `tail_source` → get `tail_hash` (`compile_chialisp_to_bytecode` from `clvm_zk_core`)
  2. Build `MintData { tail_source, tail_params, output_puzzle_hash, output_amount, output_serial, output_rand, genesis_coin }`
  3. Build `Input { chialisp_source: "(mod () ())", program_parameters: vec![], coin_mode: CoinMode::Mint(mint_data), tail_hash: Some(tail_hash), ... }`
  4. Call `crate::ClvmZkProver::prove_with_input(input)` → `ZKClvmResult`
  5. Extract `coin_commitment` from `proof_output.public_values[0]` (32 bytes)
  6. Insert genesis nullifier (`proof_output.nullifiers[0]` if present) into `self.nullifier_set`
  7. Compute `serial_commitment = compute_serial_commitment(hash_data_default, output_serial, output_rand)`
  8. Insert new `CoinInfo` into `self.utxo_set` keyed by `serial_commitment`
  9. Insert `coin_commitment` into `self.coin_tree` + update `commitment_to_index`
  10. Return `(coin_commitment, tail_hash)`

- `src/cli.rs` — two changes:

  **Add `SimAction::Mint` variant** (follows the same clap pattern as `SimAction::Faucet`):
  ```rust
  /// Mint new CAT tokens using a TAIL program
  Mint {
      /// Wallet name to receive the minted coins
      wallet: String,
      /// TAIL program source (Chialisp). e.g. "(mod () 1)" for unlimited mint.
      #[arg(long)]
      tail: String,
      /// Amount to mint
      #[arg(long)]
      amount: u64,
      /// Wallet coin index of the genesis coin (optional, for single-issuance TAILs)
      #[arg(long)]
      genesis_coin: Option<usize>,
  }
  ```

  **Add `mint_command` function** (add routing arm `SimAction::Mint { wallet, tail, amount, genesis_coin }` in `run_simulator_command`, calling `mint_command(data_dir, &wallet, &tail, amount, genesis_coin)`):
  ```rust
  fn mint_command(
      data_dir: &Path,
      wallet_name: &str,
      tail_source: &str,
      amount: u64,
      genesis_coin_index: Option<usize>,
  ) -> Result<(), ClvmZkError>
  ```
  Implementation:
  1. Load `SimulatorState::load(data_dir)`
  2. Check wallet exists (same error pattern as `faucet_command`)
  3. Generate `output_serial` and `output_rand` via `rand::thread_rng().fill_bytes(...)`
  4. Get wallet's standard puzzle: `create_faucet_puzzle(amount)` or reuse wallet's last puzzle type
  5. If `genesis_coin_index` is Some: extract `GenesisSpend` from `wallet.coins[idx]`
     - Need serial/randomness/puzzle_hash/amount/tail_hash from the stored `WalletCoinWrapper`
     - Need merkle path: call `state.simulator.get_merkle_path_and_index(serial_commitment)`
  6. Call `state.simulator.mint_cat(tail_source, vec![], output_puzzle_hash, puzzle_source, amount, output_serial, output_rand, genesis_coin_opt)`
  7. Create `WalletCoinWrapper` for the minted coin with `tail_source: Some(tail_source.to_string())`
  8. Push to `wallet.coins`
  9. Call `state.save(data_dir)`
  10. Print: `"minted {} CAT (tail: {}) → commitment {}"` with amount, hex(tail_hash), hex(coin_commitment)

- `tests/test_cat_minting.rs` — new file:
  - `test_mint_unlimited_tail` — `(mod () 1)` TAIL mints, commitment in `public_values[0]`
  - `test_mint_genesis_nullifier` — genesis coin path: nullifier in `nullifiers[0]`
  - `test_mint_genesis_prevents_remint` — second mint with same genesis → rejected (nullifier set)
  - `test_mint_tail_nil_rejected` — TAIL returns nil → `Err`
  - `test_mint_tail_hash_mismatch` — wrong tail_source (hash mismatch) → `Err`
  - `test_mint_then_spend` — mint then spend the minted coin in same simulator session

**Test commands:**
```
cargo test-mock --test test_cat_minting
cargo test-mock   # full suite must still pass
```

---

## PR 6+7 (combined): Nullifier v2, E2E tests, documentation

**Branch:** `pr/06-e2e-docs`
**Base:** `pr/05-cat-minting`
**Depends on:** PR 5 (CAT lifecycle test requires mint)

**Description:** Three areas in one PR: (1) security fix from zkdocs review (nullifier missing
`tail_hash` and domain), (2) E2E test suite closing all coverage gaps, (3) documentation.

---

### Security Background: zkdocs Review Findings

Reviewed Trail of Bits zkdocs (https://www.zkdocs.com/docs/zkdocs/) against Veil.

**ZK-01 (HIGH): Nullifier missing `tail_hash` — cross-asset collision attack**

Current `compute_nullifier` = `SHA256(serial_number || program_hash || amount)` — no domain
separator, no asset type binding. An adversary who controls serial number selection can create a
CAT coin with identical `(serial_number, program_hash, amount)` to a target XCH coin. Spending the
CAT coin inserts the nullifier first, permanently blocking the XCH coin. In a multi-asset system
this is a soundness hole.

Also: `full-context.md` documents `"clvm_zk_nullifier_v1.0"` as a domain prefix — that domain does
NOT exist in the current code. Documentation is wrong.

Fix: new v2 scheme:
```
nullifier_v2 = SHA256("clvm_zk_nullifier_v2.0" || tail_hash || serial_number || program_hash || amount)
```

**ZK-02 (LOW): AGG_SIG_UNSAFE replay risk**

Opcode 49 does not bind to coin context. Document in DOCUMENTATION.md. No code change.

**ZK-03/04 (INFORMATIONAL):** SHA-256 commitments are sound. Fiat-Shamir handled by zkVM. No action.

---

### Part 1: Nullifier v2

**Exact callsites to update** (verified by grep — these are ALL the callsites):
```
backends/mock/src/backend.rs:346      — primary coin nullifier in CoinMode::Spend arm
backends/mock/src/backend.rs:421      — ring coin nullifier in additional_coins loop
backends/risc0/guest/src/main.rs:285  — primary coin nullifier
backends/risc0/guest/src/main.rs:381  — ring coin nullifier
backends/sp1/program/src/main.rs:270  — primary coin nullifier
backends/sp1/program/src/main.rs:366  — ring coin nullifier
```
The simulator does NOT call `compute_nullifier` — it consumes nullifiers from `proof_output.nullifiers`
already computed by the backend. `src/cli.rs` also needs no change.

**Files:**
- `clvm_zk_core/src/lib.rs` — add alongside the existing `compute_nullifier`:
  ```rust
  pub const NULLIFIER_V2_DOMAIN: &[u8] = b"clvm_zk_nullifier_v2.0"; // 22 bytes
  // domain(22) + tail(32) + serial(32) + program(32) + amount(8) = 126
  pub const NULLIFIER_V2_DATA_SIZE: usize = 126;

  pub fn compute_nullifier_v2<H>(
      hasher: H,
      tail_hash: &[u8; 32],
      serial_number: &[u8; 32],
      program_hash: &[u8; 32],
      amount: u64,
  ) -> [u8; 32]
  where H: Fn(&[u8]) -> [u8; 32]
  ```
  Also add `#[deprecated(note = "use compute_nullifier_v2 — v1 lacks tail_hash binding")]` to
  `compute_nullifier`. Update imports in the 3 backend files.

- `backends/mock/src/backend.rs` — at lines 346 and 421: change `compute_nullifier(` →
  `compute_nullifier_v2(hash_data,` and add `&tail_hash,` as first arg after hasher.
  Update import line 3 to include `compute_nullifier_v2`.

- `backends/risc0/guest/src/main.rs` — at lines 285 and 381: same pattern, hasher = `risc0_hasher`,
  `tail_hash = private_inputs.tail_hash.unwrap_or([0u8;32])` for primary coin,
  `tail_hash = coin.tail_hash` for ring coins.
  Update import line 10.

- `backends/sp1/program/src/main.rs` — at lines 270 and 366: same as risc0 guest.
  Update import line 9.

**Tests in `tests/test_nullifier_v2.rs`:**
- `test_v2_includes_tail_hash` — XCH and CAT coins with same serial/program/amount → DIFFERENT v2 nullifiers
- `test_v2_domain_separates_from_v1` — v2 output ≠ v1 output for same inputs
- `test_cross_asset_isolation` — mock backend: spending XCH coin does NOT block CAT coin with same serial

---

### Part 2: E2E Test Suite (coverage gap closure)

**`tests/test_e2e_xch_lifecycle.rs`**
Full XCH lifecycle: `faucet → send(A→B) → scan(B) → spend(B's coin) → verify nullifier + new output commitment`

**`tests/test_e2e_cat_lifecycle.rs`**
Full CAT lifecycle: `mint_cat(tail="(mod () 1)") → send_cat(A→B with stealth) → scan(B) → spend_cat`
Asserts CAT nullifier ≠ XCH nullifier for same serial (v2 enforcement in action).

**`tests/test_e2e_settlement.rs`**
Settlement lifecycle: `wallet_a has XCH, wallet_b has CAT → offer_create → offer_take → 4 outputs verified`
Post-settlement spend assertions (NM-001 regression guard):
- maker_change coin passes `spend` without error
- taker_change coin passes `spend` without error

**`tests/test_e2e_cat_ring_spend.rs`**
Currently untested path (see coverage gaps in issues.md):
`mint 2 CAT coins with same tail → ring_spend(coin_a + coin_b → output_c)`
Asserts TAIL run per-ring-coin, 2 nullifiers emitted, balance enforced.

**`tests/test_simulator_serde.rs`**
Addresses `rebuild_tree after deserialization` coverage gap:
`5-coin simulator state → serde_json round-trip → rebuild_tree() → all proofs valid, root matches`

---

### Part 3: Documentation

**`DOCUMENTATION.md`** — add section **Security Model**:

```markdown
## Security Model

### Nullifier Scheme (v2)
nullifier = SHA256("clvm_zk_nullifier_v2.0" || tail_hash || serial_number || program_hash || amount)

The tail_hash binding is CRITICAL: without it an adversary with serial number control could
pre-poison any XCH coin's nullifier slot by minting a CAT coin with identical parameters and
spending it first. v1 lacked this domain and tail_hash binding — v1 is deprecated.

### AGG_SIG_UNSAFE (opcode 49)
Does NOT bind signature to coin context (coin ID, puzzle hash). A valid AGG_SIG_UNSAFE signature
can be replayed to any coin using the same puzzle + public key. Use AGG_SIG_ME (opcode 50) in
production puzzles requiring spend-specific authorization.

### Commitment Scheme Trade-offs
Serial/coin commitments use SHA-256. Sound for current use. Not homomorphic — no efficient range
proofs. Pedersen commitments would unlock homomorphic properties at the cost of additional circuit
complexity. Acceptable trade-off for v1.

### Known Limitations (open issues)
- Stealth payment coin (offer output) uses raw stealth hash as puzzle — not spendable via standard
  flow until stealth-claim mechanism (PR8+)
- CoinMode::Mint supports unlimited TAILs (`(mod () 1)`) — production TAILs should be signature-gated
```

**`DOCUMENTATION.md`** — add section **Protocol Version History**:

| Field | v1 | v2 (current) | PR |
|-------|----|--------------|----|
| nullifier | SHA256(serial ‖ program ‖ amount) | SHA256(domain ‖ tail_hash ‖ serial ‖ program ‖ amount) | PR6+7 |
| coin_commitment | SHA256("clvm_zk_coin_v2.0" ‖ ...) | unchanged | PR1 |
| serial_commitment | SHA256("clvm_zk_serial_v1.0" ‖ ...) | unchanged | initial |

**`DOCUMENTATION.md`** — update existing demo scripts / examples to show `--tail` flag for minting.

---

### Test commands
```
cargo test-mock                              # full mock suite (all 5 new test files)
cargo test-mock --test test_nullifier_v2
cargo test-mock --test test_e2e_xch_lifecycle
cargo test-mock --test test_e2e_cat_lifecycle
cargo test-mock --test test_e2e_settlement
cargo test-mock --test test_e2e_cat_ring_spend
cargo test-mock --test test_simulator_serde
```

---

## Implementation notes

### Branch creation (PR5, PR6+7)
```
git fetch origin main:main
git checkout pr/04-stealth-nonce-encryption
git checkout -b pr/05-cat-minting
# ... implement PR5 ...
git checkout pr/05-cat-minting
git checkout -b pr/06-e2e-docs
# ... implement PR6+7 ...
```

### Order matters
PRs must be merged in order 1→6+7. PR6+7 depends on PR5 (CAT lifecycle test requires mint).
PR5 depends on PR4 (base branch and wallet tail_source field).

### zkdocs reference
https://www.zkdocs.com/docs/zkdocs/ — Trail of Bits ZK documentation.
ZK-01 through ZK-04 findings above reference sections on nullifier schemes, Fiat-Shamir,
hash-based commitments, and signature replay.
