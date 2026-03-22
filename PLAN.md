# PR Breakdown Plan: stealth_addresses_new → main

**Goal:** Decompose PR #17 into 7 focused PRs merged in dependency order.
**Net result:** After all 7 are merged, diff vs current `stealth_addresses_new` should be empty.
**Source branch:** `stealth_addresses_new`
**Target:** `main`

## Background reading

- `CLAUDE.md` — project rules, dev tips, architecture invariants
- `DOCUMENTATION.md` — protocol details: nullifiers, stealth addresses, CATs, simulator, CLVM opcodes
- `VEIL_DIFFERENTIAL_REVIEW_2026-03-15.md` — security review of this branch. F-01 through F-04 referenced throughout this plan all come from that document. Read it before touching PRs 3–5.
- PR #17 on GitHub (`stealth_addresses_new`) — original monolithic PR this plan decomposes

## Key concepts for PRs 3–5

**TAIL program:** a Chialisp program that controls who can mint or melt a CAT asset. Its SHA256 hash is the asset's identifier (`tail_hash`). A coin's `tail_hash` is permanently bound at creation — you can't substitute a different TAIL program at spend time without detection.

**TAIL-on-delta:** when a CAT spend burns/melts tokens (`total_input > total_output`), the zkVM guest must run the TAIL program to authorize the supply change. The guest also verifies that `hash(tail_source) == coin.tail_hash` — this is the F-01 fix. Without it an attacker could substitute `(mod () 1)` for any restrictive TAIL.

**Ring spend:** multiple coins spent in a single ZK proof. Only the primary coin's puzzle runs for conditions; additional coins contribute their amounts as inputs and reveal their nullifiers. Because of this, `total_input` (sum of all ring coins) intentionally exceeds `total_output` (primary puzzle only) — this is NOT a melt. The TAIL-on-delta check must not fire for ring spends; it only fires when `tail_source` is explicitly provided by the caller.

**Stealth addresses:** sender encrypts a random nonce to the recipient's x25519 public key (80-byte note: ephemeral_pk || ChaCha20Poly1305 ciphertext). Recipient scans by decrypting with their private key and checking if the derived puzzle hash matches any coin on-chain. See `src/crypto_utils.rs` for the implementation and `DOCUMENTATION.md` for the full protocol.

---

## Status

| PR | Branch | Status | Notes |
|----|--------|--------|-------|
| 1 | `pr/01-core-types` | ✅ merged PR #20 | |
| 2 | `pr/02-simulator-migration` | ☐ todo | |
| 3 | `pr/03-offer-fixes` | ☐ todo | |
| 4 | `pr/04-stealth-nonce-encryption` | ☐ todo | |
| 5 | `pr/05-cat-minting` | ☐ todo | cli.rs hunk split needed |
| 6 | `pr/06-e2e-tests` | ☐ todo | |
| 7 | `pr/07-examples-docs` | ☐ todo | |

---

## PR 1: Core types + security hardening

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

## PR 2: Simulator — SparseMerkleTree migration + settlement double-spend

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

## PR 3: Offer system bugfixes

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

## PR 4: Stealth address nonce encryption

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

## PR 5: CAT minting — guests + mock + CLI + tests

**Branch:** `pr/05-cat-minting`
**Base:** `pr/04-stealth-nonce-encryption` (or main after PR 4 merged)
**Depends on:** PR 1 (MintData/GenesisSpend types), PR 2 (simulator for tests)
**Description:** Full CAT minting stack: zkVM guest mint mode, TAIL-on-delta authorization with F-01 security fix, mock backend parity, CLI mint command, and the minting test suite. See "Key concepts" above for TAIL-on-delta and ring spend semantics before touching guest code.

**Security context (read before editing guests):**
- **F-01 fix** (`VEIL_DIFFERENTIAL_REVIEW_2026-03-15.md`): guests now call `assert_eq!(compiled_tail_hash, tail_hash)` after compiling `tail_source`. This prevents an attacker substituting a permissive TAIL for a restrictive one at spend time.
- **Ring spend carve-out**: the original F-01 fix incorrectly added `else { panic!("CAT supply change requires tail_source") }`. This fires for ring spends (where `tail_source = None` and `total_input != total_output` by design). That `else` branch was removed — if `tail_source` is `None`, the TAIL block is simply skipped. Do not re-add it.
- **Mock backend parity**: the mock backend previously skipped TAIL-on-delta entirely. It now mirrors the guest logic: verify `hash(tail_source) == tail_hash`, then execute the TAIL and check it returns truthy. This ensures tests that pass mock also pass the real guests.

**Files:**
- `backends/risc0/guest/src/main.rs` — mint mode (new `if mint_data.is_some()` branch at top of main), TAIL-on-delta block with F-01 `assert_eq!`, ring spend carve-out (no `else` panic)
- `backends/sp1/program/src/main.rs` — identical to risc0 guest changes
- `backends/mock/src/backend.rs` — capture `(total_input, total_output)` from `enforce_ring_balance`; add TAIL-on-delta check block; `None` arm is a no-op (not an error)
- `src/lib.rs` — add `#[cfg(feature = "mock")] pub use clvm_zk_mock::MockBackend` so integration tests can access it
- `tests/test_cat_minting.rs` — new file: 6 tests including `test_f01_tail_substitution_rejected_mock` (F-01 regression)

**cli.rs functions changed (apply only these hunks):**
- `SimAction` enum — add `Mint { ... }` variant
- `run_simulator_command` — add routing arm for `SimAction::Mint`
- `mint_command` — entirely new function (~132 lines); uses dummy BLS/ECDSA verifiers for CLI pre-check (see issue #18 for why this is acceptable)

**Do NOT touch in this PR:**
- `offer_take_command` (PR 3)
- `send_command`, `scan_command`, `faucet_command`, `wallet_command` (PR 4)

**Test commands:**
```
cargo test-mock --test test_cat_minting
cargo test-mock   # full suite must still pass
cargo check --no-default-features --features mock,testing
```

---

## PR 6: E2E risc0 test suite

**Branch:** `pr/06-e2e-tests`
**Base:** `pr/05-cat-minting` (or main after PR 5 merged)
**Depends on:** PR 5 (guests must have mint mode + TAIL-on-delta for tests to be valid)
**Description:** Pure test addition, no production code changes. 8 end-to-end tests covering the full protocol stack with real ZK proofs.

**Files:**
- `tests/test_e2e_risc0.rs` — 8 tests: XCH spend, CAT mint+spend, genesis mint, ring spend, offer, TAIL-on-delta melt, settlement (x2), F-01 substitution regression

**Test:** `cargo test-risc0 --test test_e2e_risc0` (requires risc0 build; slow).

---

## PR 7: Examples, demos, docs, cleanup

**Branch:** `pr/07-examples-docs`
**Base:** `pr/06-e2e-tests` (or main after PR 6 merged)
**Depends on:** nothing (no logic)
**Description:** Non-code changes. Reviewed separately so they don't dilute security review of PRs 1–6.

**Files:**
- `examples/cat_offer_demo.rs` — demo showing full CAT offer flow
- `cat_offer_demo.sh` — shell demo script
- `demo.sh` — shell demo script
- `scripts/multi_cat_demo.sh` — multi-CAT demo
- `README.md` — updated docs
- `.gitignore` — add audit files
- `Cargo.toml` — minor cleanup

**Test commands:**
```
cargo check --no-default-features --features mock,testing
```

---

## Implementation notes

### Creating branches
Each branch is created off the current `stealth_addresses_new` tip and then pruned down to only the files/hunks for that PR:
```
git fetch origin main:main
git checkout -b pr/01-core-types main
# apply only the relevant files via: git checkout stealth_addresses_new -- <files>
# or apply specific hunks via: git diff main stealth_addresses_new -- <file> | git apply --include=<hunk>
```

### Verification after all 7 merged
```
git diff <final-merge-commit> stealth_addresses_new
# should be empty (or only whitespace/ordering diffs)
```

### Order matters
PRs must be merged in order 1→7. Each PR's branch is based on the previous PR's merge commit (or rebased onto main after each merge).
