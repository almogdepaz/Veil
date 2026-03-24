# EDC Differential Review: pr/02-simulator-migration vs main

**Date:** 2026-03-25
**Branch:** `pr/02-simulator-migration`
**Commits vs main:** 2 (a939127 + 0d2e8e8)
**Scope:** Security-focused differential review of all changed files
**Strategy:** Full source read of every changed file; cross-referenced against architecture invariants, known issues, and complexity audit

---

## Executive Summary

| Severity | Count | Key themes |
|----------|-------|------------|
| HIGH     | 2     | TAIL enforcement gap on ring coins in mock; settlement TAIL bypass on CAT spends |
| MEDIUM   | 4     | CoinMode::Execute allows CAT input with non-zero tail_hash; is_clvm_nil edge cases; balance enforcement silently ignores 0-byte amount; settlement guest lacks TAIL enforcement |
| LOW      | 4     | leaf_index usize cast on 64-bit mock; host guards not applied to ring coins; hash_data duplication adds more test copies; modular_pow undefined convention silently propagates |
| INFO     | 3     | Architecture notes, dead exports carried forward, complexity deltas |

**Net verdict:** The primary objective (TAIL enforcement for CAT spends) is correctly implemented in the mock backend and both zkVM guests for the **primary coin**. The ring coin TAIL enforcement is also present in the mock and both guests. However, there are correctness gaps in the host-side guards, a semantic ambiguity in `CoinMode::Execute` with a non-zero `tail_hash`, and an unguarded path in the settlement guest that never runs TAIL at all.

---

## Architecture Invariant Verification

### Invariant 1: `enforce_ring_balance` MUST run before CREATE_COIN transform

**Status: SATISFIED.** In all three backends (mock at line 234, risc0 guest at line 157, sp1 guest at line 142), `enforce_ring_balance` is called before the CREATE_COIN transformation loop. No regression observed.

### Invariant 2: `serial_commitment` inside `coin_commitment`; serial_number hidden until spend; guest verifies opening

**Status: SATISFIED.** `SerialCommitmentData` still contains both values. The Spend arm in all guests calls `compute_serial_commitment` and verifies equality before proceeding. No regression.

### Invariant 3: `leaf_index: u64` everywhere for consistent Borsh encoding

**Status: SATISFIED with a caveat.** `SerialCommitmentData.leaf_index` is now `u64` (was `usize` before PR1). `GenesisSpend.leaf_index` is `u64`. Conversion to `usize` happens at call sites via `usize::try_from(...).expect(...)`. This is architecturally correct. The mock backend performs this cast on the 64-bit host where `usize == u64` so the `.expect()` never fires; the guest performs it on 32-bit RISC-V where values > u32::MAX would panic — protected by the host-side guard in `risc0/src/lib.rs:130-138` and `sp1/src/lib.rs:148-155`. See F-03 for a residual gap.

### Invariant 4: Same `hash_data_default` used in simulator, host, all guests — roots always align

**Status: SATISFIED.** The simulator uses `crate::crypto_utils::hash_data_default`. The mock backend defines its own `hash_data` using `Sha256` from `sha2`. The risc0 guest uses `risc0_hasher` (RISC-0 SHA-256 implementation). The sp1 guest uses `sp1_hasher` (also SHA-256 via `sha2`). All produce SHA-256 over the same preimage. No divergence introduced.

### Invariant 5: `CoinMode::Mint` blocked at all levels

**Status: SATISFIED.** Host guards in both risc0 and sp1 libs return `Err` before guest execution. Mock backend returns `Err` in the `Mint` arm. Both guests `panic!` in the `Mint` arm. `enforce_ring_balance` returns `Err` on Mint. Defense-in-depth is present.

### Invariant 6: TAIL nil-return = authorization failure; `is_clvm_nil` checks output == [0x80] || empty

**Status: SATISFIED with a caveat.** `is_clvm_nil` is implemented as `output.is_empty() || output == [0x80]`. This is correct for the canonical CLVM nil encoding. However, it does not account for the integer value `0` encoded as a multi-byte atom (e.g., a TAIL returning `(+ 0 0)` might produce `[0x80]` or possibly a leading-zero-stripped 0). In practice CLVM returns `0x80` for zero, so this is low risk; see F-05 for the nuance.

---

## Findings

---

### HIGH

#### H-01: `CoinMode::Execute` path skips TAIL enforcement even when `tail_hash` is non-zero

**File:** `backends/mock/src/backend.rs:248-348`, `backends/risc0/guest/src/main.rs:217-296`, `backends/sp1/program/src/main.rs:202-281`

**Description:** The TAIL enforcement block (`if effective_tail_hash != [0u8;32]`) is nested inside `CoinMode::Spend`. A caller can set `coin_mode: CoinMode::Execute` and `tail_hash: Some(non_zero_hash)` and TAIL is never invoked. The program executes freely regardless of the committed asset type.

In `CoinMode::Execute`, by design, no coin commitment is verified at all (no Merkle proof, no serial commitment, no nullifier). So this is not a direct coin-theft vector. However, it means a caller can prove execution of an arbitrary program against a CAT `tail_hash` without the TAIL authorizing anything. The risk is that if a downstream consumer erroneously treats an `Execute`-mode proof as evidence that a CAT spend was authorized, they receive a false proof.

**Classification:** Acceptable by design only if callers never confuse `Execute` proofs with `Spend` proofs. The current codebase separates these via `ProofType` and the `nullifiers` vec being empty on Execute. But there is no runtime assertion that `Execute` mode requires `tail_hash == None` — so a malformed input silently proceeds with a non-zero `tail_hash` attached to a no-coin-commitment proof.

**Attack scenario:** An adversary constructs `Input { coin_mode: Execute, tail_hash: Some(legit_CAT_hash), chialisp_source: arbitrary_program, ... }`. The mock backend produces a proof with `program_hash` of the arbitrary program, no nullifier, and `tail_hash` associated in the caller's head but not committed in the proof. If any validator code naively checks `tail_hash` from the `Input` rather than from the proof's committed coin commitment, it could be tricked.

**Recommendation:** Assert `tail_hash == None` in the `CoinMode::Execute` arm, or document that `Execute` mode is only valid for XCH contexts.

---

#### H-02: Settlement guest (`guest_settlement/src/main.rs`) has no TAIL enforcement for taker's CAT spend

**File:** `backends/risc0/guest_settlement/src/main.rs:192-235`

**Description:** `verify_taker_coin` verifies the serial commitment and Merkle membership of the taker's coin using `taker_tail_hash`. It does NOT run a TAIL program against that hash. If a taker is spending a CAT coin (non-zero `taker_tail_hash`), the TAIL that controls that CAT is never executed in the settlement guest. Any TAIL — or a completely fake one — would authorize the spend.

The TAIL enforcement added in this PR applies only to the main transaction guest (`backends/risc0/guest/src/main.rs` and `backends/sp1/program/src/main.rs`). The settlement guest (`guest_settlement`) received no corresponding update.

**Attack scenario:** Maker creates an offer to buy 100 XCH for 50 USDT. Taker holds a CAT coin whose TAIL program would normally reject this spend (e.g., a TAIL that requires a BLS signature from an issuer). Taker calls `prove_settlement` with their CAT coin. The settlement guest verifies Merkle membership but never invokes the TAIL. Taker successfully proves ownership of a coin they are not authorized to spend per its TAIL rules.

**This is a direct bypass of CAT TAIL authorization for settlement spends.**

**Recommendation:** Add the same TAIL enforcement block (compile `tail_source`, hash-verify, execute, nil-check) to `verify_taker_coin` in both `guest_settlement/src/main.rs` and `sp1/program_settlement/src/main.rs`. The `SettlementInput` struct needs `taker_tail_source: Option<String>` and `taker_tail_params: Vec<ProgramParameter>` fields, and `SettlementParams` in `src/protocol/settlement.rs` needs to propagate them.

---

### MEDIUM

#### M-01: Host-side CAT tail_source guard does not cover ring coins in `additional_coins`

**File:** `backends/risc0/src/lib.rs:119-126`, `backends/sp1/src/lib.rs:136-145`

**Description:** The host guard checks:
```rust
let is_cat = inputs.tail_hash.map_or(false, |h| h != [0u8;32]);
if is_cat && matches!(inputs.coin_mode, CoinMode::Spend(_)) && inputs.tail_source.is_none() {
    return Err(...);
}
```
This only checks the primary coin's `tail_hash` and `tail_source`. If a ring spend includes `additional_coins` where `coin.tail_hash != [0;32]` but `coin.tail_source == None`, no host-side rejection occurs. The guest will panic on the `expect()` at the ring coin TAIL enforcement block.

This is not a security bypass (the guest enforces it), but it degrades the user experience: callers get an opaque panic trace instead of a clean error message. More importantly, the stated goal of the host guard (surface clean errors before the guest) is incomplete.

**Recommendation:** Add a loop over `inputs.additional_coins` checking `coin.tail_hash != [0;32] && coin.tail_source.is_none()` in both host guards.

#### M-02: `enforce_ring_balance` silently treats 0-arg or malformed CREATE_COIN as 0-amount output

**File:** `clvm_zk_core/src/lib.rs:839-862`

**Description:** The amount extraction in `enforce_ring_balance` matches on `condition.args.len()`:
```rust
2 | 4 => { /* extract args[1] */ }
_ => 0,
```
A CREATE_COIN with 0, 1, or 3 args returns amount `0`. This means a malformed CREATE_COIN condition can create a coin commitment in the tree (via the transform path) while contributing zero to the output balance, breaking the inflation check. The transform path only runs for `args.len() == 4`, so a 3-arg or 1-arg CREATE_COIN would not be transformed but also not be caught by balance enforcement.

In practice, the CLVM program generates the conditions, so a well-formed puzzle wouldn't produce malformed CREATE_COINs. But a maliciously crafted Chialisp source could produce them to smuggle extra outputs past balance enforcement.

**Recommendation:** Return `Err("invalid CREATE_COIN arg count")` for `args.len()` values other than 2 and 4, consistent with the transform path which already panics/errors on unexpected arg counts.

#### M-03: `is_clvm_nil` does not cover single-byte `[0x00]` which CLVM may produce for `(+ 0 0)`

**File:** `clvm_zk_core/src/lib.rs:225-227`

**Description:**
```rust
pub fn is_clvm_nil(output: &[u8]) -> bool {
    output.is_empty() || output == [0x80]
}
```
CLVM canonical nil is the empty atom, serialized as `[0x80]`. Integer `0` in CLVM is represented as `()` (nil, same encoding). However, `number_to_atom(0)` in this codebase produces `ClvmValue::Atom(vec![])` (empty atom), which serializes to `[0x80]`.

If a TAIL program returns the atom `[0]` (single byte zero value, as opposed to empty atom), it serializes as a single-byte atom: prefix `0x01` then `0x00`, i.e., `[0x01, 0x00]`. This is NOT nil in CLVM — it is the integer `-0` via signed encoding... wait. Actually in CLVM, `0` is encoded as empty list `0x80`. A byte `0x00` would represent an atom with value 0 (the number zero with a leading zero bit), which is treated as truthy by most CLVM interpreters since it is not nil. This is an edge case with low practical risk but the comment in the code should be more precise.

More concretely: a TAIL returning `(r 1)` (identity) with param `0` could produce `[0x80]` which `is_clvm_nil` catches. A TAIL returning `(q . 0)` produces `[0x80]`. Covered.

**Net assessment:** The current implementation is correct for canonical CLVM. The MEDIUM rating is for the incomplete documentation rather than a real bypass.

**Recommendation:** Add a doc comment to `is_clvm_nil` noting that CLVM defines nil as the empty atom only, and `[0x00]` (if it ever appeared) is technically a non-nil atom. Confirm via a test that `is_clvm_nil([0x00]) == false`.

#### M-04: Settlement host code computes `serial_commitment` inline, diverging from `compute_serial_commitment`

**File:** `src/protocol/settlement.rs:142-146` (risc0 path), `src/protocol/settlement.rs:280-285` (sp1 path)

**Description:** Both the risc0 and sp1 settlement paths compute the taker's serial commitment manually:
```rust
let mut serial_commit_data = Vec::new();
serial_commit_data.extend_from_slice(b"clvm_zk_serial_v1.0");
serial_commit_data.extend_from_slice(&params.taker_secrets.serial_number);
serial_commit_data.extend_from_slice(&params.taker_secrets.serial_randomness);
let serial_commitment: [u8; 32] = Sha256::digest(&serial_commit_data).into();
```
This reimplements `compute_serial_commitment` from `clvm_zk_core::lib.rs:920-933`. If the domain string or field order in `compute_serial_commitment` ever changes, the settlement path will silently compute a different value and the Merkle proof will fail at the guest with an opaque mismatch error.

This is the same class of problem flagged by `.context/complexity.md` for `compute_coin_commitment` being reimplemented in test files.

**Recommendation:** Replace both inline computations with `clvm_zk_core::compute_serial_commitment(sha2_hasher, ...)`.

---

### LOW

#### L-01: `usize::try_from(leaf_index).expect()` in mock backend cannot fail on 64-bit host, but is undocumented

**File:** `backends/mock/src/backend.rs:286-287`, `backends/mock/src/backend.rs:346-347`

**Description:** The mock backend runs on the 64-bit host where `usize == u64`. The `.expect("leaf_index exceeds usize — tree larger than platform supports")` will never fire. The host-side guard (which only protects risc0/sp1 backends) is not applied before the mock's `prove_with_input`. A `leaf_index > u32::MAX` would succeed in the mock but fail in the production backends.

This creates a testing gap: CAT ring spend tests using the mock would pass for oversized leaf indices, giving false confidence before production backend testing.

**Recommendation:** Add the same `leaf_index > u32::MAX` guard to the mock backend's `prove_with_input`, or at minimum add a doc comment explaining why the mock silently accepts values the production backends reject.

#### L-02: `modular_pow(x, y, 0) == 0` convention not enforced at CLVM operator call sites

**File:** `clvm_zk_core/src/lib.rs:321-323`

**Description:** The added guard:
```rust
if modulus == 0 { return 0; }
```
returns `0` by convention for undefined input. The doc comment says "callers must not treat this as a mathematically meaningful result." However, CLVM operator code that calls `modular_pow` has no check at the call site. If a Chialisp program computes `(divmod x 0)`, it will get `0` back rather than an error, potentially causing silent incorrect computation.

**Recommendation:** Either propagate an error (returning `Result`) or add a call-site assertion in the CLVM operator that calls `modular_pow`. The current behavior (return 0 silently) differs from Chia's reference implementation which raises an exception on division by zero.

#### L-03: `process_settlement` double-spend guard only covers maker and taker nullifiers, not the 4 new coin commitments

**File:** `src/simulator.rs:657-682`

**Description:** `process_settlement` checks `nullifier_set` for `maker_nullifier` and `taker_nullifier`. It then inserts 4 new coin commitments into the Merkle tree without checking whether those exact commitments already exist in `commitment_to_index`. A replayed `SettlementOutput` would add duplicate commitments to the tree (at new leaf indices) but would be blocked by the nullifier check. This is not a security issue (the nullifier check is sufficient), but the Merkle tree would contain duplicate leaves in a hypothetical replay scenario (which the nullifier check prevents first).

**Recommendation:** No action required for correctness. Document that the nullifier check is the replay guard, and duplicate commitment checks are not needed.

#### L-04: Test file `test_cat_tail_enforcement.rs` adds another local `hash_data` definition

**File:** `tests/test_cat_tail_enforcement.rs:19-23`

**Description:** The new test file defines:
```rust
fn hash_data(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}
```
This is the 6th instance of this local definition across the test suite. `.context/complexity.md` already flags 5 existing instances and recommends using `clvm_zk_core::hash_data` directly.

This PR adds one more copy rather than following the existing recommendation.

**Recommendation:** Replace with `use clvm_zk_core::hash_data;` or `use crate::crypto_utils::hash_data_default;` to reduce drift risk.

---

### INFO

#### I-01: Precompiled `DELEGATED_PUZZLE_BYTECODE` not re-verified in this PR

**File:** `backends/risc0/guest/src/main.rs:32-44`, `backends/sp1/program/src/main.rs:31-43`

The precompiled bytecode optimization bypasses `compile_chialisp_to_bytecode` for the delegated puzzle. The hash `DELEGATED_PUZZLE_HASH` is hardcoded. There is no test that recompiles `DELEGATED_PUZZLE_SOURCE` and asserts the hash equals `DELEGATED_PUZZLE_HASH`. If the compiler ever produces different output (determinism is listed as an architecture invariant but not enforced by tests), the hardcoded hash would silently diverge.

**Recommendation:** Add a compile-time or test assertion: `compile_chialisp_to_bytecode(hasher, DELEGATED_PUZZLE_SOURCE).hash == DELEGATED_PUZZLE_HASH`.

#### I-02: Guest duplication not reduced by this PR

The risc0 and sp1 guests remain 88% identical (per `.context/complexity.md`). This PR adds another ~40 identical lines (TAIL enforcement) to each. The complexity debt increases. No new action required — this is PR scope — but it increases urgency of the refactor suggested in complexity.md.

#### I-03: `CoinMode::Mint` with `MintData.genesis_coin: None` has no nullifier to prevent re-minting

**File:** `clvm_zk_core/src/types.rs:213-214`

`genesis_coin` is `Option<GenesisSpend>`. When `None`, the comment says no genesis nullifier is emitted. This means mint without a genesis coin can be repeated arbitrarily. This is listed as UNIMPLEMENTED (PR5 scope) but the type design permits it — worth documenting explicitly that unlimited mint (genesis_coin == None) is only for non-fungible or issuer-controlled supply schemes, and that protocols requiring fixed supply MUST use a genesis coin.

---

## Known Issue Cross-Reference

| Issue | Status in this PR |
|-------|------------------|
| **NM-001** (post-settlement coins non-spendable) | Not addressed. PR3 scope. No regression introduced. |
| **M-01** (get_merkle_path_and_index swallows errors) | Partially mitigated. This PR adds `eprintln!` logging before `ok()?`. Root cause (caller sees misleading error) remains. Status unchanged. |
| **M-02** (ring spend TAIL not per-coin) | **FIXED by this PR.** `AdditionalCoinInput` has `tail_source`/`tail_params`. All three backends enforce per-ring-coin TAIL. Test coverage added in `test_cat_tail_enforcement.rs`. |
| **Stealth nonce plaintext** | Not addressed. PR4 scope. No regression introduced. |
| **NM-002** (missing maker pubkey assertion) | Not addressed. PR3 scope. No regression introduced. |
| **CoinMode::Mint unimplemented** | Correctly blocked at all levels. No regression. Types defined for future PR5 work. |

**New issues introduced by this PR (not pre-existing):**

| New Issue | Severity | See Finding |
|-----------|----------|-------------|
| Settlement guest has no TAIL enforcement for taker CAT coin | HIGH | H-02 |
| Host guard does not check ring coin tail_source | MEDIUM | M-01 (this review) |
| Settlement host reimplements compute_serial_commitment inline | MEDIUM | M-04 |

---

## Complexity Cross-Reference

| Complexity flag | This PR impact |
|----------------|---------------|
| risc0 ↔ sp1 guest 88% identical | **WORSENED.** ~40 more identical TAIL enforcement lines added to each guest. Cumulative delta grows. |
| risc0 ↔ sp1 host 47% duplicate | **WORSENED.** Identical host guards added to both. Offset: guards are simple and mechanical. |
| `hash_data` redefined in N test files | **WORSENED.** 6th copy added in `test_cat_tail_enforcement.rs`. |
| `compute_coin_commitment` reimplemented in test files | **Not worsened.** New test uses production `compute_coin_commitment` correctly. |
| `OperandInput` dead export | **Not touched.** Carried forward unchanged. |
| `src::Condition` builder API dead export | **Not touched.** Carried forward unchanged. |

---

## Test Coverage Assessment

### New test file: `tests/test_cat_tail_enforcement.rs` (245 lines, 8 tests)

| Test | Covers | Assessment |
|------|--------|------------|
| `test_cat_spend_trivial_tail_succeeds` | Happy path: TAIL `(mod () 1)` | PASS — correct |
| `test_cat_spend_tail_with_params_succeeds` | TAIL `(mod (x) x)` with truthy param | PASS — correct |
| `test_xch_spend_no_tail_required` | XCH spend without tail_source | PASS — correct |
| `test_cat_spend_missing_tail_source_rejected` | `tail_hash != 0` but `tail_source == None` | PASS — covers primary coin |
| `test_cat_spend_wrong_tail_source_rejected` | Hash mismatch between committed and provided TAIL | PASS — key security check |
| `test_cat_spend_failing_tail_via_exception_rejected` | TAIL raises exception | PASS — correct |
| `test_cat_spend_tail_returning_nil_rejected` | TAIL returns `()` | PASS — explicit nil semantics |
| `test_cat_spend_tail_returning_zero_rejected` | TAIL returns `0` | PASS — 0 == nil in CLVM |

**Coverage gaps in these tests:**
- **No ring spend TAIL test.** None of the 8 tests exercises a ring spend with per-coin TAIL enforcement (`additional_coins != None`). The M-02 fix (ring coin TAIL) is untested at the test level.
- **Mock only.** All 8 tests use the mock backend. TAIL enforcement in the risc0/sp1 guests (which use `assert!` instead of `Err`) is not integration-tested.
- **No test for TAIL returning a CAT-invalid value.** E.g., a TAIL that returns a list instead of an atom — would `is_clvm_nil` return false (correct) and allow it?
- **No test for `CoinMode::Execute` with non-zero `tail_hash`.** The H-01 gap is not exposed by any test.
- **No test for settlement TAIL bypass (H-02).** The settlement code path is not covered by new tests.

---

## Summary

This PR successfully delivers TAIL enforcement for primary CAT coin spends across all three backends, with solid test coverage for the primary coin path. The `CoinMode` enum refactor is clean and compile-time exclusive. The `leaf_index: u64` change correctly resolves Borsh encoding consistency. The `modular_pow` zero-modulus guard and `checked_add` for output amounts are correct arithmetic hardening.

**Two HIGH findings require action before this branch merges:**

1. **H-02 (settlement TAIL bypass)** is the more urgent. Any user settling a CAT trade via the settlement guest bypasses TAIL authorization for their coin. Fix: add `taker_tail_source`/`taker_tail_params` to `SettlementInput` and add the TAIL enforcement block to `verify_taker_coin` in both settlement guests.

2. **H-01 (Execute mode with non-zero tail_hash)** is lower urgency but should be documented or guarded, as it creates a semantically confusing proof that carries a `tail_hash` label with no TAIL authorization.

The MEDIUM findings (host guard gap on ring coins, inline `serial_commitment` reimplementation, malformed CREATE_COIN balance bypass) are lower priority but should be tracked. The complexity debt from guest/host duplication continues to grow and the planned `veil_main_logic` extraction would pay dividends immediately.
