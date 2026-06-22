# Differential Security Review: `pr/01-core-types` vs `main`

**Date:** 2026-03-22
**Branch:** `pr/01-core-types` (2 commits ahead of `main`)
**Commits:** `a939127` (core types + arithmetic hardening), `0d2e8e8` (TAIL enforcement / F-01 fix)
**Scope:** 35 files, +1783 / -84 lines
**Strategy:** FOCUSED (MEDIUM codebase — 83 .rs files)
**Reviewer:** Claude (automated differential review)

---

## Executive Summary

| Severity | Count |
|----------|-------|
| HIGH     | 0     |
| MEDIUM   | 2     |
| LOW      | 1     |
| INFO (positive fixes) | 6 |

**Overall Risk:** MEDIUM
**Recommendation:** CONDITIONAL — address M-01 (TAIL return-value semantics) before merge; M-02 (ring coin TAIL) is a design-level decision that needs explicit documentation.

**Key Metrics:**
- Files analyzed: 14/35 (all HIGH/MEDIUM risk production files — 100% coverage)
- Test coverage: Good — new `test_cat_tail_enforcement.rs` (245 lines, 6 scenarios)
- Security regressions detected: 0
- Critical bugs FIXED by this branch: 6 (F-01, overflow, cross-platform usize, Mint bypass, missing host guards, CoinMode confusion)

---

## What Changed

| File | +Lines | -Lines | Risk | Category |
|------|--------|--------|------|----------|
| `clvm_zk_core/src/types.rs` | +94 | -2 | **HIGH** | CoinMode enum, MintData, GenesisSpend, leaf_index→u64 |
| `backends/mock/src/backend.rs` | +43 | -4 | **HIGH** | TAIL enforcement + Mint guard |
| `backends/risc0/guest/src/main.rs` | +36 | -4 | **HIGH** | TAIL enforcement + Mint guard + u64 leaf_index |
| `backends/sp1/program/src/main.rs` | +36 | -4 | **HIGH** | TAIL enforcement + Mint guard + u64 leaf_index |
| `clvm_zk_core/src/lib.rs` | +43 | -12 | **HIGH** | enforce_ring_balance CoinMode, checked_add, modular_pow guard |
| `backends/risc0/src/lib.rs` | +22 | -1 | MEDIUM | Host-side guards (Mint + missing tail_source) |
| `backends/sp1/src/lib.rs` | +23 | -1 | MEDIUM | Host-side guards (Mint + missing tail_source) |
| `src/lib.rs` | +5 | -3 | MEDIUM | CoinMode export, tail_source/tail_params plumbing |
| `src/protocol/spender.rs` | +12 | -2 | MEDIUM | tail_source/tail_params propagated through Spender API |
| `src/protocol/settlement.rs` | +4 | -2 | MEDIUM | leaf_index cast to u64 in settlement path |
| `src/protocol/structures.rs` | +3 | - | LOW | ProofType::Mint, is_submittable updated |
| `tests/test_cat_tail_enforcement.rs` | +245 | - | LOW | New TAIL enforcement test suite |
| `backends/risc0/guest_settlement/src/main.rs` | +2 | -2 | LOW | u64 leaf_index in settlement guest |
| `backends/sp1/program_settlement/src/main.rs` | +2 | -2 | LOW | u64 leaf_index in settlement guest |

---

## Phase 0: Triage

### Risk Classification

**HIGH risk (crypto, value transfer, validation):**
- TAIL enforcement logic — determines whether CAT spends are authorized
- `CoinMode` enum — controls whether nullifiers are emitted (double-spend prevention)
- `enforce_ring_balance` — inflation/deflation protection
- `checked_add` — overflow correctness in balance accounting
- `leaf_index: u64` — serialization consistency between 64-bit host and 32-bit zkVM guest

**MEDIUM risk (business logic, APIs):**
- Host-side guards in risc0/sp1 libs
- `tail_source`/`tail_params` propagation through Spender/settlement APIs

**LOW risk (tests, structure, constants):**
- New test file, `ProofType::Mint` variant, settlement struct changes

---

## Phase 1: F-01 Fix Analysis (Previous HIGH Finding)

**Previous finding:** `VEIL_DIFFERENTIAL_REVIEW_2026-03-15.md` §F-01 — TAIL hash compiled from `tail_source` was discarded (`_tail_hash`), allowing attacker to substitute any TAIL for a CAT spend.

**Fix applied in `0d2e8e8`:**

```rust
// backends/risc0/guest/src/main.rs:265-276
let (tail_bytecode, tail_program_hash) =
    compile_chialisp_to_bytecode(risc0_hasher, tail_src)
        .expect("TAIL program compilation failed");

assert_eq!(
    tail_program_hash, effective_tail_hash,   // ← was `_tail_hash` (discarded), now compared
    "tail_hash mismatch: tail_source does not compile to the committed tail_hash"
);
```

**Verification:**
- `effective_tail_hash = private_inputs.tail_hash.unwrap_or([0u8; 32])` — same value used in `compute_coin_commitment`, so the TAIL is verified against the hash embedded in the coin's cryptographic commitment.
- Fix is identical in risc0 guest, sp1 guest, and mock backend.
- Test `test_cat_spend_wrong_tail_source_rejected` directly validates the hash-mismatch rejection path.

**Assessment: F-01 RESOLVED.** ✓

---

## Phase 2: New Findings

### [MEDIUM] M-01: TAIL Authorization Semantics — Returning 0/nil Treated as Authorized

**File:** `clvm_zk_core/src/lib.rs:735-748`, called from `backends/risc0/guest/src/main.rs:275`, `backends/sp1/program/src/main.rs:260`, `backends/mock/src/backend.rs:308`
**Blast Radius:** All CAT spend authorizations
**Test Coverage:** Partial — tests don't cover the `(mod () 0)` or `(mod () ())` cases explicitly

**Description:**

TAIL authorization uses `run_clvm_with_conditions` and treats any non-raising execution as authorized:

```rust
// lib.rs:735-748
pub fn run_clvm_with_conditions(...) -> Result<(Vec<u8>, Vec<Condition>), &'static str> {
    let (output_bytes, _cost) = evaluator.run_program(bytecode, args, max_cost)?;  // Err = raise
    let conditions = deserialize_clvm_output_to_conditions(&output_bytes).unwrap_or_else(|_| Vec::new());
    Ok((output_bytes, conditions))  // returns Ok regardless of output value
}

// guest (risc0):
run_clvm_with_conditions(&evaluator, &tail_bytecode, &tail_args, max_cost)
    .expect("TAIL authorization failed: TAIL program rejected this CAT spend");
// ↑ only rejects if program RAISES an exception — return value (0, nil, etc.) is irrelevant
```

A TAIL program of `(mod () 0)` or `(mod () ())` returns falsy/nil without raising an exception, and this code treats it as **authorized**. A developer writing a "deny all" TAIL expecting `0` to mean rejection would inadvertently create a TAIL that allows all spends.

**Attack Scenario:**
```
TAIL author writes: "(mod () ())"  -- intending "always deny"
Spender provides tail_source = "(mod () ())"
compile succeeds, hash matches, program runs, returns nil, no raise
.expect(...) sees Ok(...) → spend AUTHORIZED

Expected behavior: TAIL returning nil = denied
Actual behavior: TAIL returning nil = authorized
```

**Correct Chialisp rejection pattern:** `(mod () (x))` — explicit exception via opcode `x`. TAIL must actively raise to reject.

**Evidence from test file (incorrect comment at line 218):**
```rust
// TAIL program that always fails: "(mod () 0)" → returns 0 (falsy in CLVM → raises exception)
// Actually in CLVM, returning 0 is valid — the program needs to explicitly fail.
```
The author acknowledges this subtlety inline but doesn't test `(mod () 0)` to confirm it would pass. This means the behavior is under-tested and the semantics could surprise TAIL authors.

**Risk Assessment:**
- Does NOT affect current tests (all use correct `(x)` pattern for rejection)
- IS a footgun for TAIL authors who follow intuition from other contract languages
- Single-issuance TAILs typically return `1` (truthy) — low practical risk currently
- Risk increases as more complex TAILs are written for Veil

**Recommendation:**
1. Document the "exception = reject" model prominently in `run_clvm_with_conditions` and in TAIL authoring docs
2. Consider adding a return-value check: reject if output is empty/nil (`output_bytes.is_empty() || output_bytes == [0x80]`)
3. Add test case: `(mod () 0)` should **fail** if return-value-based rejection is intended, to lock in the semantics

---

### [MEDIUM] M-02: TAIL Not Enforced for Additional Ring Spend Coins

**File:** `backends/risc0/guest/src/main.rs:296-348`, `backends/sp1/program/src/main.rs:280-332`
**Blast Radius:** CAT ring spends with additional coins
**Test Coverage:** NONE — no test exercises a CAT ring spend with additional coins

**Description:**

For ring spends, TAIL enforcement runs only for the **primary** coin. Additional ring coins (in `private_inputs.additional_coins`) skip TAIL entirely:

```rust
// guest: primary coin → TAIL enforced (lines 256-277)
if effective_tail_hash != [0u8; 32] {
    // compile, hash-verify, execute TAIL
}

// additional ring coins → NO TAIL enforcement
for coin in additional_coins {
    // merkle proof verified ✓
    // serial commitment verified ✓
    // tail_hash checked against primary via enforce_ring_balance ✓
    // TAIL program NOT executed ✗
}
```

`AdditionalCoinInput` has no `tail_source` or `tail_params` fields (`clvm_zk_core/src/types.rs:248-257`), making per-ring-coin TAIL structurally impossible in the current design.

**Security Analysis:**

The current model is internally consistent **if** the design intent is:
- TAIL runs once to authorize "spending this asset type" (not per-coin)
- Ring coin `tail_hash` values are cryptographically bound in each coin's commitment (verified via merkle proof)
- `enforce_ring_balance` ensures all ring coins have the same `tail_hash` as the primary

Under these constraints, there is no inflation attack: the total amount is balanced, all coins are the same asset type (commitment-verified), and the TAIL authorizes the spend.

**Risk:** Exists if TAIL semantics are expected to be per-coin (e.g., a TAIL that checks specific coin amounts, recipients, or ring membership). Current TAIL execution has no visibility into ring structure or individual coin amounts.

**Recommendation:**
- Document explicitly: "Veil TAILs for ring spends receive no ring context and run once per spend bundle, not per coin"
- If per-coin TAIL is needed in future: `AdditionalCoinInput` needs `tail_source`/`tail_params` fields and per-coin TAIL enforcement in guest
- Add test: CAT ring spend (at least 2 CAT coins) to validate the current model works end-to-end

---

### [LOW] L-01: `usize::try_from(leaf_index).expect()` Panics in Guest for Large Trees

**File:** `backends/risc0/guest/src/main.rs:251,340`, `backends/sp1/program/src/main.rs:236,325`, `backends/mock/src/backend.rs:285`, settlement guests
**Blast Radius:** Any proof with leaf_index > 4,294,967,295 on 32-bit zkVM platform

**Description:**

The `u64 → usize` cast uses `.expect()` (panic) in guest code:
```rust
usize::try_from(commitment_data.leaf_index)
    .expect("leaf_index exceeds usize — tree larger than platform supports")
```

On 32-bit RISC-V (RISC0/SP1 guest), `usize = u32`. A tree with 4B+ leaves would cause an uncontrolled guest panic. Since `leaf_index` is a prover-supplied input, a malicious prover could craft an input with `leaf_index = u64::MAX` to trigger this panic.

**Practical Risk:** Low — Veil's sparse merkle tree at 20 levels has 2^20 = ~1M leaves max. This limit is structural. But if tree depth ever increases beyond 32 levels, this becomes exploitable.

**Recommendation:** Add a validation on the host side: `leaf_index < MAX_LEAF_INDEX` before sending to guest, or document the maximum tree size invariant.

---

## Phase 3: Positive Security Changes (INFO)

### I-01: F-01 Fixed — TAIL Hash Now Verified Before Execution
`tail_program_hash != effective_tail_hash` now causes guest panic. Previously `_tail_hash` was discarded. This closes the "substitute any TAIL" attack on CAT spends.

### I-02: `CoinMode` Enum Eliminates `Option<SerialCommitmentData>` Ambiguity
**Before:** `serial_commitment_data: Option<SerialCommitmentData>` — `None` meant both Execute and conceptually-Mint.
**After:** `CoinMode::Execute | CoinMode::Spend(…) | CoinMode::Mint(…)` — three distinct states, mutually exclusive by type. Mint is explicitly rejected in `enforce_ring_balance`:
```rust
CoinMode::Mint(_) => return Err("mint mode must use dedicated mint validation, not enforce_ring_balance"),
```

### I-03: `checked_add` Prevents Overflow-to-Zero Inflation Attack
**Before:** `total_output_amount += amount` — in release mode, wrapping overflow could produce a smaller total, bypassing `output > input` check.
**After:** `.checked_add(amount).expect("output amount overflow")` — panics in guest (proof fails) instead of wrapping.

### I-04: `leaf_index: u64` Fixes Cross-Platform Borsh Serialization
**Before:** `leaf_index: usize` — Borsh encodes `usize` as 4 bytes on 32-bit guest, 8 bytes on 64-bit host. Deserialization of a host-produced input on the guest would read wrong bytes.
**After:** `leaf_index: u64` — explicit 8-byte encoding on both platforms. All cast sites guarded with `usize::try_from(…)`.

### I-05: Host-Side Guards Prevent Opaque Guest Panics
New guards in `backends/risc0/src/lib.rs:106-121` and `backends/sp1/src/lib.rs:123-140`:
- Mint mode rejected with clean error before guest invocation
- CAT spend without `tail_source` caught with descriptive error instead of guest panic on `.expect()`

### I-06: `modular_pow` Zero-Modulus Guard
**Before:** `if modulus == 1 { return 0; }` — calling with `modulus == 0` would divide-by-zero in the loop.
**After:** Added `if modulus == 0 { return 0; }` guard. No callers pass 0 as modulus currently (function has no call sites outside tests), but defensive. Well-documented convention.

---

## Phase 4: Test Coverage Assessment

| Test | Scenario | Pass/Fail Path | Status |
|------|----------|---------------|--------|
| `test_cat_spend_trivial_tail_succeeds` | `(mod () 1)`, no params | Expected OK | ✓ |
| `test_cat_spend_tail_with_params_succeeds` | `(mod (x) x)`, truthy x | Expected OK | ✓ |
| `test_xch_spend_no_tail_required` | tail_hash=None, no tail_source | Expected OK | ✓ |
| `test_cat_spend_missing_tail_source_rejected` | tail_hash set, tail_source=None | Expected Err | ✓ |
| `test_cat_spend_wrong_tail_source_rejected` | tail_hash mismatch | Expected Err | ✓ |
| `test_cat_spend_failing_tail_rejected` | `(mod () (x))` raises | Expected Err | ✓ |

**Gap:** No test for `(mod () 0)` — locks in the "0 = authorized" behavior (relates to M-01).
**Gap:** No CAT ring spend test with additional coins (relates to M-02).
**Gap:** No test for `leaf_index` at u32::MAX boundary (relates to L-01).

---

## Phase 5: Blast Radius Summary

| Finding | Blast Radius | Attack Vector |
|---------|-------------|--------------|
| M-01 (TAIL semantics) | All CAT spends | TAIL author writes `(mod () 0)` expecting denial |
| M-02 (Ring TAIL) | CAT ring spends | TAIL expecting per-coin context gets no ring visibility |
| L-01 (leaf_index panic) | Large trees >4B leaves | Prover-supplied `leaf_index = u64::MAX` → guest panic |

---

## Summary

This PR correctly fixes F-01 (the previous HIGH finding) and introduces meaningful security hardening: type-level Mint/Spend/Execute separation, overflow-safe arithmetic, cross-platform serialization correctness, and defense-in-depth host guards. No regressions detected.

The two MEDIUM findings are design-level concerns:
- **M-01** is an observable footgun that could produce insecure TAILs — should be resolved before external TAIL authors exist
- **M-02** is a known architectural constraint that needs documentation to prevent future misuse

**Merge recommendation:** Conditional — resolve or explicitly accept M-01 and M-02 before merging.
