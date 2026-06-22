# Differential Security Review: `pr/02-simulator-migration` vs `pr/01-core-types`

**Date:** 2026-03-23
**Branch:** `pr/02-simulator-migration` (uncommitted changes on top of `pr/01-core-types`)
**Scope:** 4 files, ~160 changed lines (simulator.rs, cli.rs, 2 test files)
**Strategy:** DEEP (SMALL scope — 1 HIGH risk file, 1 MEDIUM, 2 LOW)
**Reviewer:** Claude (automated differential review)

---

## Executive Summary

| Severity | Count |
|----------|-------|
| HIGH     | 0     |
| MEDIUM   | 2     |
| LOW      | 1     |
| INFO (positive) | 4 |

**Overall Risk:** LOW-MEDIUM
**Recommendation:** Conditional — add test for `process_settlement` double-spend protection (M-02) before merge; M-01 is observability-only with no security impact.

---

## What Changed

| File | Risk | Description |
|------|------|-------------|
| `src/simulator.rs` | **HIGH** | `rs_merkle::MerkleTree` → `SparseMerkleTree`; `process_settlement` → `Result` with double-spend guard |
| `src/cli.rs` | MEDIUM | Handle `process_settlement` `Result` (propagate error) |
| `tests/test_settlement_api.rs` | LOW | Add `ProofType::Mint` distinctness assertions |
| `tests/signature_integration_tests.rs` | LOW | Gate with `#![cfg(feature = "testing")]`, fix doc comment style |

---

## Phase 1: SparseMerkleTree Migration Analysis

### Correctness of root semantics

**Before:** `rs_merkle::MerkleTree::root()` returned `Option<[u8;32]>`. An empty tree returned `None`.

**After:** `SparseMerkleTree::root()` always returns `[u8;32]` — the empty tree has a well-defined root (the hash produced from all-zero leaves at depth 20). This is the expected behavior of a sparse merkle tree.

**Removed guard (simulator.rs:242–244 before):**
```rust
// OLD — guarded against empty tree at spend-time:
let merkle_root = self.coin_tree.root()
    .ok_or_else(|| SimulatorError::TestFailed("merkle tree has no root".to_string()))?;

// NEW — always succeeds:
let merkle_root = self.coin_tree.root();
```

**Security impact:** None. If `spend_coins` is called on an empty simulator, the returned root is the empty-tree root (not a sentinel). Any proof against this root will fail verification in the zkVM guest because no coin commitment can have a valid membership proof. The error degrades from "test failed: merkle tree has no root" to a proof generation failure — less ergonomic but not a security hole.

### `rebuild_tree` insertion order

`merkle_leaves: Vec<[u8;32]>` is serialized/persisted. `rebuild_tree` re-inserts leaves in the same order:
```rust
for leaf in &self.merkle_leaves {
    self.coin_tree.insert(*leaf, h);
}
```
`commitment_to_index` is separately persisted via serde. The leaf_indices in the map match the insertion-order positions in the rebuilt tree. **Correct.**

### `commit()` removal

`rs_merkle` required explicit `commit()` to finalize the tree root after insertions. `SparseMerkleTree::insert()` updates the root in-place. All `commit()` calls are correctly removed at every insertion site. **No missed `commit()` calls detected.**

### `hasher()` function

```rust
fn hasher() -> fn(&[u8]) -> [u8; 32] {
    crate::crypto_utils::hash_data_default
}
```

`hasher()` is called at every insertion and proof generation site. The returned function pointer is always `hash_data_default`, which is the same hasher used by the zkVM guests. This ensures host simulator trees produce roots that match what the guest would verify against. **Critical alignment property — verified correct.**

---

## Phase 2: Findings

### [MEDIUM] M-01: `get_merkle_path_and_index` Silently Swallows Proof Errors

**File:** `src/simulator.rs:486-491`
**Blast Radius:** All spend operations (every coin spend goes through this)
**Test Coverage:** Covered by existing spend tests (they fail if proof is wrong, just with a worse error)

```rust
// BEFORE (rs_merkle API — panic on invalid index):
let proof = self.coin_tree.proof(&[leaf_index]);

// AFTER:
let proof = self
    .coin_tree
    .generate_proof(leaf_index, h)
    .map_err(|e| e.to_string())
    .ok()?;  // ← error from generate_proof is silently discarded
```

If `generate_proof` fails (e.g., `leaf_index` is out of bounds for the depth-20 tree), the function returns `None`. The caller at the spend site sees:
```
SimulatorError::TestFailed("coin not found in merkle tree")
```
instead of the actual proof generation error. **Security impact: none** — an invalid proof fails at the zkVM guest level regardless. **Observability impact: real** — a tree depth bug or OOB index would be masked.

**Recommendation:** Preserve the error:
```rust
let proof = self
    .coin_tree
    .generate_proof(leaf_index, h)
    .map_err(|e| {
        eprintln!("WARN: merkle proof generation failed for leaf {}: {}", leaf_index, e);
        e
    })
    .ok()?;
```

---

### [MEDIUM] M-02: `process_settlement` Double-Spend Guard Has No Test

**File:** `src/simulator.rs:643-679`
**Blast Radius:** Settlement double-spend protection
**Test Coverage:** NONE — no test exercises duplicate calls to `process_settlement` with the same proof

```rust
pub fn process_settlement(&mut self, output: &crate::protocol::SettlementOutput) -> Result<(), String> {
    if self.nullifier_set.contains(&output.maker_nullifier) {
        return Err("maker nullifier already spent".into());
    }
    if self.nullifier_set.contains(&output.taker_nullifier) {
        return Err("taker nullifier already spent".into());
    }
    // insert...
}
```

The guard logic is correct: both nullifiers are checked before any insertion. If maker passes but taker is already spent, the function returns an error without inserting anything (maker nullifier is NOT partially inserted). **The implementation is correct.** However, there is no test that:
1. Calls `process_settlement` successfully
2. Calls it again with the same output
3. Asserts the second call returns `Err`

**Recommendation:** Add to `tests/test_settlement_api.rs`:
```rust
#[test]
fn test_process_settlement_double_spend_rejected() {
    let mut sim = CLVMZkSimulator::new();
    let output = make_dummy_settlement_output();
    assert!(sim.process_settlement(&output).is_ok());
    let result = sim.process_settlement(&output);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("already spent"));
}
```

---

### [LOW] L-01: `get_merkle_root()` Always Returns `Some` — Breaks Empty-Tree Detection

**File:** `src/simulator.rs:607`

```rust
// BEFORE:
pub fn get_merkle_root(&self) -> Option<[u8; 32]> {
    self.coin_tree.root()  // returned None on empty tree
}

// AFTER:
pub fn get_merkle_root(&self) -> Option<[u8; 32]> {
    Some(self.coin_tree.root())  // always Some
}
```

Return type is kept as `Option<[u8;32]>` for API compatibility, but now always returns `Some`. Any caller that used `None` as a sentinel for "simulator has no coins" will now receive `Some(<empty-tree-root>)`. This could lead to confusing proof failures if a caller checks `get_merkle_root().is_some()` as a readiness indicator.

**Search result:** No callers in the current codebase check for `None` from `get_merkle_root()`. **Impact is theoretical** — the API contract changes silently. The correct fix would be to change the return type to `[u8;32]` at some point, but this is out of PR2 scope.

---

## Phase 3: Positive Changes (INFO)

### I-01: Double-Spend Guard Correctly Ordered
Both nullifier checks run before any state mutation. If taker nullifier is spent but maker is not, the function returns `Err` without inserting maker nullifier. **Atomic from a Rust ownership perspective — no partial state corruption possible.**

### I-02: Hasher Alignment — Simulator and Guest Use Same Hash Function
`crate::crypto_utils::hash_data_default` is used at every tree operation. This is the same function injected into the guests. Merkle roots produced by the simulator will always match roots the guests verify against.

### I-03: `rebuild_tree` Leaves Insertion Order Preserved
`merkle_leaves: Vec<[u8;32]>` is the source of truth for rebuild. Insertion order is preserved → `commitment_to_index` remains consistent post-deserialization.

### I-04: `signature_integration_tests.rs` Correctly Gated
Adding `#![cfg(feature = "testing")]` prevents this test from compiling without the `testing` feature, eliminating the pre-existing CI error when building without `--features testing`.

---

## Phase 4: Test Coverage

| Scenario | Tested? |
|----------|---------|
| Normal coin add + spend (SparseMerkleTree) | ✓ (existing tests pass) |
| Ring spend after tree migration | ✓ (ring balance tests) |
| Settlement add commitments to tree | ✓ (settlement_mock test) |
| `process_settlement` called twice (double-spend) | ✗ missing |
| `rebuild_tree` after serialize/deserialize | ✗ missing |
| Empty tree spend attempt | ✗ missing (low priority) |

---

## Summary

The migration from `rs_merkle` to `SparseMerkleTree` is mechanically correct — all insertion sites updated, `commit()` correctly removed, hasher alignment maintained. The `process_settlement` double-spend guard is logically correct but untested. **Recommend adding the double-spend regression test before merge.**
