# EDC Review: pr/03-offer-fixes vs pr/02-simulator-migration

**Date:** 2026-03-25
**Scope:** `src/cli.rs` only — 256 diff lines across one commit (`07bba3b`)
**Strategy:** Full diff read + targeted code traversal for each stated fix (FIX-02, FIX-05, FIX-06, NM-001) plus invariant verification against `.context/` files.

---

## Executive Summary

PR3 resolves four known issues (NM-001, FIX-02, FIX-05, FIX-06) and introduces no new HIGH or MEDIUM severity bugs. The critical NM-001 fix (post-settlement coin spendability) is structurally correct but contains one MEDIUM finding: `maker_change_program` is re-derived by re-calling `create_delegated_puzzle()` at settlement time rather than being stored in `StoredOffer` — this works only because the function is hardcoded/deterministic, and silently diverges if the program ever changes between offer creation and settlement. FIX-02 introduces an offer ID reuse hazard (LOW). All other fixes are correct and complete.

---

## Architecture Invariant Verification

### 1. `coin_commitment` must bind `tail_hash + amount + puzzle_hash + serial_commitment`

**Status: SATISFIED for all 4 new output coins; PARTIAL for maker's payment coin (known residual).**

All four spendable output coins in PR3 now use `PrivateCoin::new_with_tail(puzzle_hash, amount, serial_commitment, tail_hash)` with:
- `goods_coin`: `tail_hash = offer.offered_tail_hash` ✓
- `change_coin`: `tail_hash = taker_coin.to_private_coin().tail_hash` ✓
- `maker_change_coin`: `tail_hash = offer.offered_tail_hash` ✓
- `maker_payment_coin`: `tail_hash = taker_coin.to_private_coin().tail_hash` ✓

The maker's payment coin (`puzzle_hash = sha256("stealth_v1" || maker_pubkey || nonce)`) is a known-unspendable residual; documented in `issues.md` and in the code as `program: "(stealth)"`.

### 2. `puzzle_hash` must be the hash of a compiled Chialisp program

**Status: SATISFIED for 3 of 4 new spendable coins; INTENTIONALLY VIOLATED for maker's payment coin (known residual).**

- `taker_goods_puzzle` and `taker_change_puzzle` come from `create_faucet_puzzle()`, which calls `compile_chialisp_template_hash_default("(mod () 1)")` — legitimate compiled hash. ✓
- `offer.change_puzzle` was set in `offer_create_command` via `create_delegated_puzzle()` — legitimate compiled hash. ✓
- `maker_change_program` is re-derived by calling `create_delegated_puzzle()` at settlement time; this produces the same hash as `offer.change_puzzle` only because the function is deterministic and hardcoded. See **Finding F-01** below.
- `payment_puzzle` is a raw `sha256()` output, not a compiled Chialisp hash. Intentional; documented as stealth-unspendable.

### 3. `serial_commitment` is unique per coin; `puzzle_hash` is NOT unique

**Status: SATISFIED.** FIX-05 correctly switches dedup from `puzzle_hash` to `serial_commitment`. The `existing_serial_commitments` set is built from `wallet.coins` and the skip check uses `info.coin.serial_commitment.as_bytes()`. Since `serial_commitment = SHA256("clvm_zk_serial_v1.0" || serial_number || serial_randomness)` and both `serial_number` and `serial_randomness` are random per coin, uniqueness is guaranteed.

### 4. No backend-specific imports in `clvm_zk_core`; no circular deps

**Status: NOT AFFECTED.** PR3 touches only `src/cli.rs` — no new inter-crate dependencies.

### 5. Determinism — `clvm_tools_rs` compilation produces identical output across runs

**Status: RELIED UPON.** `maker_change_program` is re-derived from a hardcoded string in `create_delegated_puzzle()`. The correctness of maker's change coin spendability depends on this property holding. See **Finding F-01**.

---

## Findings

### F-01 — `maker_change_program` re-derived rather than stored in `StoredOffer` [MEDIUM]

**Location:** `src/cli.rs:2531` and `src/cli.rs:2809`
**Description:**
At settlement time, `offer_take_command` re-calls `create_delegated_puzzle()` to obtain `maker_change_program` (the Chialisp source string). It then stores this as the wallet program for the maker's change coin, whose `puzzle_hash` is `offer.change_puzzle` — a value set during `offer_create_command` by the same `create_delegated_puzzle()` call.

```rust
// offer_create_command — stored in StoredOffer
let (_, change_puzzle) = crate::protocol::create_delegated_puzzle()?;
// ...
StoredOffer { change_puzzle, ... }

// offer_take_command — re-derived from scratch
let (maker_change_program, _) = crate::protocol::create_delegated_puzzle()?;
// ...
WalletCoinWrapper { program: maker_change_program, ... }
```

**Why it matters:** The `StoredOffer` stores `change_puzzle: [u8;32]` (hash) but not the program source. The PR silently assumes the hash from re-calling `create_delegated_puzzle()` at settlement time matches the hash stored in `offer.change_puzzle`. This holds only because the function is deterministic with a hardcoded string. Any future change to `create_delegated_puzzle()` — even a whitespace change — would produce a different hash, causing: (a) the re-derived `maker_change_program` to hash to a different value than `offer.change_puzzle`, (b) the maker's change coin to be recorded with a program whose hash doesn't match the committed `puzzle_hash`, and (c) the coin to be unspendable at proof generation time with a `program_hash mismatch` error.

**Relation to known issues:** NM-001 — this is the fix for maker's change coin spendability, and it introduces a latent fragility.

**Recommendation:** Store `change_program: String` in `StoredOffer` alongside `change_puzzle: [u8;32]`. Use the stored program source at settlement time instead of re-deriving. This eliminates the implicit coupling to `create_delegated_puzzle` being immutable.

---

### F-02 — Offer ID reuse after removal [LOW]

**Location:** `src/cli.rs:2417` (offer_create_command) and `src/cli.rs:2848` (offer_take_command)
**Description:**
`offer_id` is assigned as `state.pending_offers.len()` before push — so it starts at 0, increments per offer. When an offer is settled and removed via `state.pending_offers.remove(offer_pos)`, the `len()` decreases. The next offer created will receive an ID equal to the current `len()`, which may equal a previously used (and removed) ID.

Scenario: create offer 0 → settle offer 0 (removed) → create offer 1 → settle offer 1 (removed) → create offer 2 → `len() = 0`, so new offer gets `id = 0`. A user who wrote down "offer-id 0" from the first offer, then creates a new offer, sees the new offer also listed as ID 0.

FIX-02's `.position(|o| o.id == offer_id)` finds the FIRST match — with reuse, the wrong offer could theoretically be taken if two offers with the same ID existed simultaneously. That can't happen with a single `Vec` since the old offer is removed before the new one is added. However, the UX confusion and potential for scripted clients to take the wrong offer is real.

**Relation to known issues:** FIX-02 — this is a residual fragility in the fix itself.

**Recommendation:** Use a monotonically increasing counter (e.g., `next_offer_id: usize` stored on `SimulatorState`) for offer IDs. Never reuse an ID.

---

### F-03 — FIX-06 marks spent by `serial_commitment` but FIX-05 dedup also uses `serial_commitment` — no interaction issue [INFO]

**Location:** `src/cli.rs:2715-2721` (FIX-06), `src/cli.rs:1777-1781` (FIX-05)
**Description:**
Both fixes use `serial_commitment` as the coin identity key, which is correct. No interaction hazard: FIX-06 marks the taker's input coin as spent; FIX-05 prevents re-scanning already-known coins. They operate on different wallets and different code paths.

---

### F-04 — `create_faucet_puzzle` called with `offer.offered` for taker's change coin [INFO]

**Location:** `src/cli.rs:2528`
**Description:**
```rust
let (taker_change_program, taker_change_puzzle) = create_faucet_puzzle(offer.offered);
```
The taker's change coin is the leftover from the taker's payment, not related to `offer.offered` (the goods amount). However, `create_faucet_puzzle` ignores its `_amount` argument entirely — the program is always `"(mod () 1)"` regardless. No functional impact.

This is pre-existing behavior (the parameter was always a no-op). The call is misleading but harmless. Not introduced by this PR.

---

### F-05 — Scan dedup check precedes ownership check — potential false skip [LOW]

**Location:** `src/cli.rs:1799-1806`
**Description:**
The serial_commitment skip check runs BEFORE `try_scan_with_nonce`, which is the call that determines if a coin belongs to this wallet:

```rust
// skip check uses info.coin.serial_commitment from ANY coin in the simulator
if existing_serial_commitments.contains(info.coin.serial_commitment.as_bytes()) {
    println!("  found coin {} (already in wallet, skipping)", ...);
    continue;
}
// only THEN does ownership check run
let scanned = match view_key.try_scan_with_nonce(puzzle_hash, nonce) { ... };
```

`existing_serial_commitments` is the set of serial commitments from THIS wallet's coins. If two wallets share the same serial commitment (practically impossible — serial numbers are random 32-byte values), a coin could be incorrectly skipped. In practice the probability is negligible (2^-256 collision), but the logic claims "already in wallet, skipping" for a coin it hasn't yet confirmed belongs to this wallet. The printed message is misleading.

More concretely: if for any reason the simulator's `CoinInfo.serial_commitment` diverges from what was stored in the wallet (e.g., a future protocol version changes how serial commitments are represented), this skip could produce a false positive and silently drop a coin from the scan.

**Recommendation:** Move the serial_commitment skip check AFTER `try_scan_with_nonce`, so it only skips coins confirmed to belong to this wallet.

---

### F-06 — Maker's coin not marked spent during `offer_take_command` [INFO — pre-existing]

**Location:** `src/cli.rs:2404-2411` (offer_create_command marks it spent), `offer_take_command` — no counterpart.
**Description:**
The maker's original coin IS marked spent in `offer_create_command` at lines 2404-2411. This is correct. No action needed — PR3 does not regress this. Noted for completeness.

---

### F-07 — `taker_tail_source: None` hardcoded — XCH-only taker assumption [MEDIUM]

**Location:** `src/cli.rs:2563`
**Description:**
```rust
taker_tail_source: None, // XCH taker: no TAIL required
```
`SettlementParams.taker_tail_source` is `None` unconditionally, meaning the settlement will fail if the taker is spending a CAT coin. The taker's asset type is validated against `offer.requested_tail_hash` (line 2490), but if a CAT taker is allowed through (e.g., if someone sets `requested_tail_hash` to a non-XCH hash), the settlement guest will reject the spend because TAIL enforcement requires a non-None `tail_source`.

This is not introduced by PR3 — the prior code had the same behavior. But it means the asset-type check on line 2490 does not fully validate whether the taker CAN complete the settlement — it only checks the tail_hash matches, not whether the TAIL source is provided.

**Recommendation:** Either enforce XCH-only taker at the argument-parsing layer (assert `offer.requested_tail_hash == XCH_TAIL`), or require taker to supply TAIL source when their coin is a CAT.

---

## Known Issue Resolution Status

| Issue | Expected Fix | Actual Status |
|-------|-------------|---------------|
| NM-001: Post-settlement coins non-spendable | Fix tail_hash + program source for all outputs | FIXED for 3 of 4 spendable outputs; payment coin is intentionally left as stealth-unspendable (documented). Maker change coin fix has a latent fragility (F-01). |
| FIX-02: Offer ID uses vec index | Find by stored `.id` | FIXED. Now uses `.position(|o| o.id == offer_id)`. Introduces ID reuse hazard (F-02). |
| FIX-05: Scan dedup by puzzle_hash | Switch to serial_commitment | FIXED. Now deduplicates by `serial_commitment.as_bytes()`. Minor ordering concern noted (F-05). |
| FIX-06: Taker coin not marked spent | Mark `spent = true` after settlement | FIXED. Marks via serial_commitment match. |
| NM-002: Missing maker_pubkey assertion | Assert proof output matches stored offer | NOT IN THIS PR (fixed in PR2, unchanged here). |
| Stealth payment coin unspendable | Known residual; PR4+ scope | CARRIED FORWARD. Documented in code as `"(stealth)"`. |
| FIX-04: Nonce collision on multiple payments | PR4 scope | OPEN. Not touched by this PR. |

---

## Test Coverage

No new tests are added in this PR. The following settlement scenarios remain untested:

1. **Post-settlement spendability (NM-001 fix):** No end-to-end test verifies that goods/change/maker_change coins can be spent after settlement (the core claim of the fix). The issues.md coverage gap "Settlement wallet insertion: No test verifies post-settlement coins are spendable" remains open.

2. **FIX-02 regression:** No test verifies that taking offer ID 1 still works when offer ID 0 has been previously settled and removed (the bug scenario). No test for ID reuse (F-02).

3. **FIX-05 regression:** No test verifies that re-scanning after an initial scan doesn't add duplicate coins.

4. **FIX-06 regression:** No test verifies that the taker's coin shows `spent = true` after settlement.

5. **CAT taker path:** No test exercises settlement with a CAT taker coin — the `taker_tail_source: None` hardcoding (F-07) would fail silently.

---

## Summary

| Finding | Severity | New in PR3 | Recommendation |
|---------|----------|-----------|----------------|
| F-01: `maker_change_program` re-derived, not stored | MEDIUM | YES | Add `change_program: String` to `StoredOffer` |
| F-02: Offer ID reuse after removal | LOW | YES (side effect of FIX-02) | Use monotonic counter for offer IDs |
| F-03: FIX-05 and FIX-06 no interaction issue | INFO | N/A | No action |
| F-04: `create_faucet_puzzle(offer.offered)` for change coin | INFO | PRE-EXISTING | Cosmetic; no functional impact |
| F-05: Dedup skip precedes ownership check | LOW | YES | Move skip after `try_scan_with_nonce` |
| F-06: Maker coin marked spent in `offer_create_command` | INFO | PRE-EXISTING | Already handled correctly |
| F-07: `taker_tail_source: None` hardcoded (CAT taker unsupported) | MEDIUM | PRE-EXISTING | Enforce XCH-only taker or supply TAIL source |

The four stated fixes (NM-001, FIX-02, FIX-05, FIX-06) are correctly applied. The PR does not introduce any HIGH severity issues. The most actionable finding is **F-01**: storing `maker_change_program` in `StoredOffer` eliminates a hidden coupling that will silently break if `create_delegated_puzzle` ever changes.
