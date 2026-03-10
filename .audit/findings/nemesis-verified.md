# E N E M Y - Verified Findings

## Scope
- Language: Rust
- Modules analyzed: `src/cli.rs`, `src/simulator.rs`, `src/protocol/settlement.rs`, `src/protocol/spender.rs`, `src/protocol/structures.rs`, `clvm_zk_core/src/coin_commitment.rs`, `backends/risc0/guest/src/main.rs`, `backends/risc0/guest_settlement/src/main.rs`, `backends/sp1/program_settlement/src/main.rs`
- Functions analyzed: 41 (priority high-risk paths)
- Coupled state pairs mapped: 5
- Mutation paths traced: 14
- Total passes run: 4 (max 6)
- Converged: yes

## Enemy Map (Phase 1 Cross-Reference)

| Function | Writes A | Writes B | A<->B Pair | Sync Status |
|---|---:|---:|---|---|
| `CLVMZkSimulator.process_settlement` | nullifier + commitment state | wallet descriptors | `CP-01/02/03` | producer-only |
| `offer_take_command` (post-proof wallet insertion) | wallet descriptors | simulator commitments | `CP-01/02/03` | **gap** |
| `offer_take_command` (key linkage) | offer metadata key use | proof-output key check | `CP-04` | **gap** |
| `SettlementProof::to_spend_bundle` | maker nullifier projection | taker nullifier projection | `CP-05` | asymmetry (not active path) |

## Verification Summary

| ID | Discovery Path | Coupled Pair | Breaking Op | Severity | Verdict |
|----|----------------|-------------|-------------|----------|---------|
| NM-001 | Cross-feed P2->P3 | `CP-01/02/03` | `offer_take_command` | HIGH | TRUE POSITIVE |
| NM-002 | Cross-feed P2->P3 | `CP-04` | `offer_take_command` | LOW | TRUE POSITIVE |
| NM-003 | Feynman-only | `CP-05` | `SettlementProof::to_spend_bundle` | LOW | FALSE POSITIVE |

## Verified Findings (TRUE POSITIVES only)

### Finding NM-001: Settlement outputs are persisted with non-spendable and asset-divergent wallet metadata
**Severity:** HIGH  
**Discovery Path:** Cross-feed P2->P3  
**Source:** State gap from Pass 2 + Feynman root-cause pass 3  
**Verification:** Hybrid code trace

**Coupled Pair:**  
- simulator commitment state (`commitment_to_index` / merkle leaves)  
- wallet spend descriptors (`WalletCoinWrapper.wallet_coin.coin` + `program`)

**Invariant:**  
A wallet coin inserted after settlement must (a) reconstruct the exact committed leaf and (b) carry a program that hashes to the coin's `puzzle_hash`.

**Feynman question that exposed it:**  
> Why does `offer_take_command` create post-settlement wallet coins with a placeholder program and XCH-default constructor when commitments were generated from settlement proof outputs?

**State mapper gap that confirmed it:**  
> Settlement writes simulator commitments first, then writes wallet descriptors that do not preserve program/tail-hash coupling required by spend verification.

**Breaking operation:** `offer_take_command` in `src/cli.rs`
- Uses `PrivateCoin::new(...)` for all five settlement outputs (XCH default tail).
- Writes `program: "(mod () (q . ()))"` for all outputs.
- Proof outputs committed in simulator were produced using settlement guest tails and puzzle fields.

**Trigger Sequence:**
1. Execute `offer-take` and complete settlement proof verification.
2. `process_settlement` inserts commitments/nullifiers to simulator state.
3. CLI inserts wallet coins with placeholder program and default tail.
4. Attempt to spend one of these coins through normal CLI spend flow.
5. Spend fails:
   - `program_hash mismatch` in guest verifier path.
   - For CAT outputs, commitment lookup can fail due tail mismatch.

**Consequence:**
- Accepted settlement outputs become non-spendable or inconsistently typed in local state.
- In CAT trades, asset identity can be silently rewritten to XCH in wallet records.
- This breaks core settlement usability and can lock value in practice.

**Verification Evidence:**
- Spend flow uses stored wallet `program` (`src/cli.rs` spend path).
- Guest enforces compiled program hash equality (`backends/risc0/guest/src/main.rs`).
- Commitment preimage includes `tail_hash` (`clvm_zk_core/src/coin_commitment.rs`).
- Settlement wallet insertion does not preserve these invariants (`src/cli.rs` offer-take tail/program insertion).

**Fix (minimal direction):**
```rust
// 1) Preserve real asset tails per output:
//    - payment + taker change + maker payment: requested/taker asset tail
//    - taker goods + maker change: offered/maker asset tail
let coin = PrivateCoin::new_with_tail(puzzle_hash, amount, serial_commitment, tail_hash);

// 2) Persist correct puzzle source per output (not placeholder), and reject
//    insertion if no spendable source is available for a produced puzzle hash.

// 3) For settlement payment puzzle design, ensure generated puzzle_hash maps to
//    an executable puzzle source that can be re-proven in spend flow.
```

---

### Finding NM-002: Missing maker pubkey linkage assertion before settlement state transition
**Severity:** LOW  
**Discovery Path:** Cross-feed P2->P3  
**Source:** State linkage check + targeted Feynman guard consistency  
**Verification:** Code trace

**Coupled Pair:** `StoredOffer.maker_pubkey` <-> `SettlementOutput.maker_pubkey`

**Invariant:**  
The key used by settlement proof output must match the key attached to the accepted offer metadata.

**Feynman question that exposed it:**  
> Why is a validator requirement documented in comments but not enforced in runtime code before mutating settlement state?

**State mapper gap that confirmed it:**  
> `offer_take_command` consumes both values in different places but has no equality check gate.

**Breaking operation:** `offer_take_command` accepts settlement and mutates state without asserting key equality.

**Trigger Sequence:**
1. Offer metadata key and maker proof key diverge (tampered/imported mismatch case).
2. Settlement proof still validates cryptographically.
3. CLI processes settlement and derives local payment coin using metadata key.
4. Local payment derivation can diverge from proof-committed outputs.

**Consequence:**
- State inconsistency between accepted proof outputs and locally reconstructed payment metadata.
- Primarily a hardening and integrity issue under tampered input conditions.

**Verification Evidence:**
- Guest output carries `maker_pubkey` for validator check.
- CLI comment notes this check should exist.
- No runtime assertion found before `process_settlement`.

**Fix:**
```rust
if settlement_proof.output.maker_pubkey != offer.maker_pubkey {
    return Err(ClvmZkError::InvalidProgram(
        "settlement/offer maker_pubkey mismatch".to_string(),
    ));
}
```

## Feedback Loop Discoveries
- `NM-001` required cross-feed:
  - State pass mapped the concrete coupled gaps (commitments vs wallet descriptors).
  - Feynman pass traced the exact downstream breakpoints (`program_hash` and tail-sensitive commitment matching).
- `NM-002` was elevated from a guard-style suspicion to a concrete coupled-state integrity check via State mapping.

## False Positives Eliminated
- `NM-003`: `SettlementProof::to_spend_bundle` keeps only maker nullifier, but no active in-scope settlement mutation path consumes this helper.

## Downgraded Findings
- None in this run.

## Summary
- Total functions analyzed: 41
- Coupled state pairs mapped: 5
- Total passes run: 4 (max 6)
- Converged: yes
- Raw findings (pre-verification): 0 C | 1 H | 0 M | 2 L
- Feedback loop discoveries: 2
- After verification: 2 TRUE POSITIVE | 1 FALSE POSITIVE | 0 DOWNGRADED
- Final: 0 CRITICAL | 1 HIGH | 0 MEDIUM | 1 LOW
