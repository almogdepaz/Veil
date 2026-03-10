# Enemy Pass 3 - Feynman (Targeted Re-Interrogation)

## Pass Ledger
- Pass: `3`
- Auditor: `Feynman`
- Scope mode: `Targeted (delta-only)`
- Input delta from Pass 2:
  - `SI-001` (settlement output reconstruction mismatch)
  - `SI-002` (maker key linkage check omission)
  - `SI-003` (single-nullifier projection helper)
- Scope IN:
  - `src/cli.rs` offer-take and spend flows
  - `src/protocol/structures.rs` + `clvm_zk_core/src/coin_commitment.rs`
  - `backends/risc0/guest/src/main.rs`
  - `src/protocol/settlement.rs`
- Scope OUT:
  - previously-cleared non-settlement modules
- Output artifact: `.audit/findings/feynman-pass3.md`

## Targeted Interrogation

### Delta Item A - SI-001 (wallet reconstruction mismatch)

**Q1:** Why does settlement insert wallet outputs with a placeholder program?

**Trace:**
1. `offer_take_command` pushes settlement outputs to both wallets with `program: "(mod () (q . ()))"` (`src/cli.rs`, around `2925-3035`).
2. Future spends consume this stored program (`src/cli.rs`, around `1736-1739`, `2124-2127`).
3. Guest spending enforces `program_hash == commitment_data.program_hash` (`backends/risc0/guest/src/main.rs`, around `374-375`).

**Q2:** Why are settlement output coins instantiated as XCH regardless of proof tail hashes?

**Trace:**
1. Settlement params include explicit asset tails (`taker_tail_hash`, `goods_tail_hash`) (`src/cli.rs`, around `2752-2756`).
2. Settlement guest commitments are built with those tails (`backends/risc0/guest_settlement/src/main.rs`, around `119-145`).
3. Host inserts wallet coins with `PrivateCoin::new(...)` (XCH default) (`src/cli.rs`, around `2912`, `2937`, `2961`, `2993`, `3019`; `src/protocol/structures.rs`, around `101-103`).
4. Commitment preimage includes `tail_hash`; CAT/XCH mismatch changes leaf (`clvm_zk_core/src/coin_commitment.rs`, around `71-85`, `105-123`).

**Feynman verdict:** The implicit assumption is "proof output commitments and wallet coin records are equivalent by construction." They are not. This breaks both spend preconditions: (a) program hash equality and (b) leaf commitment reconstruction.

**Reachability / impact:**
- Reachable on every `offer_take_command`.
- For XCH-only offers: spend path fails at `program_hash mismatch`.
- For CAT-involving offers: failure can occur earlier at merkle path lookup due wrong `tail_hash`, then also at program mismatch.

**Result:** `TRUE POSITIVE`, severity kept `HIGH`.

---

### Delta Item B - SI-002 (maker pubkey linkage guard)

**Q:** Why is there no explicit runtime check that settlement proof key matches stored offer key?

**Trace:**
1. Settlement guests expose `maker_pubkey` publicly "so validator can check it matches offer" (`backends/*/guest_settlement/src/main.rs`, comments around output struct).
2. CLI contains only a comment about this requirement (`src/cli.rs`, around `2816`) and proceeds to state mutation without assertion.
3. Wallet payment puzzle derivation uses `offer.maker_pubkey` (`src/cli.rs`, around `2892-2895`), while proof commitment derivation uses key extracted from maker proof inside `prove_settlement`.

**Feynman verdict:** Missing guard is real. It is a consistency hardening gap: if metadata and proof diverge (tampered/off-path offer object), host local coin reconstruction can desync from proof-committed outputs.

**Reachability / impact:**
- Not triggered on normal in-process offer creation/take flow.
- Triggerable under tampered imported or edited offer metadata.

**Result:** `TRUE POSITIVE`, severity `LOW`.

---

### Delta Item C - SI-003 (`SettlementProof::to_spend_bundle`)

**Q:** Is single-nullifier projection exploitable in active flow?

**Trace:**
- Method exists and drops taker nullifier (`src/protocol/settlement.rs`, around `43-51`).
- No active settlement execution path in this scope uses `to_spend_bundle`; CLI uses `process_settlement(&settlement_proof.output)` directly (`src/cli.rs`, around `2872-2874`).

**Feynman verdict:** Risky API shape, but no in-scope exploitable path currently.

**Result:** `FALSE POSITIVE` for this audit scope.

## Delta vs Previous Passes

### Net-New Findings
1. `FF-001` (Cross-feed `P2 -> P3`): settlement output/wallet reconstruction desync causes deterministic post-settlement spend failure.
2. `FF-002` (Cross-feed `P2 -> P3`): missing maker key linkage assertion before settlement state mutation.

### Net-New Root Causes
- RC-01: Placeholder wallet program + XCH-default tail insertion after settlement.
- RC-02: Required key-link invariant documented but not enforced.

### False Positives Eliminated
- `SI-003`: single-nullifier projection helper not used in active settlement path.

### Severity Adjustments
- None (SI-001 remains HIGH; SI-002 remains LOW).

## Output for Pass 4 (Targeted State Re-Analysis)
- Re-check all settlement mutation paths for additional coupled pairs impacted by RC-01/RC-02.
- Verify no parallel path already performs reconciliation.
