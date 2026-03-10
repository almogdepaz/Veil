# Enemy Pass 4 - State (Targeted Re-Analysis)

## Pass Ledger
- Pass: `4`
- Auditor: `State`
- Scope mode: `Targeted (delta-only)`
- Input delta from Pass 3:
  - `FF-001` root cause: settlement wallet reconstruction desync
  - `FF-002` root cause: missing maker key linkage assertion
- Scope IN:
  - settlement-related mutations in `src/cli.rs`, `src/simulator.rs`, `src/protocol/settlement.rs`
  - spend path checks in `src/cli.rs` + guest program hash invariant
- Scope OUT:
  - previously-cleared non-settlement subsystems
- Output artifact: `.audit/findings/state-pass4.md`

## Targeted Re-Analysis Results

### Coupled Pair Re-Check
- Re-validated `CP-01/CP-02/CP-03`:
  - settlement outputs inserted into simulator are not reconciled with wallet descriptors in offer-take path.
- Re-validated `CP-04`:
  - no runtime assertion introduced between offer key and proof key.

### Mutation Path Propagation
- No additional writer besides `offer_take_command` creates post-settlement wallet coin descriptors.
- No hidden hook/modifier reconciles `program` or `tail_hash` after insertion.
- Non-settlement coin creation helpers (`create_coin`, `create_coin_with_tail`) remain synchronized and unaffected.

### Parallel Path Mismatch Confirmation
- Normal spend/faucet paths: synchronized coin+program+simulator updates.
- Offer settlement path: simulator commitments are updated first, then wallet descriptors are written with divergent metadata.
- Missing `maker_pubkey` linkage check remains localized to settlement acceptance path.

## Verification Summary

| ID | Coupled Pair | Breaking Op | Verdict | Final Severity |
|---|---|---|---|---|
| NM-001 | CP-01/CP-02/CP-03 | `offer_take_command` post-settlement wallet insertion | TRUE POSITIVE (code-trace) | HIGH |
| NM-002 | CP-04 | missing `maker_pubkey` equality assertion in `offer_take_command` | TRUE POSITIVE (code-trace) | LOW |

## Delta vs Previous Passes

### Net-New Findings
- None.

### Net-New Coupled Pairs
- None.

### Net-New Mutation Paths
- None.

### False Positives Eliminated
- None (carried from Pass 3).

## Convergence Check
- Last pass produced no net-new findings, couplings, or mutation paths.
- Enemy loop converged at Pass 4.
