# Enemy Raw Findings (Pre-Final Consolidation)

## Scope
- Target: `/Users/home/Dev/veil`
- Language: Rust
- Priority modules scanned: 10
- Priority functions analyzed: 41

## Pass Timeline

| Pass | Auditor | Mode | Output | Net-New Delta |
|---|---|---|---|---|
| 1 | Feynman | Full | `feynman-pass1.md` | 4 suspects (`FS-01`..`FS-04`) |
| 2 | State | Full (enriched) | `state-pass2.md` | 2 confirmed gaps (`SI-001`, `SI-002`), 1 unresolved (`SI-003`) |
| 3 | Feynman | Targeted | `feynman-pass3.md` | 2 confirmed findings (`FF-001`, `FF-002`), 1 false positive eliminated |
| 4 | State | Targeted | `state-pass4.md` | no net-new items (converged) |

## Phase 1 Enemy Map (Condensed)

| Function | Writes A | Writes B | Coupled Pair | Status |
|---|---:|---:|---|---|
| `CLVMZkSimulator.process_settlement` | nullifier set + commitment tree | wallet descriptors | CP-01/02/03 | producer only |
| `offer_take_command` wallet insertion | wallet coin descriptors | simulator commitments | CP-01/02/03 | **gap** |
| `offer_take_command` key handling | offer key usage | proof key check | CP-04 | **gap** |
| `SettlementProof::to_spend_bundle` | maker nullifier | taker nullifier | CP-05 | asymmetry (later eliminated in-scope) |

## Raw Finding Set

### RF-001 -> NM-001 (survived)
- **Title:** Post-settlement wallet reconstruction diverges from proof-committed outputs
- **Discovery path:** Cross-feed `P2 -> P3`
- **Root cause:** `offer_take_command` inserts settlement outputs with placeholder program source and default XCH tail, while simulator commitments come from settlement proof output (which may include non-XCH tails and different puzzle hashes).
- **Why it matters:** outputs accepted into global state can become non-spendable from wallet flow due `program_hash mismatch` and/or commitment mismatch.
- **Current status:** TRUE POSITIVE (`HIGH`).

### RF-002 -> NM-002 (survived)
- **Title:** Missing maker pubkey linkage assertion before settlement state mutation
- **Discovery path:** Cross-feed `P2 -> P3`
- **Root cause:** runtime never enforces `settlement_proof.output.maker_pubkey == offer.maker_pubkey` despite guest and comments declaring this validator requirement.
- **Current status:** TRUE POSITIVE (`LOW`).

### RF-003 (eliminated)
- **Title:** Single-nullifier projection in `SettlementProof::to_spend_bundle`
- **Discovery path:** Feynman suspect -> State check -> targeted Feynman call-site review
- **Disposition:** FALSE POSITIVE in current scope (helper not used in active settlement state transition path).

## Multi-Step Trigger Traces (Raw)

### NM-001 operational sequence
1. Taker executes `offer_take_command`, producing a valid settlement proof and output commitments.
2. `process_settlement` inserts commitments into simulator merkle/index state.
3. Host inserts corresponding wallet coins using placeholder program and XCH-default tail.
4. Later spend path consumes wallet `program` and `coin` fields.
5. Guest assertion `program_hash == coin.program_hash` fails; CAT outputs can also fail merkle lookup due tail mismatch.

### NM-002 operational sequence
1. Settlement output carries `maker_pubkey` from maker proof/journal.
2. Host does not assert that it equals `offer.maker_pubkey`.
3. If offer metadata diverges (tampered/imported mismatch), local payment coin derivation can diverge from proof output commitments.

## Verification Log (Raw)

| Finding | Method | Result |
|---|---|---|
| RF-001 | Deep code trace across `cli` -> `simulator` -> guest spend invariants | confirmed |
| RF-002 | Deep code trace + invariant check against guest output contract | confirmed |
| RF-003 | Call-site trace | disproved (in-scope non-reachable) |

## Convergence
- No net-new findings in Pass 4.
- Loop converged before pass bound (`4/6` passes used).
