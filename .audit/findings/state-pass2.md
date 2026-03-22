# Enemy Pass 2 - State Inconsistency (Full, Enriched by Pass 1)

## Pass Ledger
- Pass: `2`
- Auditor: `State`
- Scope: `/Users/home/Dev/veil`
- Mode: `Full baseline (Phase 1->8)`
- Input:
  - Raw codebase
  - Pass 1 suspects: `FS-01`..`FS-04`
- Output artifact: `.audit/findings/state-pass2.md`

## Coupled State Dependency Map

| Pair ID | Coupled State | Invariant |
|---|---|---|
| CP-01 | `simulator.commitment_to_index/merkle_leaves` <-> wallet `WalletCoinWrapper.wallet_coin.coin` | Every wallet coin inserted after settlement must reconstruct a coin commitment that already exists in simulator state. |
| CP-02 | wallet `coin.puzzle_hash` <-> wallet `program` | Stored program must compile to the same puzzle hash for spend proofs to succeed. |
| CP-03 | settlement asset tails (`taker_tail_hash`, `goods_tail_hash`) <-> wallet `coin.tail_hash` | Output coins must preserve proof-committed asset type (XCH vs CAT). |
| CP-04 | `StoredOffer.maker_pubkey` <-> `SettlementOutput.maker_pubkey` | Offer metadata key and proof-committed key must match before state transition. |
| CP-05 | `SettlementOutput.{maker_nullifier,taker_nullifier}` <-> any projected spend-bundle nullifier representation | No projection helper should silently drop one side when used for anti-double-spend checks. |

## Mutation Matrix (Focused)

### CP-01 / CP-02 / CP-03 (`offer_take_command` + simulator)

| Mutating Function | Mutates simulator commitments | Mutates wallet coin descriptor | Sync status |
|---|---:|---:|---|
| `CLVMZkSimulator.process_settlement()` | yes (adds 4 commitments) | no | baseline producer |
| `offer_take_command` post-settlement wallet insertion | no | yes (adds 5 wallet coins + program strings) | **gap** |
| `spend_to_puzzle` / transfer paths | yes (via simulator) | yes (uses matching helper-generated puzzle/program) | synced in non-settlement paths |

### CP-04 (`offer_take_command` / `prove_settlement`)

| Mutating Function | Writes offer key | Writes proof key | Enforces equality | Sync status |
|---|---:|---:|---:|---|
| `offer_create_command` | yes (`StoredOffer.maker_pubkey`) | implicit in maker proof output | n/a | initialized |
| `prove_settlement` | reads offer bundle | outputs `maker_pubkey` from maker proof journal | no host assertion | potential gap |
| `offer_take_command` | uses `offer.maker_pubkey` to derive local payment puzzle | processes `settlement_proof.output` separately | **no** | **gap** |

### CP-05 (`SettlementProof::to_spend_bundle`)

| Mutating Function | Reads maker nullifier | Reads taker nullifier | Result |
|---|---:|---:|---|
| `SettlementProof::to_spend_bundle` | yes | **no** | possible projection mismatch; usage-dependent |

## Parallel Path Comparison

| Goal | Path A | Path B | State outcome |
|---|---|---|---|
| Add spendable outputs to wallet + simulator | faucet/normal transfer paths (`create_coin*`) | offer settlement path (`offer_take_command`) | non-settlement path stores matching puzzle+coin metadata; settlement path stores placeholder program and XCH-default tails. |
| Enforce maker key linkage | comment/guest requirement | runtime enforcement in CLI | requirement exists but runtime check missing. |
| Nullifier tracking | `process_settlement` tracks both nullifiers | `to_spend_bundle` keeps one | asymmetry requires targeted interrogation. |

## Feynman-Enriched Target Results

### SI-001 (from FS-01 + FS-02) - Confirmed state gap
- **Coupled pairs:** `CP-01`, `CP-02`, `CP-03`
- **Breaking operation:** settlement wallet reconstruction in `offer_take_command` (`src/cli.rs`, around `2912-3035`)
- **Gap details:**
  - Wallet program for all five outputs is forced to placeholder source (`"(mod () (q . ()))"`).
  - All five outputs are created via `PrivateCoin::new` (default XCH tail), regardless of settlement asset tails.
  - Simulator commitments are inserted from proof output in `process_settlement` and may encode CAT tails and non-placeholder puzzle hashes.
- **Downstream consequence path:**
  - Spend path uses wallet `program` and coin fields (`src/cli.rs`, around `2124-2127`).
  - Guest enforces compiled hash equality (`backends/risc0/guest/src/main.rs`, around `374-375`).
  - Merkle lookup uses commitment built from wallet coin fields; CAT tail mismatch yields missing leaf (`src/simulator.rs`, around `463-475`).
- **Preliminary severity:** `HIGH` (core settlement outputs can become unusable/inconsistent).
- **Verification method (this pass):** code trace.

### SI-002 (from FS-03) - Guard gap confirmed (needs root-cause severity calibration)
- **Coupled pair:** `CP-04`
- **Observation:** CLI notes validator should compare settlement proof key to offer key but does not enforce check.
- **Status:** `Requires Pass 3 targeted Feynman on exploitability and realistic trigger conditions`.

### SI-003 (from FS-04) - unresolved
- **Coupled pair:** `CP-05`
- **Observation:** settlement projection helper emits one nullifier from a two-nullifier output.
- **Counter-hypothesis:** helper may be unused in active settlement validation path.
- **Status:** `Needs Pass 3 call-site interrogation`.

## Verification Summary (Pass 2)

| ID | Coupled Pair | Breaking Op | Original Severity | Verdict | Final Severity |
|---|---|---|---|---|---|
| SI-001 | CP-01/CP-02/CP-03 | `offer_take_command` settlement coin insertion | HIGH | TRUE POSITIVE (code-trace) | HIGH (provisional) |
| SI-002 | CP-04 | missing key linkage assertion | LOW | TRUE POSITIVE (mechanism), impact pending | LOW (provisional) |
| SI-003 | CP-05 | `to_spend_bundle` projection | LOW | UNRESOLVED | pending |

## Output for Pass 3 (Targeted Feynman)
- Re-interrogate **SI-001**:
  - Why is settlement output reconstructed with placeholder program/default tail?
  - What exact downstream call fails first (`merkle lookup` vs `program_hash mismatch`)?
  - Is this all-assets or CAT-only?
- Re-interrogate **SI-002**:
  - Is missing key linkage exploitable in current trust model, or only tamper-risk?
- Re-interrogate **SI-003**:
  - Is `to_spend_bundle` actually used in settlement validation paths?
