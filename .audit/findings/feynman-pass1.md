# Enemy Pass 1 - Feynman (Full Baseline)

## Pass Ledger
- Pass: `1`
- Auditor: `Feynman`
- Scope: `/Users/home/Dev/veil`
- Mode: `Full baseline (Phase 0->5)`
- Input: Raw `veil` workspace
- Output artifact: `.audit/findings/feynman-pass1.md`

## Phase 0 - Attacker Recon

### Language
- Rust workspace (`src`, `clvm_zk_core`, settlement guests for RISC0/SP1)

### Attack Goals
1. Lock or desynchronize settled assets so users cannot spend outputs after an apparently successful trade.
2. Break nullifier/accounting integrity so spends are accepted while wallet/simulator state diverges.
3. Misroute settlement payment outputs to the wrong recipient key material.
4. Create irreversible state skew between proof outputs and host wallet records.

### Novel / High Bug-Density Areas
- `src/cli.rs`: local validator/orchestrator flow for `offer-create` and `offer-take`.
- `src/protocol/settlement.rs`: host-side extraction of maker terms + settlement proof creation.
- `src/simulator.rs`: nullifier and commitment state mutation (`process_settlement`).
- `backends/*/guest_settlement/src/main.rs`: settlement output commitments and public fields.

### Value Stores and Outflow/Mutation Paths
- **Nullifier anti-double-spend state:** `CLVMZkSimulator.nullifier_set`
  - Mutated by: `spend_coins_*`, `process_settlement`.
- **Spendable commitment tree/index:** `coin_tree`, `commitment_to_index`, `merkle_leaves`
  - Mutated by: `add_coin*`, `spend_coins_*`, `process_settlement`.
- **Wallet-side spend descriptors:** `WalletCoinWrapper { coin, program, spent }`
  - Mutated by: faucet/transfer paths and `offer_take_command` wallet insertion.
- **Offer metadata:** `StoredOffer.{maker_pubkey,maker_bundle,offered_tail_hash,requested_tail_hash}`
  - Mutated by: `offer_create_command`, consumed by `offer_take_command`.

### Complex Interaction Path
1. `offer_create_command` -> persists `StoredOffer`.
2. `offer_take_command` -> `prove_settlement(...)` -> dual proof verification -> `simulator.process_settlement(...)`.
3. `offer_take_command` then reconstructs output coins into wallets for future spending.

This path crosses proof construction, proof verification, state commitment insertion, and wallet local state mutation.

## Phase 1 - Function-State Matrix (Condensed)

| Function | Reads | Writes | Guards / Assumptions | External Calls |
|---|---|---|---|---|
| `offer_create_command` | maker wallet coin/program, requested tail arg | pending offer list, maker coin `spent=true` | assumes delegated puzzle hash match and exactly one maker coin | `Spender::create_conditional_spend` |
| `offer_take_command` | offer metadata + taker coin + simulator root/path | simulator settlement state, maker/taker wallet coins, pending offers | assumes settlement output is link-consistent with stored offer metadata | `prove_settlement`, proof verifiers, `process_settlement` |
| `prove_settlement` | maker proof bytes/journal, taker coin data | settlement proof/output | assumes validator enforces maker/taker linkage and maker pubkey binding | zkVM prover (`risc0`/`sp1`) |
| `CLVMZkSimulator.process_settlement` | settlement output | nullifier set, commitment index/tree | assumes upstream output commitments map to wallet-manageable coin descriptors | none |
| `Spender::create_spend_with_serial` | wallet coin + program + secrets | proof bundle | assumes `program` compiles to `coin.puzzle_hash` and commitment fields align | `ClvmZkProver::prove_with_serial_commitment` |
| `SettlementProof::to_spend_bundle` | settlement output | single-nullifier spend bundle | assumes one nullifier is sufficient for downstream validators | none |

## Phase 2 - Feynman Interrogation Highlights

### Suspect FS-01 (Category 1/2/7): Settlement output reconstruction appears inconsistent with spend semantics
- **Question:** Why are post-settlement wallet coins created with placeholder program source instead of the program that matches each coin's `puzzle_hash`?
- **Code evidence:**
  - `offer_take_command` inserts five post-settlement wallet coins with `program: "(mod () (q . ()))"` (`src/cli.rs`, around lines `2925-3035`).
  - Spending path later uses stored wallet program when proving (`src/cli.rs`, around lines `2124-2127` and `1736-1739`).
  - Guest spend logic asserts compiled `program_hash == coin.program_hash` (`backends/risc0/guest/src/main.rs`, around lines `374-375`).
- **Verdict:** `SUSPECT`.
- **State feed to Pass 2:** wallet coin descriptor (`coin fields + program`) <-> simulator commitment tree entries.

### Suspect FS-02 (Category 3/4): Asset-type metadata may be dropped on settlement wallet insertion
- **Question:** Why are settlement output coins instantiated with `PrivateCoin::new` (XCH default tail) even when settlement supports non-XCH asset tails?
- **Code evidence:**
  - `offer_take_command` creates all five settlement wallet coins via `PrivateCoin::new(...)` (`src/cli.rs`, around lines `2912`, `2937`, `2961`, `2993`, `3019`).
  - `PrivateCoin::new` hardwires `XCH_TAIL` (`src/protocol/structures.rs`, around lines `101-103`).
  - Coin commitment includes `tail_hash` in preimage (`clvm_zk_core/src/coin_commitment.rs`, lines around `71-85` and `105-123`).
- **Verdict:** `SUSPECT`.
- **State feed to Pass 2:** settlement commitment tail-hash state <-> wallet `coin.tail_hash`.

### Suspect FS-03 (Category 3/4): Missing explicit maker key linkage check despite stated validator requirement
- **Question:** Why is there no check that `settlement_proof.output.maker_pubkey` matches `offer.maker_pubkey` before settlement state mutation?
- **Code evidence:**
  - Guest output explicitly exposes `maker_pubkey` for validator checking (`backends/*/guest_settlement/src/main.rs`, comments around lines `22-33` and `143-153`).
  - CLI comment acknowledges required check but does not enforce it (`src/cli.rs`, around line `2816`).
- **Verdict:** `SUSPECT`.
- **State feed to Pass 2:** offer metadata key <-> settlement proof public key <-> payment coin derivation.

### Suspect FS-04 (Category 6): Settlement bundle helper drops one nullifier
- **Question:** Why does `SettlementProof::to_spend_bundle()` include only `maker_nullifier` while settlement output carries two nullifiers?
- **Code evidence:**
  - `to_spend_bundle` maps settlement to single-nullifier `PrivateSpendBundle` (`src/protocol/settlement.rs`, around lines `43-51`).
- **Verdict:** `SUSPECT` (possible API-level inconsistency; requires state cross-check for active usage).

## Verification Summary (Pass 1)
- Confirmed C/H/M findings this pass: `0`
- Suspects forwarded to State pass: `4` (`FS-01`..`FS-04`)

## Output for Pass 2
- Run full State pass on coupled pairs around settlement outputs, wallet descriptors, nullifier sets, and offer metadata linkage.
