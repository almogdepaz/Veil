# Veil — Full Architecture Context

**Project:** Privacy-preserving zkVM for Chialisp
**Status:** WIP research, MIT licensed. Core + offers infrastructure complete.
**Date:** 2026-03-25
**Branch analyzed:** `pr/02-simulator-migration`

---

## 1. System Overview

Veil enables zero-knowledge proofs for Chia blockchain operations. A prover demonstrates knowledge of coin secrets and merkle membership without revealing them. The system supports XCH (native) and CATs (custom asset tokens with TAIL program authorization), ring spends, stealth addresses, and atomic settlement proofs.

**Three execution environments:**
- **Host (64-bit):** `src/` + `backends/*/src/lib.rs` — orchestrates proof generation, manages state
- **zkVM guest (32-bit RISC-V):** `backends/*/guest/src/main.rs` — proves computation inside ZK circuit
- **Core library (no_std):** `clvm_zk_core/` — shared logic across host and guest

**Key invariant:** The host is trusted; the guest is the trust boundary. Anything the guest computes is cryptographically attested.

---

## 2. Module Map

```
clvm_zk_core/src/
  lib.rs              — Chialisp compilation, CLVM execution, condition parsing,
                        balance enforcement, modular_pow, is_clvm_nil, BLS/ECDSA
  types.rs            — Input, CoinMode, SerialCommitmentData, MintData,
                        GenesisSpend, AdditionalCoinInput, ProofOutput, ZKClvmResult
  coin_commitment.rs  — Commitment scheme: coin_commitment, serial_commitment, nullifier
  merkle.rs           — SparseMerkleTree (depth 20, ~1M leaves)
  clvm_parser.rs      — CLVM bytecode parser
  operators.rs        — CLVM operator implementations
  backend_utils.rs    — validate_nullifier_proof_output, validate_proof_output

src/
  lib.rs              — ClvmZkProver facade; routes to backend via feature flags
  simulator.rs        — CLVMZkSimulator (in-memory blockchain state for testing)
  crypto_utils.rs     — hash_data_default (SHA-256 wrapper)
  protocol/
    spender.rs        — Spender: create_spend_with_serial, create_ring_spend,
                        create_conditional_spend
    settlement.rs     — prove_settlement, SettlementOutput, SettlementParams
    structures.rs     — PrivateCoin, PrivateSpendBundle, ProofType, ProtocolError
    puzzles.rs        — Standard puzzle definitions
    recursive.rs      — Recursive proof aggregation
  wallet/
    hd_wallet.rs      — BIP32 HD wallet
    stealth.rs        — Stealth address scanning
    types.rs          — WalletCoinWrapper, StoredOffer

backends/
  mock/src/backend.rs — Full logic, no ZK (for testing)
  risc0/src/lib.rs    — RISC-0 host: host-side guards, prove_with_input
  risc0/guest/main.rs — RISC-0 guest: CLVM execution + cryptographic checks
  sp1/src/lib.rs      — SP1 host (same structure as risc0)
  sp1/program/main.rs — SP1 guest (mirrors risc0 guest)
```

---

## 3. Data Flow — Single Coin Spend

```
CLI / test
  → Spender::create_spend_with_serial(coin, puzzle, params, secrets, merkle_path, root, idx, tail_source, tail_params)
  → ClvmZkProver::prove_with_serial_commitment(...)
      → Build Input { coin_mode: CoinMode::Spend(SerialCommitmentData), tail_hash, tail_source, ... }
      → [host guards: Mint rejected, CAT without tail_source rejected, leaf_index > u32::MAX rejected]
      → Backend::prove_with_input(inputs)
          → Guest receives Input via env::read()
          → compile chialisp OR use precompiled puzzle hash
          → create_veil_evaluator(hasher, bls_verifier, ecdsa_verifier)
          → run_clvm_with_conditions(evaluator, bytecode, args, max_cost)
          → enforce_ring_balance(inputs, conditions)   ← CRITICAL: MUST precede CREATE_COIN transform
          → CoinMode::Spend: verify serial_commitment, coin_commitment, merkle_proof
          → TAIL enforcement: compile tail_source, verify hash == tail_hash, execute TAIL, check !is_clvm_nil
          → compute_nullifier(hash, serial_number, program_hash, amount)
          → transform CREATE_COIN conditions (4-arg → 1-arg coin_commitment)
          → env::commit(ProofOutput { program_hash, nullifiers, clvm_res, ... })
      → Return ZKClvmResult { proof_output, proof_bytes }
  → PrivateSpendBundle { zk_proof, nullifiers, public_conditions }
```

---

## 4. Commitment Scheme

**Serial commitment (hiding):**
```
serial_commitment = SHA256("clvm_zk_serial_v1.0" || serial_number || serial_randomness)
```
Hides `serial_number` until spend time. `serial_randomness` is the blinding factor.

**Coin commitment (binding):**
```
coin_commitment = SHA256("clvm_zk_coin_v2.0" || tail_hash || amount || puzzle_hash || serial_commitment)
```
Permanently binds asset type, amount, puzzle, and serial commitment. Any change → different commitment → fails merkle proof.

**Nullifier (spend receipt):**
```
nullifier = SHA256("clvm_zk_nullifier_v1.0" || serial_number || program_hash || amount)
```
Deterministic from secrets. Added to nullifier set on spend; duplicate → double-spend rejection.

**Key property:** `serial_commitment` is in `coin_commitment` but `serial_number` is not directly. The guest reveals `serial_number` during spend to compute the nullifier, proving knowledge of the preimage.

---

## 5. TAIL Authorization Flow

For any CAT spend (`tail_hash != [0u8;32]`):

1. **`tail_source` required** — host rejects missing `tail_source` for CAT spends before guest
2. **Compile** — guest compiles `tail_source` → `(tail_bytecode, compiled_hash)`
3. **Hash verification** — `assert_eq!(compiled_hash, effective_tail_hash)` — prevents TAIL substitution (F-01 fix)
4. **Execute** — `run_clvm_with_conditions(evaluator, tail_bytecode, tail_args, max_cost)`
5. **Non-nil check** — `assert!(!is_clvm_nil(&tail_output))` — prevents nil return being treated as authorization
6. **Ring coins** — same 5 steps applied per additional ring coin

**TAIL semantics:** A TAIL authorizes by returning truthy (any non-nil, non-zero value). It rejects by raising a CLVM exception OR returning nil/0. `is_clvm_nil(output) = output == [0x80] || output.is_empty()`.

---

## 6. Ring Spend Protocol

- All coins MUST share the same `tail_hash` (enforced by `enforce_ring_balance`)
- Primary coin's puzzle runs for condition generation
- Additional coins verify: serial_commitment, coin_commitment, merkle_proof, TAIL (per-coin)
- `enforce_ring_balance` checks: Σ(input amounts) ≥ Σ(output CREATE_COIN amounts)
- One proof → N nullifiers (one per coin)
- `total_input > total_output` is allowed (burn/fee); `total_output > total_input` = inflation → rejected

---

## 7. Settlement Protocol (V2.0)

Atomic offer flow (no recursive verification):
1. Maker creates `ConditionalSpend` proof with `delegated_puzzle`
2. Taker calls `prove_settlement(params)` — proves taker's coin + embeds maker proof hash
3. Validator checks both proofs independently
4. `process_settlement` (simulator) inserts 4 output commitments + 2 nullifiers atomically, with pre-insertion double-spend check

**Settlement outputs:** maker_change, payment, taker_goods, taker_change (4 coins)

---

## 8. Simulator Architecture

`CLVMZkSimulator` fields:

| Field | Type | Role |
|-------|------|------|
| `nullifier_set` | `HashSet<[u8;32]>` | Double-spend prevention |
| `utxo_set` | `HashMap<[u8;32], CoinInfo>` | UTXOs keyed by serial_number |
| `coin_tree` | `SparseMerkleTree` | Depth-20, ~1M leaves |
| `commitment_to_index` | `HashMap<[u8;32], usize>` | Commitment → leaf position |
| `merkle_leaves` | `Vec<[u8;32]>` | Ordered insertion history (for rebuild) |

**Invariant:** `commitment_to_index[leaf]` == position of `leaf` in `merkle_leaves`. `rebuild_tree()` maintains this by re-inserting `merkle_leaves` in order.

**Hasher alignment:** `crate::crypto_utils::hash_data_default` used everywhere → simulator and guest produce identical roots.

**SparseMerkleTree properties:**
- `root()` always returns `[u8;32]` (empty tree has defined root)
- `insert(leaf, h)` updates root in-place (no `commit()` call needed)
- `generate_proof(leaf_index, h)` → `Result<Proof, String>`; `.path: Vec<[u8;32]>`

---

## 9. CoinMode Enum

```rust
pub enum CoinMode { Execute, Spend(SerialCommitmentData), Mint(MintData) }
```

- `Execute` → no nullifier emitted
- `Spend` → nullifier emitted; serial_commitment, coin_commitment, merkle_proof all verified
- `Mint` → blocked: host returns `Err`, guest panics, `enforce_ring_balance` returns `Err`

Default is `Execute` (safe — does nothing with coins).

---

## 10. Leaf Index Platform Consistency

`SerialCommitmentData.leaf_index: u64` (explicit 8-byte fixed-width for Borsh)

- Host: `leaf_index as u64` (usize ≤ u64 on 64-bit)
- Guest: `usize::try_from(leaf_index).expect(...)` — panics if > u32::MAX (32-bit RISC-V)
- Host guard: rejects `leaf_index > u32::MAX` before sending to guest

---

## 11. CLVM Execution Model

**Condition opcodes used in Veil:**
- `49` AGG_SIG_UNSAFE — BLS sig verification
- `50` AGG_SIG_ME — BLS sig with coin context
- `51` CREATE_COIN — Coin creation (2-arg transparent, 4-arg private, 1-arg after transform)
- `60` CREATE_COIN_ANNOUNCEMENT — Atomic swap support
- `61` ASSERT_COIN_ANNOUNCEMENT — Atomic swap validation

**Balance enforcement position:** MUST run before CREATE_COIN transformation. After transformation, amounts are hidden inside `coin_commitment`.

**CREATE_COIN transformation:**
- 4-arg `(puzzle_hash, amount, serial_number, serial_randomness)` → compute `coin_commitment` → replace with 1-arg `(coin_commitment)`
- Hides output puzzle hash and amount from validators

---

## 12. Security Properties

**In-circuit (guest verifies):**
- `serial_commitment == hash(serial_number || serial_randomness)` — opening is valid
- `coin_commitment == hash(tail_hash || amount || puzzle_hash || serial_commitment)` — coin exists with claimed params
- `merkle_proof` valid against `merkle_root` — coin is in the current tree
- `nullifier == hash(serial_number || program_hash || amount)` — correct nullifier computed
- TAIL compiled hash matches `tail_hash` — no TAIL substitution
- TAIL executes without raising and returns non-nil — authorized

**Out-of-circuit (validator/host verifies):**
- ZK proof validity
- Nullifier not in nullifier set (double-spend)
- Coin commitments form valid merkle tree at claimed root
- Settlement: both maker and taker proofs valid and consistent

---

## 13. Known Issues / Gaps

**NM-001 (FIXED in PR3):** Settlement wallet insertion now uses correct program sources and `new_with_tail` for all outputs. Residual: maker's payment coin uses a stealth-hash puzzle that has no Chialisp program equivalent — not spendable via standard flow (PR4+ scope).

**CoinMode::Mint unimplemented:** Types and guards exist; guest panics. No test coverage.

**Stealth nonce plaintext:** Currently `[u8;32]` stored in CoinInfo. PR4 adds x25519+ChaCha20Poly1305 encryption.

**CAT ring spend untested:** All ring spend tests use XCH coins. No test for multi-coin ring with TAIL enforcement per coin.

**rebuild_tree deserialization:** No test verifies that `rebuild_tree` + serde round-trip produces correct proofs.

**Missing maker pubkey linkage assertion (NM-002, LOW):** `offer_take_command` doesn't assert `StoredOffer.maker_pubkey == SettlementOutput.maker_pubkey` before state transition.

---

## 14. Key Constants

```
BLS_DST  = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG:CHIA_CS_FEE_BLAH_BLAH_BLAH"
SIMULATOR_TREE_DEPTH = 20  (supports ~1M coins)
MAX_LEAF_INDEX = u32::MAX  (32-bit guest limit)
Commitment domain: "clvm_zk_serial_v1.0", "clvm_zk_coin_v2.0", "clvm_zk_nullifier_v1.0"
```

---

## 15. PR Decomposition Status

| PR | Branch | Status |
|----|--------|--------|
| 1 | pr/01-core-types | ✅ merged |
| 2 | pr/02-simulator-migration | ✅ pushed |
| 3 | pr/03-offer-fixes | ✅ pushed (current) |
| 3 | pr/03-offer-fixes | pending (NM-001 fix, offer indexing, taker spent tracking) |
| 4 | pr/04-stealth-nonce-encryption | pending (x25519+ChaCha20Poly1305 stealth nonces) |
| 5 | pr/05-cat-minting | pending (Mint mode guests + CLI) |
| 6 | pr/06-e2e-tests | pending (real ZK e2e tests) |
| 7 | pr/07-examples-docs | pending (non-code) |

---
## Incremental Update — 2026-03-25 (PR3)
Base: 712addb (pr/02-simulator-migration tip)
Head: 07bba3b (pr/03-offer-fixes)
Changed files: src/cli.rs
Modules re-analyzed: none (src/cli.rs not in module map — too large, tracked separately)
Issues resolved: NM-001, NM-002, FIX-02, FIX-05, FIX-06
Issues added: 1 (Stealth payment coin unspendable — residual from NM-001)
