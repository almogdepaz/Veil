# Delivery / Architecture Review

## Summary

**Delivery verdict:** delivered
**Architecture fit:** fits

## Review Calibration

- real goal: complete the canonical-root proof contract so a verified network journal exposes the exact membership root/height and a backend-neutral validator can compare it with canonical history.
- done evidence: typed request/output, guest-enforced root equality, strict canonical journal encoding, real backend prove/verify parity, canonical root/lifetime/metadata policy, and preserved legacy paths.
- not the goal: persistent ledger state, transactions/blocks, SQLite, RPC, sequencing, follower replay, wallets, or Chia checkpoints.
- non-obvious invariants: core stays no_std/backend-neutral; transition variant is the sole proof-kind source; consensus bytes are strict Borsh; canonical lookup binds both height and root; envelope data cannot override verified journal data; validation is mutation-free.

## Goal / Spec Delivery

| Requirement | Evidence in implementation | Status |
|---|---|---|
| spend output contains the root used for membership | `clvm_zk_core/src/network.rs:28`; both guests build output only after request/root validation | delivered |
| faucet binds request, asset, amount, commitment, metadata, and root context | `NetworkProofIntentV1`/`NetworkTransitionV1`; `clvm_zk_core/src/network.rs:70` | delivered |
| mismatched primary/ring roots fail | `clvm_zk_core/src/network.rs:51`; mock regression coverage | delivered |
| proof kind cannot disagree with transition | one typed intent/transition variant; duplicate `proof_kind` removed from the approved plan/docs | delivered |
| strict versioned public journal | network-mode guests commit raw Borsh; `borsh::from_slice` rejects trailing bytes | delivered |
| canonical root, window, and expiry policy | `CanonicalRootV1` plus `validate_network_output_v1` in `crates/veil-ledger/src/lib.rs` | delivered |
| note metadata mutation fails | domain-separated canonical note hash and regression test | delivered |
| backend/program/size verifier boundary | `ProofVerifier`, `verify_network_proof_v1`, concrete size-first SP1/RISC Zero verification | delivered |
| real backend parity | SP1 and RISC Zero each generate/verify faucet and private-transfer proofs and decode equal summaries | delivered |
| preserve simulator compatibility | legacy `ProofOutput` path remains selected by `Input.network == None`; legacy APIs reject network-mode input | delivered |

### Findings

No material delivery finding. The approved contract was corrected before implementation to supply faucet request identity, expose faucet asset identity, eliminate duplicate proof-kind state, and move the minimal storage-independent ledger boundary into this slice.

## Architecture Fit

### Findings

No architecture-boundary finding.

- `clvm_zk_core` owns no_std request/output types and guest-compatible validation.
- backend crates own zkVM proving, verification, and program identity.
- `veil-ledger` owns backend-neutral verification policy, strict decode, canonical root policy, metadata binding, limits, and stable validation errors.
- no HTTP, SQLite, or backend SDK dependency leaked into `veil-ledger`.
- network-mode output construction is shared; backend-specific code only commits/decodes the bytes through each SDK.

## Integration / Rollout Notes

- legacy journal encoding is unchanged; network mode is explicitly selected through the appended optional request field.
- guest program IDs changed as expected and are recorded as slice evidence, not frozen genesis values.
- CI now compiles backend tests, runs mock plus ledger validation, and schedules real network proof evidence.
- the production `ProofVerifier` adapter belongs in `veil-node` when that crate is introduced; concrete backend verification methods already provide the required size-first verify/decode behavior.
- persistent root lookup, nullifier freshness against stored state, transaction admission, and atomic mutation remain slice 2.

## Limitations

- no generated `edc-context/` routing index was available; repository architecture/protocol docs and adjacent modules were used.
- full local suite and real-backend evidence passed; clean GitHub-runner evidence remains pending.
- node, persistence, and concurrency behavior cannot be reviewed before their slices exist.
