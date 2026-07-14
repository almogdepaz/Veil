# Security Review Report

## What Changed

- Target: `main..network/01-canonical-root` working-tree diff
- Baseline: `10c99bd6371c4335fadd08a2ed36fbba5d954875`
- Files reviewed: 30 tracked/new implementation, test, workflow, plan, and documentation files
- Security-relevant files: 12
- Context loaded: repository architecture/protocol documentation, current call sites, security-hardening history, and EDC differential-review methodology

## Findings

### No security findings

No exploitable or security-relevant issue survived verification in the reviewed scope.

Checked:

- proof inputs bind every primary/ring membership root to the public network context (`clvm_zk_core/src/network.rs:28`);
- faucet intent cannot consume the legacy genesis-mint path and publicly binds request ID, asset TAIL, amount, and output commitment (`clvm_zk_core/src/network.rs:42`);
- network CREATE_COIN outputs cannot use transparent two-argument conditions (`backends/sp1/program/src/main.rs:159`, `backends/risc0/guest/src/main.rs:174`);
- network journals use strict Borsh decoding, including trailing-byte rejection (`crates/veil-ledger/src/lib.rs:117`);
- concrete SP1/RISC Zero verification rejects oversized proof bytes before deserialization (`backends/sp1/src/lib.rs:190`, `backends/risc0/src/lib.rs:184`);
- verifier identity checks happen before the injected verifier boundary (`crates/veil-ledger/src/lib.rs:90`);
- canonical root, root-window, expiry, lifetime, network, and version checks fail closed (`crates/veil-ledger/src/lib.rs:204`);
- transition limits run before duplicate scans; zero/empty/duplicate nullifiers and outputs are rejected (`crates/veil-ledger/src/lib.rs:121`, `crates/veil-ledger/src/lib.rs:140`);
- encrypted-note count and domain-separated metadata hash bind transport notes to proof outputs (`crates/veil-ledger/src/lib.rs:140`, `crates/veil-ledger/src/lib.rs:252`);
- no state mutation, filesystem, subprocess, SQL, network, key, or authorization path was introduced.

## Security Test Confidence

- red/green regressions cover root mismatch, ring-root mismatch, intent/mode mismatch, unsupported faucet genesis, explicit faucet asset identity, canonical Borsh encoding, strict trailing-byte rejection, wrong/unknown/expired roots, excessive lifetime, metadata mutation, note-count mismatch, zero/duplicate values, transition limits, proof-size limits, and backend/program identity.
- real SP1 and RISC Zero tests generate and verify both faucet and private-transfer proofs, then compare the decoded typed journals.
- mock tests exercise the same shared request/output builders; ledger tests use the real validation code rather than reimplementing it.

## Blast Radius

- changed entrypoints: mock/SP1/RISC Zero `prove_network_with_input`, SP1/RISC Zero `verify_network_proof_and_decode`, core network request/output helpers, and the new storage-independent `veil-ledger` verifier/root policy.
- legacy proving methods reject network-mode input and retain legacy journal behavior.
- no public node or RPC reaches these interfaces yet; slice 2 will supply canonical storage and transaction admission.

## Historical Context

- reviewed security-hardening commits `a939127`, `712addb`, and `6f2d1fc` for mode exclusivity, arithmetic, asset-bound nullifiers, and mint behavior.
- no removed protection or reverted security fix was found.
- the review identified and corrected two pre-report candidates: unbounded concrete proof deserialization, duplicate scanning before configured count limits, and an untyped canonical-root hash that did not bind its lookup height.

## Limitations

- no node, RPC, persistent root history, nullifier database, or concurrent state mutation exists yet, so those future attack paths are outside this diff.
- SP1 and RISC Zero cryptographic implementations are treated as external trusted dependencies; this review verifies Veil's invocation and decode order, not zkVM internals.
- callers must enforce raw transaction/note byte limits before constructing `Vec<Vec<u8>>`; note-byte allocation limits belong to the slice-2 transaction decoder.
- guest program IDs recorded in this slice are evidence identifiers, not frozen alpha-genesis configuration.

## Recommendation

APPROVE
