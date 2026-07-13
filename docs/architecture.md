# Veil architecture

status: current proof-engine architecture plus the **proposed, unimplemented** alpha network topology

## current repository

Veil currently provides a proof engine and local simulator:

```text
host CLI / simulator
        │ private Input
        ▼
SP1, RISC Zero, or mock backend
        │
        ▼
clvm_zk_core
  ├─ Chialisp compilation
  ├─ CLVM evaluation
  ├─ commitment/nullifier checks
  └─ Merkle membership verification
        │
        ▼
legacy ProofOutput or NetworkProofOutputV1 + proof bytes
```

module ownership:

- `clvm_zk_core/` — no_std compiler/evaluator integration, protocol types, commitments, and Merkle verification;
- `backends/sp1/` — SP1 host adapter and guest programs;
- `backends/risc0/` — RISC Zero host adapter and guest programs;
- `backends/mock/` — non-cryptographic test backend;
- `crates/veil-ledger/` — storage-independent proof-verifier boundary and canonical-root/freshness policy;
- `src/simulator.rs` — local in-memory/file-backed ledger simulation;
- `src/wallet/` and `src/protocol/` — experimental wallet, spend, CAT, offer, and settlement logic.

network-mode guests and the pure canonical-root validation contract now exist. there is still no persistent canonical state machine, node, RPC service, peer-to-peer network, or Chia integration.

## architecture invariants

- core has no backend-specific imports;
- backends depend on core, never the reverse;
- all CLVM execution goes through the shared evaluator path;
- guest compilation and consensus serialization are deterministic;
- backend-specific optimizations are injected rather than hardcoded into core;
- Borsh is the consensus/proof encoding;
- mock proofs are never accepted by a release node.

## selected alpha topology

```text
wallet/client
  ├─ scans public encrypted notes
  ├─ requests a current Merkle witness
  ├─ proves locally with SP1
  └─ submits proof + encrypted output notes
                 │
                 ▼
       single sequencer node
  ├─ verifies proof and journal
  ├─ checks canonical root/expiry
  ├─ checks nullifier freshness
  ├─ applies one atomic state transition
  └─ signs and publishes complete block data
                 │
          ┌──────┴──────┐
          ▼             ▼
   verifier replica A  verifier replica B
          └──────┬──────┘
                 ▼
       Chia testnet checkpoint
```

this topology is selected because it exercises the missing validator/state/network contracts without inventing consensus before deterministic replay works.

## component boundaries

### `clvm_zk_core`

owns guest-compatible consensus primitives and typed public proof output. it must remain no_std and network/storage agnostic.

### `veil-ledger` (partially implemented)

currently owns the backend-neutral `ProofVerifier` boundary, strict journal decode, metadata hash, and canonical root/freshness policy. slice 2 adds transaction/block types, deterministic state deltas, and the one O(depth) Merkle append/witness algorithm. it has no HTTP or SP1 implementation dependency.

### `veil-node` (proposed)

owns SQLite persistence, migrations, HTTP RPC, sequencing, follower synchronization, resource limits, metrics, and the production SP1 verifier adapter.

### wallet/network client (proposed)

owns keys, encrypted local wallet state, note scanning, witness retrieval, local proof generation, submission, retry, and seed recovery. wallet secrets and proof private inputs never go to the node.

### checkpoint publisher/watcher (proposed)

publishes signed Veil state checkpoints through a Chia testnet singleton and independently verifies singleton lineage plus downloaded Veil history.

## trust boundaries

### zkVM boundary

SP1 proves guest execution and membership against the root committed in the public journal. the proof does not decide whether that root belongs to the canonical ledger.

### validator boundary

validators compare the proof-committed `(anchor_height, ledger_root)` with retained canonical roots, enforce nullifier uniqueness and limits, then apply state atomically.

### sequencer boundary

alpha users trust one sequencer for ordering and liveness. signed complete blocks allow replicas to detect invalid transitions or equivocation; replicas do not provide consensus finality.

### Chia boundary

Chia checkpoints externally timestamp/authenticate published Veil history. Chia does not execute Veil state transitions or verify SP1/RISC Zero proofs.

### faucet boundary

faucet authority controls test issuance quota. a mint proof independently binds the authorized public amount to its hidden commitment. the faucet asset has no real-world backing.

## persistence and replay

proposed node state uses one SQLite writer transaction per block. blocks, receipts, commitments, nullifiers, Merkle nodes, root history, and metadata commit together. a failed transaction leaves no partial state.

verifier replicas consume complete blocks, reverify proofs, recompute receipts and roots, and halt on the first mismatch. snapshots are operational accelerators, not trusted consensus inputs.

## data availability

complete transaction envelopes, encrypted output notes, proofs, receipts, and block headers remain retrievable through versioned RPC. a wallet restored from seed and genesis must be able to rescan public history. checkpoint health fails if referenced block data is unavailable or corrupt.

## deployment stages

1. green reproducible repository baseline;
2. typed proof journal and canonical-root contract;
3. deterministic persistent ledger;
4. runnable local faucet node;
5. real SP1 private transfers;
6. independent follower replay;
7. wallet restore/scan/spend;
8. Chia testnet checkpoints;
9. canary and public faucet-only alpha.

acceptance evidence is tracked in [`.plans/002-network-implementation-design.md`](../.plans/002-network-implementation-design.md).

## explicit non-goals for alpha

- mainnet or real funds;
- bridged XCH/CAT custody;
- permissionless or BFT consensus;
- CAT/ring/offer/settlement activation;
- remote proving;
- polished browser wallet;
- claims of anonymity, audit completion, or production readiness.
