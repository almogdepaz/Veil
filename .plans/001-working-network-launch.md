# working network launch plan

status: revised — architecture A + alpha selected; implementation design in `.plans/002-network-implementation-design.md`; implementation not started

## 1. target and recommendation

### recommended target

launch veil as a **public testnet rollup/coordinator**, staged through a single-sequencer devnet:

1. veil validators maintain the private-coin commitment tree, nullifier state, and deterministic block history.
2. clients generate SP1 proofs locally; remote proving is excluded from alpha.
3. independent verifier replicas replay every block and expose state/checkpoint APIs.
4. veil periodically anchors signed state checkpoints to a singleton puzzle on chia testnet.
5. the first public network uses a faucet-only test asset. bridged testnet XCH, CATs, and offers are later gated upgrades.

chia anchoring initially provides ordering evidence and data commitment, **not trustless execution**. until chia can verify veil proofs or enforce a fraud/validity mechanism, users trust the veil validator set for checkpoint correctness and bridge custody.

### rejected first-launch targets

- **direct chia deployment:** chia consensus does not verify SP1/RISC Zero proofs, track veil nullifiers, or own veil's commitment tree.
- **new p2p appchain:** unnecessary consensus/networking scope before the state machine is sound.
- **mainnet funds:** the protocol is unaudited as a network, ci is red, and core validator contracts do not exist.
- **all features at genesis:** CAT minting, ring spends, stealth settlement, and offers materially expand the launch attack surface.

### selected architecture

**A + alpha:** single sequencer, independent verifier replicas, faucet-only private asset, public block data, and chia testnet checkpoints. federation and bridged assets remain post-alpha upgrades.

this selection does not authorize implementation. planning and execution remain separate.

---

## 2. review calibration

### real goal

users can create a wallet, receive faucet test assets, generate a real zero-knowledge spend, submit it to a persistent public endpoint, observe deterministic finality, restart/resync clients, and independently verify that published state matches chia-anchored checkpoints.

### done evidence

- a clean node can sync genesis → tip and derive the same state root as two independent verifier replicas;
- only cryptographically valid, correctly typed proofs against an accepted canonical root change state;
- duplicate nullifiers, stale roots, cross-network replays, malformed outputs, and tampered envelopes are rejected;
- a wallet can complete faucet → private transfer → scan → spend using real SP1 proofs;
- checkpoint data and complete block data are publicly retrievable and reproducible;
- the service survives restart, restore, and rollback drills without state divergence;
- public testnet runs for 14 consecutive days and processes at least 1,000 real-proof transactions with no consensus/state divergence.

### not the first-launch goal

- permissionless validator consensus;
- production/mainnet funds;
- trustless XCH bridging;
- CAT issuance, ring spends, recursive aggregation, or offers;
- both zkVM backends in production simultaneously;
- polished consumer wallet UX.

### non-obvious invariants

- validators must derive nullifiers and outputs from the **verified proof journal**, never duplicated envelope fields;
- every network proof must publicly bind `network_id`, `protocol_version`, `proof_kind`, the relevant ledger root/height/expiry, and output-note metadata hash;
- state transition validation completes before one atomic database commit;
- mock proofs can never be accepted by a network build;
- backend image/verifying-key identity is consensus-critical and versioned;
- core remains backend-agnostic; backend adapters depend on core, never vice versa;
- commitment/nullifier formulas and serialization are protocol versions, not implementation details.

---

## 3. evidence-based readiness review

**delivery verdict:** not delivered — the repository has a proof engine and local simulator, not a runnable network.

**architecture fit:** the backend-agnostic execution core is a useful base; network validation, canonical state, persistence, data availability, and chia integration are absent.

### useful assets already present

- Chialisp compilation and execution in `clvm_zk_core/`;
- SP1, RISC Zero, and mock backends;
- commitment, nullifier v2, Merkle, mint, ring, and settlement research code;
- local wallet/stealth primitives and simulator workflows;
- mock lifecycle/regression tests;
- prior differential reviews and architecture context.

### launch blockers found

#### protocol and validator blockers

1. **the intended canonical-root validator contract is incomplete.** The documented design correctly requires the blockchain to supply the current Merkle root and the validator to reject stale/noncanonical roots (`AUDIT-CONTEXT-tob.md`, input-path analysis). Guest membership verification already exists. What is missing is the network boundary: spend guests currently receive the root privately and commit `public_values: vec![]`, so a future validator cannot yet extract the root from the verified journal and compare it with block state. This is implementation/spec completion, not a change to the commitment or nullifier design.
2. **transaction kind is not reliably proof-bound.** `PrivateSpendBundle.proof_type` is host metadata. conditional/transaction semantics use the same main guest, and the validator contract is undefined.
3. **the transaction envelope duplicates proof-derived fields.** `PrivateSpendBundle` carries nullifiers and conditions copied by the host. the current verifier API returns only program hash/output and discards typed public output.
4. **no canonical validator exists.** comments assign proof verification, nullifier uniqueness, root acceptance, settlement linkage, and atomic mutation to an unimplemented external actor.
5. **no chain replay domain.** proofs and protocol hashes do not bind a network/chain identifier or expiry.
6. **no authenticated global state root.** commitment root exists; the public nullifier set is a `HashSet` with no committed root. there is no composite checkpoint root.
7. **settlement contract is incomplete.** `SettlementProof::to_spend_bundle` retains only the maker nullifier; real settlement tests are absent; signature-gated CAT TAIL checks are stubbed in settlement guests.
8. **output parsing is not consensus-grade.** malformed/unsupported CREATE_COIN forms can be ignored or normalized differently across helper paths.

#### test and proof blockers

1. github ci on `main` is red (`cargo fmt --check`).
2. ci runs only mock tests; the mock verifier accepts any decodable `ProofOutput` as valid.
3. `tests/test_e2e_settlement.rs` fabricates settlement output and tests simulator mutation, not settlement proving or verification.
4. `tests/test_settlement_recursive.rs` skips the settlement proof under mock while printing success for the partial path.
5. no continuous fixture proves mock/SP1/RISC Zero produce identical public outputs for the same protocol input.
6. no real-backend launch benchmark establishes proof time, verification latency, memory, proof size, or maximum safe transaction limits.

#### state and operations blockers

1. simulator state is pretty-printed JSON written with `fs::write`; it is not transactional validator storage.
2. the simulator `SparseMerkleTree` recomputes from stored leaves on insertion and is unsuitable as persistent network state; the node needs O(depth) incremental tree updates while preserving guest-compatible roots.
3. there is no node binary, RPC, mempool, block format, genesis file, database migration system, or deterministic replay command.
4. there are no Docker images, deployment manifests, metrics, tracing, backups, restore drills, release artifacts, or runbooks.
5. there is no Chia RPC client, singleton/checkpoint puzzle, deposit watcher, withdrawal path, or reorg policy.
6. request/proof/program sizes and proving queues lack network-facing resource limits.

#### product and governance blockers

1. the stealth offer payment output remains documented as unspendable through the standard flow.
2. docs call bundles “directly submittable to blockchain,” which is false today.
3. PRs #21 and #22 remain open although their commits are ancestors of `origin/main`; PR #17 is a stale superseded mega-PR.
4. `main` has no branch protection or required checks, and branches are not deleted after merge.
5. git dependencies track branches/default heads in manifests; release inputs are not explicitly revision-pinned.
6. there are no releases or signed versioned protocol artifacts.

---

## 4. completing the intended block/validator contract

no commitment or nullifier redesign is required for alpha. the existing intended flow remains:

1. wallet obtains a recent canonical commitment root and witness from the ledger;
2. guest verifies private coin membership against that root;
3. proof publicly commits the root used;
4. validator verifies the proof, decodes the committed root, and accepts it only if it is in the ledger's accepted-root window;
5. validator checks nullifier freshness and atomically appends output commitments.

### network proof journal v1

evolve the current `ProofOutput` into an explicitly versioned network journal. do not encode consensus fields through positional `Vec<Vec<u8>>` conventions:

```text
NetworkProofOutputV1 {
  network_id,
  protocol_version,
  proof_kind,
  ledger_root,
  anchor_height,
  expiry_height,
  program_hash,
  transition,        # typed FaucetMint or PrivateTransfer outputs
  metadata_hash,
  public_conditions,
  execution_cost,
}
```

`ledger_root` is the commitment-tree root already verified inside the guest. it becomes public only so the validator can compare it with block state; coin identity, path, amount, secrets, and program source remain private.

requirements:

- every field is committed by the zkVM journal;
- validator decodes it only after verification against the configured guest program/verifying key;
- all inputs in a ring spend use the one declared `ledger_root`;
- envelope metadata is never a second source of truth;
- strict serialization and golden vectors define network protocol v1;
- existing simulator-only serialization need not be wire-compatible because no network has launched.

### canonical ledger state

```text
LedgerStateV1 {
  height,
  commitment_root,
  nullifier_log_root,
  protocol_parameters_hash,
}

state_root = H("veil_state_v1" || network_id || all fields above)
```

- commitment leaves retain the existing append-only design;
- accepted nullifiers remain a set for lookup and are also appended to a deterministic log tree for checkpointing;
- validators retain a bounded accepted commitment-root window to permit concurrent proving;
- proofs expire by height;
- every block publishes previous/new state roots and ordered transaction hashes;
- tree depth and migration rules are genesis parameters, not simulator assumptions.

### alpha transaction classes

only:

- `FaucetMint` — a typed mint proof binds public amount to the hidden output commitment and configured test-asset TAIL; sequencer authority separately enforces faucet admission/quota;
- `PrivateTransfer` — existing private spend proof with committed outputs and nullifiers.

CATs, ring spends, conditional offers, settlement, recursive aggregation, and bridged Chia assets activate only in later protocol upgrades.

### root freshness policy

begin with the last 32 finalized commitment roots as an explicit genesis parameter. measure proving latency and adjust before public alpha. nullifiers prevent double-spends across concurrent proofs; `ledger_root`, `anchor_height`, and `expiry_height` are proof-committed and validator-checked.

---

## 5. implementation milestones

implementation remains blocked until the user explicitly says `start` or `implement`.

### milestone 0 — repository and specification baseline

**goal:** one truthful source of truth and enforceable change control.

work:

1. reconcile/close superseded PRs #17, #21, and #22 after recording why commits already exist on `main`;
2. fix formatting and make `main` ci green;
3. trigger CI for every pull request regardless of stacked base branch;
4. protect `main`: required PR, required green checks, no force push, no direct admin bypass;
5. pin Rust, zkVM toolchains, git dependencies, guest program IDs, and generated artifacts;
6. write `docs/network-protocol-v1.md`, `docs/architecture.md`, threat model, ADR for rollup/checkpoint trust, and compatibility/version policy;
7. correct README/DOCUMENTATION claims about blockchain submission and real settlement status;
8. turn current known findings into tracked issues with owner, severity, and release gate.

acceptance:

- fresh clone has reproducible documented builds;
- protected `main` is green;
- network protocol v1 fields, intended root-validation flow, state transition, trust model, and alpha scope are reviewable without reading implementation;
- no stale PR claims work is pending or unmerged when it is already in `main`.

estimate: 1–2 engineer-weeks.

### milestone 1 — proof/public-input soundness

**goal:** a proof carries every fact a validator needs.

test-first work:

1. add failing tests proving a valid spend journal exposes its ledger root and validator logic rejects a valid proof for a non-accepted root; also cover proof-kind relabeling, duplicated-field tampering, cross-network replay, stale proof replay, and malformed condition parsing;
2. implement typed network-protocol-v1 journals and strict serialization;
3. commit network/version/kind/root/height/expiry from the existing guest membership flow;
4. replace verifier APIs with `verify_and_decode(...) -> VerifiedNetworkProofOutputV1`;
5. remove consensus reliance on `PrivateSpendBundle.nullifiers`, `.public_conditions`, and host-supplied `proof_type`;
6. ensure all input/ring roots follow one declared root policy;
7. centralize shared guest state-transition logic in core so SP1 and RISC Zero cannot drift;
8. add golden vectors and differential fixtures across mock/SP1/RISC Zero execution.

acceptance:

- each adversarial test fails before the fix and passes after it;
- proof verification yields the complete typed journal;
- changing any consensus field invalidates verification or validation;
- SP1 and RISC Zero emit byte-identical protocol outputs for fixed fixtures;
- mock is explicitly tagged non-cryptographic and cannot compile into the node.

estimate: 3–5 engineer-weeks.

### milestone 2 — deterministic validator state machine

**goal:** pure validation and atomic state transitions independent of networking/storage.

test-first work:

1. define `GenesisV1`, `BlockV1`, `TransactionEnvelopeV1`, `ReceiptV1`, and deterministic transaction ordering;
2. implement validation pipeline: size/rate precheck → proof verify → journal decode → chain/version/root/expiry check → nullifier uniqueness → output validation → state transition;
3. build authenticated commitment and nullifier state with composite `state_root`;
4. enforce validate-all-then-commit semantics for single transactions and blocks;
5. define accepted-root history, finality, rollback, and protocol upgrade activation;
6. define deterministic error codes; no parsing of human-readable errors as protocol;
7. add state snapshots and full replay from genesis.

acceptance:

- property tests preserve supply and reject duplicate nullifiers;
- failed transactions leave byte-identical state;
- two implementations/processes replay the same corpus to identical roots;
- crash injection before/during/after commit recovers to old or new state, never partial state;
- one million synthetic state transitions establish tree capacity/memory bounds without proof generation.

estimate: 4–6 engineer-weeks.

### milestone 3 — persistent node and public data availability

**goal:** a restart-safe single-sequencer devnet.

work:

1. create a dedicated `veil-node` binary; do not extend the 3k-line simulator CLI;
2. add an embedded transactional database with versioned column families/tables for blocks, commitments, nullifiers, root history, and metadata;
3. expose versioned RPC:
   - submit transaction;
   - fetch block/transaction/receipt;
   - fetch current and accepted roots;
   - fetch commitment witness/history data;
   - stream blocks/notes;
   - health/readiness/status;
4. implement bounded mempool, proof-size limits, request timeouts, concurrency controls, and deterministic block production;
5. publish complete block data so verifier replicas can replay without trusting sequencer APIs;
6. add `veil verify-chain` and snapshot import/export commands.

acceptance:

- local three-process topology: one sequencer + two read-only verifier replicas;
- replicas independently verify proofs and match every state root;
- restart, corrupted snapshot, stale client, duplicate submission, and network partition tests pass;
- API fuzzing cannot panic the node or allocate unbounded memory.

estimate: 4–6 engineer-weeks.

### milestone 4 — alpha wallet and prover path

**goal:** a user can transact without touching simulator internals.

work:

1. split wallet/prover commands from simulator state;
2. define encrypted wallet storage, seed backup/restore, network configuration, account discovery, and note scanning checkpoints;
3. fetch canonical root/witness, construct proof, submit transaction, and track finality;
4. support local proving first; optional remote prover accepts only encrypted/private jobs under a separately documented trust model;
5. implement deterministic retry and re-prove behavior when anchor roots expire;
6. expose clear proof progress, resource estimates, and structured errors;
7. faucet with per-address/IP quotas and no privileged arbitrary mint endpoint.

acceptance:

- clean-machine faucet → receive → transfer → recipient scan → spend flow with real SP1 proofs;
- seed restore discovers all owned notes from public chain data;
- stale-root recovery re-proves rather than losing or duplicating a spend;
- wallet never sends secrets, source, or inputs to the node API.

estimate: 3–5 engineer-weeks.

### milestone 5 — real proof production gate

**goal:** choose and operationalize one production proof backend.

work:

1. benchmark SP1 and RISC Zero on the alpha transfer circuit: prove latency, verify latency, peak RAM, proof size, cost, and failure modes;
2. choose one alpha backend (expected SP1; decision from data), keeping the other as differential validation/nightly evidence;
3. pin ELF/image IDs and verifying keys in genesis/protocol parameters;
4. create reproducible guest builds and compare artifact hashes in CI;
5. run real-backend tampering tests and full alpha lifecycle tests;
6. add bounded verification workers, caching only by cryptographic proof hash + verifier ID;
7. define key/program upgrade activation with overlap and rollback windows.

acceptance:

- 100 consecutive alpha transfer proofs generate and verify successfully;
- tampered, cross-program, truncated, oversized, and wrong-key proofs are rejected;
- verifier p95 latency and memory fit documented node capacity;
- a clean build reproduces the release program ID/artifact hash.

estimate: 2–4 engineer-weeks, plus proving compute.

### milestone 6 — chia testnet checkpoint anchor

**goal:** make veil history externally timestamped and independently discoverable.

work:

1. define checkpoint payload: chain ID, protocol version, veil height, block hash, state root, data-availability hash, previous checkpoint coin ID;
2. implement a standard Chialisp singleton/checkpoint puzzle on Chia testnet;
3. require sequencer/federation signatures for checkpoint updates; document that this authenticates operators, not veil proof correctness;
4. add Chia full-node RPC adapter, confirmation depth, fee policy, reorg handling, replacement/retry, and checkpoint reconciliation;
5. publish checkpoint payload + block data to durable public storage and expose hashes through node RPC;
6. build an independent watcher that starts from the singleton launcher ID and verifies the checkpoint chain against downloaded veil blocks.

acceptance:

- checkpoints survive Chia node restart and shallow reorg tests;
- independent watcher reconstructs the same veil state root from genesis;
- missing/corrupt data availability halts checkpoint health and pages operators;
- no deposit/withdrawal or real asset custody exists yet.

estimate: 3–5 engineer-weeks.

### milestone 7 — deployment and public alpha

**goal:** operate the network, not merely run it once.

work:

1. produce minimal hardened container images, non-root runtime, read-only filesystem where possible, and signed release artifacts/SBOM;
2. deploy sequencer, two verifier replicas in separate failure domains, public RPC, checkpoint publisher, watcher, metrics, logs, and alerting;
3. publish genesis, chain ID, program IDs, endpoint list, status page, faucet, explorer-lite, and incident contact;
4. implement backups, encrypted key custody, rotation, restore, rollback, and emergency halt procedures;
5. load test valid and invalid traffic; test proof-verification saturation and scanner load;
6. run internal adversarial review, then external protocol/crypto review before any bridged asset;
7. execute staged launch: private canary → invite alpha → public alpha.

public-alpha gate:

- 14 days canary uptime;
- at least 1,000 real-proof transactions;
- zero state-root divergence across replicas;
- successful restore and checkpoint-rebuild drills;
- no open critical/high security findings;
- all medium findings fixed or explicitly accepted with compensating controls;
- published limitations say centralized/federated testnet and faucet-only asset.

estimate: 2–4 engineer-weeks plus 14-day soak.

---

## 6. post-alpha milestones

### 6.1 federated validation

- choose established BFT/consensus machinery rather than inventing consensus;
- validators independently verify proposed blocks before signing;
- checkpoint singleton requires threshold authorization;
- add validator joining/removal, slashing/non-slashing policy, liveness, equivocation evidence, and key rotation;
- target at least 4 operators across 3 organizations before calling the network federated.

### 6.2 CATs and ring spends

- network-protocol-v1 typed journals for each newly activated transaction kind;
- remove unlimited mint from network policy or explicitly register test-only assets;
- support signature-gated TAILs in every relevant guest, including settlement;
- prove supply conservation and TAIL authorization with real-backend differential tests;
- independent security review before activation.

### 6.3 offers and settlement

- redesign/fix stealth payment claim so every output is spendable;
- canonical settlement envelope contains both proofs and all linkage fields;
- validator verifies maker proof, taker proof, maker terms, both nullifiers, all outputs, root freshness, and atomic mutation;
- replace fabricated mock “e2e” evidence with real SP1/RISC Zero settlement lifecycle tests;
- activate only through a versioned protocol upgrade.

### 6.4 bridged Chia testnet assets

- specify custody puzzle, deposit finality, denomination, mint authorization, withdrawal/burn, replay protection, reorg handling, rate limits, and emergency halt;
- reconcile veil supply against locked Chia testnet assets continuously;
- start with capped testnet value and withdrawal delay;
- external bridge audit is mandatory.

### 6.5 mainnet consideration

mainnet is a separate decision after:

- at least 90 days stable public testnet;
- independent protocol, Rust, zkVM, wallet, and bridge audits;
- resolved view/spend-key separation and wallet recovery risks;
- decentralized/federated validator and key custody model;
- economic spam/fee model;
- formal upgrade and incident governance;
- bug bounty and responsible disclosure process;
- explicit legal review for operating privacy infrastructure and asset custody.

---

## 7. proposed pull-request sequence

keep each PR independently reviewable and green:

1. `docs/network-protocol-v1` — architecture decision, intended canonical-root contract, trust model, alpha scope, protocol spec.
2. `ci/release-baseline` — formatting, all-PR CI, pins, branch/release policy.
3. `protocol/shared-guest-logic` — one production state-transition implementation used by both guests, with no behavior change.
4. `protocol/typed-public-output` — network journal v1 + golden vectors.
5. `protocol/root-chain-binding` — canonical root, network/version/kind/expiry/metadata proof binding + regressions.
6. `validator/state-machine` — pure deterministic validation and authenticated state.
7. `validator/persistent-store` — atomic DB, migrations, snapshots, replay.
8. `node/rpc-sequencer` — bounded mempool, blocks, RPC, data publication.
9. `node/verifier-replica` — independent replay and root comparison.
10. `wallet/network-client` — scan/prove/submit/finality/restore.
11. `proof/production-gate` — real proof fixtures, benchmarks, artifact reproducibility.
12. `chia/checkpoint-anchor` — singleton, RPC adapter, watcher, reorg handling.
13. `ops/public-alpha` — containers, observability, runbooks, deployment and soak evidence.

security findings are fixed one at a time with regression evidence; do not batch-rewrite protocol code under an audit-fix label.

---

## 8. estimated path

for one experienced Rust/ZK engineer, sequentially:

- public faucet-only alpha: roughly **22–37 engineer-weeks**, including the 14-day soak but excluding external-audit scheduling;
- federation: another **6–10 engineer-weeks** after alpha architecture selection;
- bridged Chia testnet assets: another **6–10 engineer-weeks plus audit**;
- mainnet: not responsibly estimable until testnet and audits produce evidence.

parallelism can reduce calendar time across protocol, node/ops, and wallet tracks, but milestone 1 (proof soundness) and milestone 2 (state machine) are hard dependencies for everything else.

---

## 9. execution control

architecture A + alpha is selected. exact module/API/PR/test design is maintained in `.plans/002-network-implementation-design.md`.

implementation must proceed one accepted slice at a time:

1. implement only the current slice;
2. run its specified acceptance commands;
3. record evidence in the implementation design;
4. present the result and unresolved concerns;
5. continue only after the user accepts the slice.

no implementation has started. explicit `start` or `implement` authorization is still required.
