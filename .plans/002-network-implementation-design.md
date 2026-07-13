# network implementation design

status: slice 0 final acceptance in progress under `.plans/003-slice-0-repository-baseline.md`; PR #25 open, governance active, required and real-backend evidence green on implementation head

references:

- strategic scope and launch gates: `.plans/001-working-network-launch.md`
- current protocol details: `DOCUMENTATION.md`
- current architecture invariants: `CLAUDE.md`
- intended root contract: `AUDIT-CONTEXT-tob.md` input-path analysis

## 1. selected delivery path

build one accepted vertical slice at a time:

| slice | running outcome | user acceptance required |
|---|---|---|
| 0 | trustworthy green repository baseline | yes |
| 1 | proof exposes intended canonical root; validator unit rejects wrong/stale root | yes |
| 2 | deterministic ledger + sqlite survives restart/replay | yes |
| 3 | local node serves status, witness, faucet, blocks | yes |
| 4 | real SP1 private transfer lands through node API | yes |
| 5 | independent follower replays and matches roots | yes |
| 6 | network wallet restores/scans/spends | yes |
| 7 | checkpoint is published and followed on chia testnet | yes |
| 8 | deployed public alpha passes soak gates | yes |

rule: implement only one slice, run its acceptance commands, record fresh evidence in this file, and stop for acceptance. no batch implementation across slices.

## 2. architecture

```text
wallet/client
  ├─ requests current commitment witness
  ├─ builds private spend input using that canonical root
  ├─ generates SP1 proof locally
  └─ submits proof + encrypted output notes
             │
             ▼
veil-node (sequencer)
  ├─ verifies SP1 proof and decodes committed journal
  ├─ checks network/version/kind/root/expiry
  ├─ checks nullifier freshness
  ├─ applies output commitments atomically
  ├─ signs/publishes BlockV1
  └─ exposes all blocks and witnesses
             │
       ┌─────┴─────┐
       ▼           ▼
verifier A      verifier B
  └─ independently verify/replay every block
             │
             ▼
chia checkpoint publisher
  └─ commits signed veil state checkpoints to chia testnet
```

trust statement:

- SP1 proves private execution and membership against the root committed in the journal.
- veil validators determine whether that root is canonical/recent and whether nullifiers are fresh.
- verifier replicas detect sequencer divergence.
- chia checkpoints timestamp/authenticate published veil history; they do not make execution trustless.

## 3. workspace/module layout

### existing modules retained

- `clvm_zk_core/` — no_std guest-compatible execution, proof types, hashes, Merkle verification.
- `backends/sp1/` — alpha prover/verifier and guest artifacts.
- `backends/risc0/` — differential/nightly backend; not accepted by alpha genesis initially.
- `backends/mock/` — test-only protocol execution; never linked into release node.
- root `clvm-zk` crate — existing prover, wallet, simulator, and legacy CLI.

### new crates

```text
crates/
  veil-ledger/
    src/
      lib.rs
      types.rs          # GenesisV1, BlockV1, TransactionV1, ReceiptV1
      hashing.rs        # domain-separated canonical hashes
      validator.rs      # pure validation → StateDelta
      state.rs          # roots, counts, accepted-root policy
      merkle.rs         # one O(depth) append/witness algorithm over a node-reader boundary
      verifier.rs       # ProofVerifier trait + VerifiedProof
      errors.rs         # stable typed validation errors

  veil-node/
    src/
      main.rs
      config.rs
      api.rs
      sequencer.rs
      follower.rs
      store.rs          # SQLite schema/migrations/atomic block commit
      sp1_verifier.rs   # production ProofVerifier adapter
      metrics.rs
```

why separate crates:

- node/network dependencies never enter `clvm_zk_core`;
- ledger validation remains independent of HTTP and SP1 implementation details;
- node cannot accidentally select the mock backend through root-crate default features;
- verifier replicas reuse exactly the sequencer state transition.

no new generic framework or p2p layer is introduced for alpha.

## 4. network proof contract

### 4.1 core types

add to `clvm_zk_core/src/types.rs` or a referenced `network.rs` module:

```rust
pub const NETWORK_PROTOCOL_V1: u16 = 1;

pub enum NetworkProofKindV1 {
    FaucetMint,
    PrivateTransfer,
}

pub struct NetworkContextV1 {
    pub network_id: [u8; 32],
    pub protocol_version: u16,
    pub proof_kind: NetworkProofKindV1,
    pub ledger_root: [u8; 32],
    pub anchor_height: u64,
    pub expiry_height: u64,
    pub metadata_hash: [u8; 32],
}

pub struct NetworkProofOutputV1 {
    pub context: NetworkContextV1,
    pub program_hash: [u8; 32],
    pub transition: NetworkTransitionV1,
    pub public_conditions: Vec<u8>,
    pub execution_cost: u64,
}

pub enum NetworkTransitionV1 {
    FaucetMint {
        request_id: [u8; 32],
        public_amount: u64,
        output_commitment: [u8; 32],
    },
    PrivateTransfer {
        nullifiers: Vec<[u8; 32]>,
        output_commitments: Vec<[u8; 32]>,
    },
}
```

`metadata_hash` binds encrypted output notes carried outside the proof journal. without it, a relay/sequencer could replace notes and make outputs undiscoverable.

### 4.2 guest input

extend `Input` with:

```rust
pub network_context: Option<NetworkContextV1>
```

legacy simulator calls may use `None`. network submission requires `Some`.

network-mode guest checks:

1. `context.protocol_version == NETWORK_PROTOCOL_V1`;
2. proof kind matches the executed `CoinMode`/network transition;
3. `context.anchor_height <= context.expiry_height` for every network proof;
4. primary `SerialCommitmentData.merkle_root == context.ledger_root` for spends;
5. every additional coin root equals `context.ledger_root`;
6. normal commitment, membership, puzzle, balance, TAIL, mint, and nullifier checks run unchanged;
7. faucet mint output commits the public amount, request ID, and resulting coin commitment;
8. transformed spend CREATE_COIN commitments are collected directly into `PrivateTransfer.output_commitments`;
9. guest commits `NetworkProofOutputV1`.

this completes the intended design: for transfers, the blockchain-provided root already used for membership becomes observable to the validator. faucet mint commits the same root context only for freshness/replay policy; it has no input membership claim. neither path reveals a coin or Merkle path.

### 4.3 verifier API

replace network use of:

```rust
verify_proof(...) -> (bool, program_hash, output)
```

with:

```rust
pub trait ProofVerifier {
    fn backend_id(&self) -> BackendIdV1;
    fn program_id(&self) -> [u8; 32];
    fn verify_and_decode(
        &self,
        proof: &[u8],
    ) -> Result<NetworkProofOutputV1, VerificationError>;
}
```

SP1 adapter order:

1. reject proof above configured byte limit before deserialization;
2. deserialize strictly;
3. verify against the genesis-pinned SP1 verifying key/program;
4. decode exactly one `NetworkProofOutputV1` from public values;
5. reject trailing public bytes;
6. return typed output.

RISC Zero implements the same trait for differential tests. mock implements only a test fixture verifier inside `veil-ledger` tests; `veil-node` has no `mock` feature.

### 4.4 root policy

genesis parameters:

```text
accepted_root_window = 32 blocks
max_proof_lifetime = 32 blocks
```

validator accepts every network proof, including faucet mint, only when:

```text
roots[anchor_height].commitment_root == context.ledger_root
current_height <= context.expiry_height
context.expiry_height <= context.anchor_height + max_proof_lifetime
anchor_height is within accepted_root_window
```

append-only commitments mean an older accepted root remains a valid existence statement. nullifier freshness handles concurrent spends.

## 5. canonical ledger protocol

### 5.1 genesis

```rust
pub struct GenesisV1 {
    pub protocol_version: u16,
    pub chain_name: String,
    pub created_at_unix: u64,
    pub tree_depth: u8,                 // 32 for alpha
    pub accepted_root_window: u16,      // 32
    pub max_proof_lifetime: u16,        // 32
    pub max_proof_bytes: u32,
    pub max_note_bytes: u32,
    pub max_outputs_per_tx: u16,
    pub max_nullifiers_per_tx: u16,
    pub sp1_program_id: [u8; 32],
    pub sequencer_public_key: Vec<u8>,
    pub faucet_public_key: Vec<u8>,
    pub faucet_asset_tail_hash: [u8; 32],
}
```

`network_id = SHA256("veil_network_v1" || canonical_borsh(genesis))`. `sp1_program_id` is SHA-256 over the canonical serialized SP1 verifying key plus guest ELF hash; the exact vector is frozen in slice 1.

all release nodes compare configured genesis hash/network ID before opening the database.

### 5.2 transactions

```rust
pub enum TransactionV1 {
    FaucetMint(FaucetMintV1),
    PrivateTransfer(PrivateTransferV1),
}

pub struct FaucetMintV1 {
    pub backend: BackendIdV1,
    pub proof: Vec<u8>,
    pub encrypted_note: Vec<u8>,
    pub authority_signature: Vec<u8>,
}

pub struct PrivateTransferV1 {
    pub backend: BackendIdV1,           // SP1 only in alpha genesis
    pub proof: Vec<u8>,
    pub encrypted_notes: Vec<Vec<u8>>,
}
```

faucet flow:

1. recipient wallet fetches a current root/height/expiry, then creates coin secrets, commitment, and encrypted note for the genesis-pinned faucet test asset;
2. wallet generates a typed `FaucetMint` proof showing that `output_commitment` binds `public_amount` and the configured faucet asset TAIL; the proof also commits the fetched root context for normal freshness validation;
3. faucet endpoint verifies the proof and enforces quota;
4. faucet signs domain-separated `(network_id, request_id, public_amount, output_commitment, metadata_hash)` extracted from the verified journal;
5. every follower independently verifies the proof, authority signature, metadata hash, TAIL identity, and uniqueness of `request_id`;
6. state appends the commitment and increments public `faucet_issued` by the proof-committed amount.

an authority signature without the mint proof is insufficient: it would not prove that the hidden commitment preimage uses the authorized amount.

private transfer flow:

1. verify/decode proof and require `NetworkTransitionV1::PrivateTransfer`;
2. verify `metadata_hash == hash(canonical encrypted_notes)`;
3. validate root policy;
4. reject empty, zero, duplicate, or previously seen nullifiers;
5. require exactly one encrypted note per output commitment, in the same order;
6. enforce configured nullifier/output/note limits;
7. append nullifiers and output commitments.

### 5.3 blocks

```rust
pub struct BlockHeaderV1 {
    pub network_id: [u8; 32],
    pub protocol_version: u16,
    pub height: u64,
    pub parent_hash: [u8; 32],
    pub previous_state_root: [u8; 32],
    pub new_state_root: [u8; 32],
    pub transaction_root: [u8; 32],
    pub timestamp_unix_ms: u64,
}

pub struct BlockV1 {
    pub header: BlockHeaderV1,
    pub transactions: Vec<TransactionV1>,
    pub receipts: Vec<ReceiptV1>,
    pub sequencer_signature: Vec<u8>,
}
```

alpha produces one transaction per block. this removes mempool ordering/batch atomicity from the first network while preserving a block format that can later batch.

block hash and signature use canonical Borsh bytes and explicit domain separators. alpha authority signatures use secp256k1 ECDSA through `k256`: compressed 33-byte SEC1 public keys, fixed 64-byte low-S signatures, SHA-256 prehash, and deterministic RFC6979 signing. followers check parent, height, old root, transaction/receipt roots, new root, and sequencer signature.

### 5.4 state

```rust
pub struct LedgerStateV1 {
    pub height: u64,
    pub commitment_root: [u8; 32],
    pub nullifier_log_root: [u8; 32],
    pub commitment_count: u64,
    pub nullifier_count: u64,
    pub faucet_issued: u128,
    pub protocol_parameters_hash: [u8; 32],
}
```

```text
state_root = SHA256(
  "veil_state_v1" || network_id || canonical_borsh(LedgerStateV1)
)
```

nullifiers are stored both:

- in a unique indexed table for O(1)/indexed freshness checks;
- in an append-only Merkle log for deterministic checkpoint root.

### 5.5 Merkle implementation

DO NOT use the current simulator `SparseMerkleTree` as validator storage. it keeps all leaves and recomputes the full depth tree on every insert, which is unsuitable for a network.

implement the consensus Merkle algorithm once in `veil-ledger`:

```rust
pub trait MerkleNodeReader {
    fn node(&self, tree: TreeId, level: u8, index: u64)
        -> Result<Option<[u8; 32]>, LedgerError>;
}

pub struct MerkleAppendPlan {
    pub leaf_index: u64,
    pub updates: Vec<MerkleNodeUpdate>,
    pub new_root: [u8; 32],
}

pub fn plan_append(
    reader: &impl MerkleNodeReader,
    tree: TreeId,
    depth: u8,
    leaf_count: u64,
    leaf: [u8; 32],
) -> Result<MerkleAppendPlan, LedgerError>;

pub fn witness(
    reader: &impl MerkleNodeReader,
    tree: TreeId,
    depth: u8,
    leaf_index: u64,
) -> Result<Vec<[u8; 32]>, LedgerError>;
```

- fixed depth 32 for alpha;
- insertion plans one leaf plus 32 ancestors: O(depth);
- witness reads one sibling per level: O(depth);
- empty hashes and left/right ordering exactly match the existing Veil Merkle verifier;
- commitments and nullifier logs use separate `TreeId` values;
- `SqliteStore` implements `MerkleNodeReader` for both normal connections and SQL transactions;
- SQLite applies `MerkleAppendPlan.updates` in the same transaction as block persistence;
- in-memory tests implement the reader with a map but call the same planning functions.

before implementation, add compatibility vectors proving planned roots/paths equal `clvm_zk_core::SparseMerkleTree` for small fixed leaf sets.

## 6. validation and atomicity

### 6.1 validation pipeline

```text
raw request limits
→ decode TransactionV1
→ transaction hash/dedup
→ backend allowlist
→ cryptographic proof verification
→ decode committed journal
→ network/version/kind checks
→ metadata hash check
→ accepted root + expiry check
→ nullifier duplicate/freshness checks
→ output limits/uniqueness checks
→ produce StateDelta
→ build receipt/new roots
→ sign block
→ one SQLite transaction commits block + tx + state delta + roots
```

no state mutation occurs during proof verification or semantic validation.

### 6.2 state delta

```rust
pub struct StateDeltaV1 {
    pub transaction_hash: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub commitments: Vec<[u8; 32]>,
    pub faucet_issue: u64,
    pub faucet_request_id: Option<[u8; 32]>,
}
```

`validate_transaction` returns a delta without mutation. the sequencer uses ledger `plan_append` calls against the current store to compute the proposed roots/block. `SqliteStore::commit_block` opens one SQL transaction, rechecks tip/root and uniqueness constraints, recomputes or verifies the append plans against that transactional snapshot, applies node updates, writes block/receipt/root history, and commits. any failure rolls back everything. the single writer queue prevents a competing tip update between planning and commit.

### 6.3 stable errors

```rust
pub enum ValidationError {
    WrongNetwork,
    UnsupportedVersion,
    UnsupportedBackend,
    WrongProgram,
    InvalidProof,
    ProofTooLarge,
    WrongProofKind,
    UnknownAnchorHeight,
    LedgerRootMismatch,
    ExpiredProof,
    LifetimeTooLong,
    DuplicateNullifier,
    DuplicateOutput,
    MetadataMismatch,
    LimitExceeded,
    InvalidFaucetAuthority,
    DuplicateFaucetRequest,
    InternalStateMismatch,
}
```

HTTP maps these typed variants to stable machine codes. no regex/error-string protocol.

## 7. SQLite storage

use `rusqlite` with bundled SQLite for the first node. one writer fits the single-sequencer architecture and gives mature atomic transactions without a separate service.

schema v1:

```sql
metadata(key TEXT PRIMARY KEY, value BLOB NOT NULL)
blocks(height INTEGER PRIMARY KEY, hash BLOB UNIQUE NOT NULL, bytes BLOB NOT NULL)
transactions(hash BLOB PRIMARY KEY, block_height INTEGER NOT NULL, tx_index INTEGER NOT NULL, bytes BLOB NOT NULL)
receipts(tx_hash BLOB PRIMARY KEY, bytes BLOB NOT NULL)
commitments(leaf_index INTEGER PRIMARY KEY, commitment BLOB UNIQUE NOT NULL, created_height INTEGER NOT NULL)
nullifiers(leaf_index INTEGER PRIMARY KEY, nullifier BLOB UNIQUE NOT NULL, spent_height INTEGER NOT NULL)
merkle_nodes(tree_id INTEGER, level INTEGER, node_index INTEGER, hash BLOB NOT NULL,
             PRIMARY KEY(tree_id, level, node_index))
root_history(height INTEGER PRIMARY KEY, commitment_root BLOB NOT NULL,
             nullifier_root BLOB NOT NULL, state_root BLOB NOT NULL)
faucet_requests(request_id BLOB PRIMARY KEY, created_height INTEGER NOT NULL)
```

startup checks:

1. schema version supported;
2. stored genesis hash equals configured genesis;
3. tip block hash/height matches metadata;
4. tip roots match `root_history` and Merkle root nodes;
5. optional `--verify-on-startup` replays all blocks into a temporary DB and compares tip.

snapshots are SQLite online backups plus genesis and tip hash. restore always runs integrity check before readiness.

## 8. HTTP API v1

JSON control plane; binary fields are lowercase hex. canonical consensus encoding remains Borsh, never JSON.

```text
GET  /v1/status
GET  /v1/genesis
GET  /v1/roots/current
GET  /v1/blocks/{height}
GET  /v1/blocks?from={height}&limit={n}
GET  /v1/transactions/{hash}
GET  /v1/commitments/{commitment}/witness
POST /v1/faucet             # submit typed mint proof; sequencer adds authority signature
POST /v1/transactions
GET  /health/live
GET  /health/ready
GET  /metrics
```

witness response is generated from one SQLite read transaction and contains:

```text
anchor_height, ledger_root, leaf_index, merkle_path, expiry_height
```

submission response:

```text
transaction_hash, block_height, block_hash, receipt_status, new_state_root
```

initially submission waits for its one-transaction block. asynchronous mempool semantics come later only if measured throughput requires them.

limits are read from genesis/node config and checked before allocation/deserialization where possible.

## 9. sequencer and follower

### sequencer

- one process owns SQLite write lock and block signing key;
- serializes submissions through a bounded channel;
- verifies at most configured `max_parallel_verifications` with a semaphore;
- commits blocks in channel order, one tx each;
- returns readiness false if database, verifier, or signing key is unavailable.

### follower

- configured with genesis and sequencer URL;
- polls `/v1/blocks?from=next_height`;
- verifies sequencer signature and every proof independently;
- applies blocks to its own SQLite database using the same ledger code;
- halts on first mismatch and emits `veil_state_divergence` alert;
- never imports sequencer snapshots as trusted state; snapshot bootstrap must replay from its recorded checkpoint.

CLI modes:

```text
veil-node sequencer --config ...
veil-node follower --config ...
veil-node verify-chain --db ... --genesis ...
veil-node export-snapshot ...
veil-node import-snapshot ...
```

## 10. wallet/network client

add network commands without mixing them into simulator state:

```text
clvm-zk network wallet create
clvm-zk network address
clvm-zk network faucet --amount ...
clvm-zk network sync
clvm-zk network balance
clvm-zk network send --to ... --amount ...
clvm-zk network status
```

flow for send:

1. sync public blocks/notes from last scanned height;
2. decrypt notes and reconstruct owned coins/secrets;
3. select inputs locally;
4. request current witnesses for selected commitments;
5. create encrypted notes for recipient/change;
6. hash canonical note list into `NetworkContextV1.metadata_hash`;
7. set root/anchor/expiry from witness response;
8. generate SP1 proof locally;
9. submit and wait for receipt;
10. mark inputs pending, then spent only after included block is independently checked.

wallet persistence:

- seed encrypted at rest with password-derived key;
- network ID stored and checked;
- scanned height/block hash checkpointed;
- pending transaction data sufficient to retry/re-prove;
- restore from seed + genesis + block data recovers all spendable notes.

remote proving is excluded from alpha implementation until a separate privacy design exists.

## 11. chia checkpoint design

checkpoint only after slices 0–6 are accepted.

payload:

```rust
pub struct CheckpointV1 {
    pub network_id: [u8; 32],
    pub veil_height: u64,
    pub veil_block_hash: [u8; 32],
    pub veil_state_root: [u8; 32],
    pub data_hash: [u8; 32],
    pub previous_checkpoint_coin_id: [u8; 32],
}
```

- Chialisp singleton is controlled by the configured checkpoint authority key;
- solution reveals the next checkpoint payload and signature;
- publisher waits configured Chia confirmations before marking checkpoint final;
- shallow Chia reorg returns checkpoint to pending and retries from the surviving singleton coin;
- independent watcher starts from launcher ID, follows singleton lineage, downloads Veil blocks, replays, and compares state root;
- checkpoint cadence starts at every 100 Veil blocks or 10 minutes, whichever comes first;
- no custody/deposit/withdrawal puzzle is included.

## 12. observability and operations

minimum metrics:

```text
veil_tip_height
veil_commitment_count
veil_nullifier_count
veil_state_root_info
veil_submission_total{result,code}
veil_proof_verify_seconds
veil_block_commit_seconds
veil_follower_height
veil_follower_lag_blocks
veil_state_divergence
veil_checkpoint_height
veil_checkpoint_age_seconds
```

structured logs include request ID, tx hash, block height, error code, and duration—never wallet secrets, proof private inputs, decrypted notes, seeds, or raw auth headers.

required runbooks:

- sequencer restart;
- follower divergence;
- SQLite corruption/restore;
- signing-key rotation;
- emergency submission halt while preserving read APIs;
- SP1 program upgrade;
- Chia RPC outage/reorg;
- public incident communication.

## 13. exact slices and acceptance

### slice 0 — repository baseline

files/surfaces:

- `.github/workflows/ci.yml`
- pinned toolchain/config manifests
- `README.md`, `DOCUMENTATION.md`, new network protocol/architecture docs
- github PR/branch settings

steps:

1. fix existing formatting failure without unrelated cleanup;
2. add required mock check/test jobs; network serialization golden tests begin in slice 1 when the versioned types exist;
3. add scheduled/manual SP1 and RISC Zero real-proof jobs with artifact caching and timeouts;
4. make workflow run on every PR, not only PRs targeting `main`;
5. pin git dependency revisions and zkVM toolchains;
6. reconcile stale PRs and enable branch protection after checks are green;
7. document intended root flow accurately.

acceptance commands/evidence:

```bash
cargo fmt --all -- --check
cargo clippy-mock -- -D warnings
cargo test-mock
cargo check-sp1
cargo check-risc0
```

plus:

- github required checks visible and green;
- clean-clone build records pinned revisions;
- docs explicitly distinguish guest membership verification from block validator root acceptance.

status evidence: implementation through docs/governance preparation complete on `network/00-baseline`; local required command set passes; stale PRs reconciled; PR push, GitHub checks/rules, and final acceptance pending. exact evidence is in `.plans/003-slice-0-repository-baseline.md`.

### slice 1 — canonical-root proof contract

production files:

- `clvm_zk_core/src/types.rs` / `network.rs`
- shared guest execution path
- SP1/RISC Zero/mock output construction
- backend verifier interfaces

red tests first:

1. network spend output contains exactly the root used for guest membership verification;
2. faucet mint journal binds request ID, public amount, configured test-asset TAIL, commitment, metadata hash, and current root context;
3. mismatching `network_context.ledger_root` and private spend root fails proving;
4. ring input with a different root fails proving;
5. validator accepts proof at exact known `(height, root)`;
6. validator rejects cryptographically valid proof whose committed root is unknown;
7. validator rejects expired root/proof;
8. changing notes after proving causes metadata mismatch;
9. changing envelope proof kind does not change committed kind.

acceptance commands/evidence:

```bash
cargo test-mock --test network_root_contract
cargo test-mock
cargo test-sp1 --test network_root_contract
cargo test-risc0 --test network_root_contract
cargo fmt --all -- --check
git diff --check
```

manual evidence: decode one real SP1 proof and print only network ID, kind, root/height/expiry, nullifier count, and output count.

status evidence: not run.

### slice 2 — ledger + persistent state

production files:

- `crates/veil-ledger/`
- `crates/veil-node/src/store.rs` migration harness only

red tests first:

- persistent tree roots/paths equal core tree vectors;
- duplicate commitment/nullifier rejected;
- unknown/stale root rejected;
- failed block leaves DB byte-equivalent at logical state level;
- restart produces same tip/root;
- replay from genesis produces same DB state root;
- schema/genesis mismatch refuses startup.

acceptance commands/evidence:

```bash
cargo test -p veil-ledger
cargo test -p veil-node store
cargo test-mock
cargo fmt --all -- --check
```

manual demo:

```bash
veil-node verify-chain --db ./tmp/ledger.db --genesis ./config/devnet-genesis.json
```

expected: reports height, block hash, commitment root, nullifier root, and state root; second run is identical.

status evidence: not run.

### slice 3 — runnable local faucet node

production files:

- remaining `veil-node` config/API/sequencer modules
- devnet genesis and local configuration

red tests first:

- faucet proof binds public amount, commitment, request ID, and configured asset TAIL;
- faucet authority and request replay;
- HTTP limits/malformed hex/oversized body;
- one transaction creates exactly one signed block;
- restart preserves API-visible status;
- witness matches returned root;
- block signature and hash vectors.

acceptance commands/evidence:

```bash
cargo test -p veil-node
cargo run -p veil-node -- sequencer --config config/devnet.toml
```

manual acceptance from another shell:

```bash
curl -s localhost:PORT/v1/status
curl -s -X POST localhost:PORT/v1/faucet -d @fixtures/faucet-mint-proof.json
curl -s localhost:PORT/v1/blocks/1
# restart node
curl -s localhost:PORT/v1/status
```

expected: height remains 1, block verifies, commitment witness verifies against returned root.

status evidence: not run.

### slice 4 — real SP1 private transfer

red tests first:

- valid real proof accepted;
- invalid/tampered/wrong-program/oversized proof rejected;
- duplicate nullifier rejected after first inclusion;
- fabricated-tree proof is cryptographically valid but validator rejects its unrecognized committed root;
- output note replacement rejected;
- stale accepted root works inside window and fails outside it.

acceptance commands/evidence:

```bash
cargo test -p veil-node --features sp1
cargo test-sp1 --test network_transfer_e2e
cargo test-mock
```

manual demo:

```text
start node
create alice and bob wallets
faucet alice
alice syncs and gets witness
alice proves/sends to bob with SP1
bob syncs/decrypts note
bob proves/spends received output
attempt alice double-spend → DuplicateNullifier
```

record proof generation time, verification time, peak memory, proof size, and resulting block/state roots.

status evidence: not run.

### slice 5 — independent follower

red tests first:

- follower reaches sequencer tip;
- tampered block signature rejected;
- tampered proof/receipt/root rejected;
- missing parent halts sync;
- follower restart resumes exact next height;
- sequencer/follower roots match across 100 mixed faucet/transfer blocks.

acceptance:

```bash
cargo test -p veil-node follower
# run sequencer + two follower processes with separate DBs
veil-node verify-chain ... # against all three DBs
```

expected: identical height, tip hash, and state root on all three. intentionally corrupt one fetched block; follower halts before applying it.

status evidence: not run.

### slice 6 — network wallet recovery

red tests first:

- scan discovers only owned notes;
- scan checkpoint detects/reconciles reorged local cache;
- seed restore rediscovers all outputs;
- pending transaction survives process restart;
- expired-root submission re-fetches witness and re-proves;
- wrong network ID rejected.

acceptance:

```bash
cargo test -p clvm-zk network_wallet
./scripts/network-demo.sh --backend sp1
```

expected demo performs faucet → alice-to-bob → bob scan → bob spend → fresh wallet restore, with balances and block links matching.

status evidence: not run.

### slice 7 — chia testnet checkpoint

red/integration tests first:

- checkpoint puzzle rejects wrong authority/previous coin/payload;
- publisher retries RPC failure without creating conflicting state;
- watcher follows launcher lineage;
- simulated shallow reorg returns pending then reconfirms;
- downloaded Veil history reproduces checkpoint root.

acceptance:

- publish checkpoint on selected Chia testnet;
- record launcher ID, singleton coin ID, Chia height, Veil height/root, and transaction ID;
- independent watcher from an empty DB reaches and verifies it.

status evidence: not run.

### slice 8 — public alpha

acceptance gates are inherited from `.plans/001-working-network-launch.md`:

- two independent followers;
- 14-day canary;
- at least 1,000 real-proof transactions;
- no root divergence;
- backup/restore and checkpoint rebuild drills;
- no open critical/high findings;
- public trust/limitations documentation.

status evidence: not run.

## 14. decisions intentionally deferred

- BFT/federated consensus implementation;
- fees and economic spam pricing beyond faucet/API rate limits;
- CATs, ring spends, offers, settlement, aggregation;
- bridged Chia assets and custody;
- remote proving;
- browser wallet/explorer beyond minimal status views;
- mainnet.

these are not allowed to leak into alpha slices as speculative abstractions.

## 15. first authorization boundary

when the user says `start` or `implement`, begin **slice 0 only**:

1. preserve the current uncommitted README/plan edits, then create `network/00-baseline` from local `main` using the repository-required main-branch workflow (`git fetch origin main:main && git checkout -b network/00-baseline main`);
2. add failing/verification checks before production changes where behavior changes;
3. perform slice 0;
4. run all slice 0 acceptance commands;
5. update this file's `status evidence` with exact command results;
6. stop and request acceptance before slice 1.
