# proposed network protocol v1

status: **draft; typed proof journal and storage-independent root policy implemented, but no node or network is active**

this document defines the intended validator boundary for Veil's first faucet-only alpha. current proof and simulator behavior remains documented in [`../DOCUMENTATION.md`](../DOCUMENTATION.md). implementation sequencing and acceptance evidence live in [`.plans/`](../.plans/).

## scope

network protocol v1 is deliberately narrow:

- one centralized sequencer;
- independently replaying verifier replicas;
- one faucet-issued test asset;
- private transfers proven with SP1;
- public block data;
- periodic state checkpoints on Chia testnet.

it does not include bridged XCH/CAT custody, offers, settlement, recursive aggregation, permissionless consensus, fees, or mainnet funds.

## current versus proposed behavior

implemented today:

- guests verify coin commitments and Merkle membership;
- `SerialCommitmentData` carries the expected Merkle root as private zkVM input;
- guests derive public nullifiers and committed outputs;
- the local simulator supplies its current root and rejects repeated nullifiers.

implemented for network-mode proofs:

- `Input.network` carries a typed context plus faucet/private-transfer intent;
- spend guests require every membership root to equal the context root;
- SP1, RISC Zero, and mock commit the typed journal below as strict Borsh bytes;
- `veil-ledger` validates network/version, exact canonical root, root window, expiry, proof lifetime, faucet asset, note count, and note metadata without mutating state.

still missing:

- persistent canonical root/nullifier/commitment state;
- transaction and block formats, node, RPC, sequencing, and follower replay;
- a production adapter wiring the pure `ProofVerifier` boundary to node configuration.

legacy simulator proofs still use `ProofOutput` and do not expose a canonical root. network protocol v1 does not replace the existing commitment or nullifier constructions.

## proof journal

network proofs commit a strictly encoded, versioned journal:

```text
NetworkProofRequestV1 {
  context: {
    network_id,
    protocol_version,
    ledger_root,
    anchor_height,
    expiry_height,
    metadata_hash,
  },
  intent: FaucetMint { request_id } | PrivateTransfer,
}

NetworkProofOutputV1 {
  context,
  program_hash,
  transition,
  public_conditions,
  execution_cost,
}

transition =
  FaucetMint {
    request_id,
    asset_tail_hash,
    public_amount,
    output_commitment,
  }
  | PrivateTransfer {
    nullifiers[],
    output_commitments[],
  }
```

the transition variant is the proof kind; it is not encoded a second time in the context where the two values could disagree. all output fields above are zkVM public output. private coin secrets, amounts for ordinary transfers, Merkle paths, program source, and program inputs remain private.

`metadata_hash` binds the encrypted output notes carried in the transaction envelope. the validator requires one note per output commitment in the same order.

## canonical-root contract

for a private transfer:

1. wallet requests a current commitment witness from the ledger;
2. guest proves membership against the supplied commitment root;
3. guest commits that exact root and anchor height in `NetworkProofOutputV1`;
4. validator verifies the proof before decoding the journal;
5. validator resolves `CanonicalRootV1 { height, commitment_root }` and requires both `height == anchor_height` and `commitment_root == ledger_root`;
6. validator requires the anchor to remain inside the accepted-root window;
7. validator checks expiry and nullifier freshness;
8. validator atomically appends nullifiers and output commitments.

append-only commitments allow proofs against a bounded recent-root window. the public nullifier set prevents concurrent proofs from spending one coin twice.

initial proposed genesis parameters:

```text
accepted_root_window = 32 blocks
max_proof_lifetime = 32 blocks
commitment_tree_depth = 32
```

these values are provisional until real proving latency is measured.

## faucet mint

faucet issuance has two independent controls:

1. a `FaucetMint` proof binds the public amount, configured test-asset TAIL, request ID, and hidden output commitment;
2. the faucet authority signature enforces admission, quota, and request uniqueness.

an authority signature without the mint proof is insufficient because a validator could not determine whether the hidden commitment actually uses the authorized amount.

## transaction validation

validators process a transaction in this order:

```text
request size limits
→ strict transaction decode
→ transaction deduplication
→ backend/program allowlist
→ cryptographic proof verification
→ strict journal decode
→ network/version/kind checks
→ encrypted-note metadata check
→ accepted root and expiry checks
→ nullifier freshness
→ output/condition limits
→ deterministic state delta
→ one atomic database commit
```

envelope fields are transport data, not consensus truth. nullifiers, output commitments, proof kind, and root context come from the verified journal.

## ledger state

```text
LedgerStateV1 {
  height,
  commitment_root,
  nullifier_log_root,
  commitment_count,
  nullifier_count,
  faucet_issued,
  protocol_parameters_hash,
}

state_root = SHA256(
  "veil_state_v1" || network_id || canonical_borsh(LedgerStateV1)
)
```

commitments and nullifiers are append-only Merkle logs. nullifiers also have a unique lookup index for double-spend checks.

## blocks and finality

alpha uses a signed hash chain produced by one sequencer. each block commits:

- network and protocol version;
- height and parent block hash;
- previous and new state roots;
- transaction root;
- timestamp;
- sequencer signature.

alpha initially produces one transaction per block. finality means inclusion in the sequencer's signed chain and matching replay by verifier replicas. this is centralized finality, not BFT consensus.

## encoding and hashing

- consensus structures use strict Borsh encoding;
- JSON is an RPC representation only;
- hashes use explicit domain prefixes;
- unknown versions, enum variants, and trailing bytes are rejected;
- backend program/verifying-key identity is pinned in genesis;
- golden vectors define every consensus hash and encoding before launch.

## checkpoint boundary

Chia testnet checkpoints commit the Veil network ID, height, block hash, state root, data-availability hash, and previous checkpoint coin ID. Chia provides external ordering/timestamp evidence. Chia consensus does **not** verify Veil proofs or state transitions.

## version policy

- this draft may change incompatibly until the first alpha genesis is published;
- genesis fixes protocol version, backend program ID, limits, and root policy;
- post-genesis changes require an explicit activation height and new golden vectors;
- unsupported versions fail closed;
- CATs, settlement, bridges, and federation are separate upgrades.

## security status

Veil is unaudited WIP research. protocol v1 must not carry real assets. public alpha requires real-backend adversarial tests, deterministic replay across replicas, restore drills, a canary period, and no unresolved critical/high findings.
