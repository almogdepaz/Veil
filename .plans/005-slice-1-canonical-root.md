# slice 1 — canonical-root proof contract

status: implementation and local evidence complete — commit/PR/GitHub evidence pending

branch: `network/01-canonical-root`
base: `10c99bd6371c4335fadd08a2ed36fbba5d954875`
parent: `.plans/002-network-implementation-design.md`

## ~~1. Establish accepted slice baseline~~

- PR #25 squash-merged as `10c99bd`.
- branch created from updated `main`.
- `.loop-optimizer/` and `.plans/004-loop-optimizer-validation.md` remain untouched.
- no slice-1 production code has been written.

## ~~2. Freeze the typed proof contract~~

status: complete — approved reshape implemented and synchronized into protocol/design docs

resolved decisions:

1. `FaucetMint` output requires `request_id`, but the approved `Input` extension supplies only `NetworkContextV1`, which has no request ID.
2. faucet proofs must bind the configured asset TAIL, but the proposed public transition omits `tail_hash`; the hiding output commitment is insufficient for validator enforcement.
3. canonical-root acceptance belongs in `veil-ledger`, but the slice table defers that crate until slice 2 while slice-1 acceptance requires validator root-policy tests.

recommended resolution:

```rust
pub struct NetworkProofRequestV1 {
    pub context: NetworkContextV1,
    pub intent: NetworkProofIntentV1,
}

pub enum NetworkProofIntentV1 {
    FaucetMint { request_id: [u8; 32] },
    PrivateTransfer,
}

pub struct NetworkContextV1 {
    pub network_id: [u8; 32],
    pub protocol_version: u16,
    pub ledger_root: [u8; 32],
    pub anchor_height: u64,
    pub expiry_height: u64,
    pub metadata_hash: [u8; 32],
}

pub enum NetworkTransitionV1 {
    FaucetMint {
        request_id: [u8; 32],
        asset_tail_hash: [u8; 32],
        public_amount: u64,
        output_commitment: [u8; 32],
    },
    PrivateTransfer {
        nullifiers: Vec<[u8; 32]>,
        output_commitments: Vec<[u8; 32]>,
    },
}
```

`Input` receives `network: Option<NetworkProofRequestV1>`. the transition enum is the proof kind; do not encode a second `proof_kind` field that can disagree. legacy simulator calls use `None`; network admission requires `Some`.

move the minimal no-IO `veil-ledger` crate scaffold into slice 1. it owns `ProofVerifier`, accepted-root policy, typed validation errors, and test fixtures. persistence, Merkle append planning, transactions, and blocks remain slice 2.

acceptance: update `.plans/002-network-implementation-design.md` and `docs/network-protocol-v1.md` so one authoritative contract exists before tests.

## ~~3. Drive core and guest behavior with red tests~~

write and observe failures before production changes:

1. faucet output binds request ID, asset TAIL, public amount, commitment, metadata hash, and root context;
2. private spend output contains exactly the membership root used by the guest;
3. mismatched primary/ring roots fail execution;
4. transformed private CREATE_COIN conditions become ordered output commitments;
5. changing encrypted-note metadata after proving fails validation.

implement the smallest shared core production path used by mock, SP1, and RISC Zero guests. preserve legacy `ProofOutput` behavior when `Input.network` is `None`.

## ~~4. Add verifier and canonical-root policy~~

in the minimal `veil-ledger` crate:

- define strict `ProofVerifier::verify_and_decode` boundary;
- reject size before proof deserialization;
- require the genesis-pinned backend/program identity;
- compare exact `(anchor_height, ledger_root)` against retained roots;
- enforce accepted-root window and proof lifetime;
- derive state-neutral validation output only; no persistence or mutation.

red tests cover unknown root, wrong root, expired proof, excessive lifetime, wrong network/version/transition, trailing bytes, and mutated metadata.

## ~~5. Verify backend parity and evidence~~

status: complete locally — all required checks, canonical-Borsh real proofs, and differential reviews pass; GitHub evidence pending

run:

```text
cargo test-mock --test network_root_contract
cargo test-mock
cargo test-sp1 --test network_root_contract_backend -- --test-threads=1
cargo test-risc0 --test network_root_contract_backend -- --test-threads=1
cargo fmt --all -- --check
git diff --check
```

manually decode one real SP1 proof and expose only network ID, transition kind, root/height/expiry, nullifier count, and output count. record guest program IDs as slice-1 evidence, not stable alpha genesis IDs.

verified real-backend evidence (2026-07-13):

- SP1: 4/4 passed in 403.41s; program ID `008b0e1a9a05978661a0850a95b1352604b2853b40b5bd4686339d34c5c4e4dc`;
- RISC Zero: 4/4 passed in 2,150.69s; program ID `a6e6e79d1e1f553bbc756abf7c64b5dfa2b80c2f85bb132c4b007d5d4064efa4`;
- both decoded the same private-transfer journal summary: root `c5e0b52e698267c097deed2e5008780e20d8b5d8733d95bd424fead643e3daba`, anchor 27, expiry 28, one nullifier, one output;
- IDs are slice evidence only and are not frozen alpha-genesis identifiers;
- full local gate passed: fmt, mock/ledger clippy, mock/ledger tests, SP1/RISC Zero host test checks, all guest checks, and both backend clippy runs;
- security review: `review-network-01-canonical-root.md` → APPROVE;
- delivery/architecture review: `review-delivery-network-01-canonical-root.md` → delivered / fits.

stop for explicit slice acceptance before merge or slice 2.
