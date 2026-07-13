# ADR 0001: centralized alpha with Chia testnet checkpoints

- status: accepted for planning; implementation not started
- date: 2026-07-12

## context

Veil has zkVM guests, proof backends, private-coin primitives, and a local simulator. it does not have a canonical validator, persistent ledger, node, RPC, networking, or Chia integration.

three first-network directions were considered:

1. a centralized sequencer with independently replaying replicas and Chia checkpoints;
2. a new standalone appchain using third-party consensus;
3. a Chia fork or consensus proposal that directly verifies Veil proofs.

building consensus or changing Chia before the state transition is deterministic would increase scope without proving the core network contract.

## decision

build a faucet-only public alpha with:

- one sequencer;
- at least two independently replaying verifier replicas;
- complete public block data;
- local SP1 proving;
- signed deterministic block history;
- periodic state checkpoints through a Chia testnet singleton;
- no deposits, withdrawals, bridge custody, or real assets.

Chia checkpoints provide ordering/timestamp and discovery evidence. they do not make Veil execution trustless.

## consequences

positive:

- smallest architecture that exercises proof verification, canonical roots, nullifiers, persistence, replay, wallet recovery, and operations;
- avoids inventing p2p consensus;
- makes sequencer state independently auditable;
- creates evidence needed to choose later federation/consensus architecture.

negative:

- sequencer controls ordering and can halt or censor;
- verifier replicas detect invalid history but cannot finalize an alternative history;
- checkpoint authority remains trusted;
- no real asset can be safely represented without a separately designed and audited bridge.

## rejected alternatives

### standalone appchain first

rejected because consensus, networking, validator membership, and upgrade governance would dominate work before the proof/state transition boundary is validated.

### direct Chia integration first

rejected because Chia consensus does not currently verify Veil's SP1/RISC Zero proofs, own Veil's commitment/nullifier state, or enforce its transitions.

### mainnet or bridged testnet assets

rejected until public testnet evidence, independent audits, operational maturity, custody design, and validator governance exist.

## review trigger

revisit this ADR only after the alpha demonstrates deterministic replay, real-proof throughput, restore/checkpoint drills, and a sustained canary. federation should use established consensus machinery rather than a custom protocol.
