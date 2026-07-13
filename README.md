# Veil

[![CI](https://github.com/almogdepaz/Veil/actions/workflows/ci.yml/badge.svg)](https://github.com/almogdepaz/Veil/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**A privacy-preserving zkVM for Chialisp.** Veil proves that a Chialisp program executed correctly without revealing its private inputs—or the program itself.

Veil compiles and runs Chialisp inside [SP1](https://github.com/succinctlabs/sp1) or [RISC Zero](https://github.com/risc0/risc0), then exposes a proof and selected public values. On top of that execution layer, the project explores a private coin model inspired by Chia, with commitments, nullifiers, stealth addresses, CATs, and atomic offers.

> [!WARNING]
> Veil is an unaudited research prototype. It is not ready for production or real funds. There is currently no public Veil network, node, validator, consensus system, or Chia bridge.

## Why Veil?

Chialisp is a small, auditable language for programmable money, but normal execution reveals the program and its inputs. Veil moves that execution into a zkVM:

```text
private Chialisp + private inputs
                │
                ▼
       SP1 or RISC Zero
                │
                ▼
    proof + selected public outputs
```

This gives the project a few useful properties:

- **Private execution** — prove a puzzle ran correctly while keeping source and inputs hidden.
- **Chialisp compatibility** — use Chia's `clvm_tools_rs` compiler rather than a new circuit language.
- **Backend portability** — the core evaluator is independent of SP1 and RISC Zero.
- **Private coin primitives** — commitments hide coin details; nullifiers prevent double-spends.
- **Programmable privacy** — stealth payments, CATs, ring spends, and atomic settlement share one execution model.

## Try it

### Fast test loop

The mock backend exercises the protocol without generating a real ZK proof:

```bash
git clone https://github.com/almogdepaz/Veil.git
cd Veil
cargo test-mock
```

### Generate a real proof

Install the selected zkVM toolchain, then run the simulator demo:

```bash
./install-deps.sh
./sim_demo.sh         # SP1
./sim_demo.sh risc0   # RISC Zero
```

Or prove a Chialisp expression directly:

```bash
cargo run-sp1 -- prove \
  --expression "(mod (a b) (+ a b))" \
  --variables "5,3"
```

> Real proof generation is resource-intensive. Use `cargo test-mock` for normal development.

## What is private?

A spend proof establishes knowledge of coin secrets and membership against a host-supplied commitment root. Legacy simulator proofs rely on the simulator to supply its current root. Network-mode proofs expose that same root and anchor height in a typed public journal; the storage-independent ledger policy can compare it with a caller-supplied canonical root. Persistent canonical state and a node are not implemented yet.

| Kept private | Revealed for verification |
|---|---|
| Chialisp source | Program hash |
| Program inputs | Proof validity |
| Coin serial and randomness | Nullifier |
| Committed coin details | Selected CLVM conditions/public values |

The nullifier makes a second spend detectable without identifying the original coin. See [the protocol documentation](DOCUMENTATION.md) for the construction, threat model, and current limitations.

## How it works

1. The host supplies Chialisp source, parameters, and optional private coin data.
2. The zkVM guest compiles the source with `clvm_tools_rs`.
3. `VeilEvaluator` executes the resulting CLVM bytecode with injected cryptographic handlers.
4. The guest checks commitments and Merkle membership, then derives nullifiers where required.
5. The backend returns a proof plus explicit public outputs for the verifier.

```text
clvm_zk_core/       no_std compiler, evaluator, commitments, and Merkle logic
backends/risc0/     RISC Zero host and guest programs
backends/sp1/       SP1 host and guest programs
backends/mock/      fast protocol testing without proof generation
src/protocol/       private spend, puzzle, and settlement logic
src/wallet/         HD wallet and stealth-address logic
src/simulator.rs    local privacy-chain simulator
```

The core has no backend-specific dependencies; cryptographic implementations are injected by each zkVM backend.

## Project status

The compiler/evaluator core, SP1 and RISC Zero backends, typed network proof journal, storage-independent root policy, private-coin primitives, simulator, and experimental offers infrastructure are implemented. A persistent canonical state machine, node, RPC, independent replicas, and Chia checkpoints are proposed but not implemented. See the [alpha architecture](docs/architecture.md) and [draft network protocol](docs/network-protocol-v1.md).

Veil currently targets research and experimentation around:

- private programmable assets on Chia;
- zkVM performance for CLVM workloads;
- recursive proof aggregation and atomic settlement;
- backend-independent proof interfaces.

If those overlap with your work, open an issue or bring a focused experiment. Reproducible benchmarks, protocol review, and adversarial test cases are especially useful.

## Development

Backend-specific aliases keep build artifacts separate:

```bash
cargo mock           # build mock backend
cargo sp1            # release build with SP1
cargo risc0          # release build with RISC Zero

cargo test-mock      # fast test suite
cargo test-sp1       # tests with SP1
cargo test-risc0     # tests with RISC Zero
```

Each real zkVM backend can use roughly 1 GB of build artifacts. For a faster compile-only check, use `cargo check-mock`, `cargo check-sp1`, or `cargo check-risc0`.

## Explore

- [Protocol documentation](DOCUMENTATION.md) — implemented nullifiers, stealth addresses, CATs, simulator, and CLVM opcodes
- [Proposed network protocol](docs/network-protocol-v1.md) — draft validator and block contract
- [Alpha architecture](docs/architecture.md) — selected topology, trust model, and boundaries
- [Repository governance](docs/governance.md) — required checks, review policy, and emergency bypass
- [`examples/alice_bob_lock.rs`](examples/alice_bob_lock.rs) — private puzzle execution
- [`examples/recursive_aggregation.rs`](examples/recursive_aggregation.rs) — recursive proofs
- [`clvm_zk_core`](clvm_zk_core) — backend-agnostic execution core
- [`backends`](backends) — SP1, RISC Zero, and mock implementations

## License

[MIT](LICENSE)
