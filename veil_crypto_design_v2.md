# Veil Cryptographic Design

## Overview

Veil uses a hash-based nullifier protocol for coin spending authorization instead of traditional digital signatures. This document describes the construction, security assumptions, and tradeoffs for cryptographic review.

## System Model

### Actors
- **Spender**: party who knows coin secrets and can authorize spending
- **Verifier**: any party verifying proofs (blockchain nodes)
- **Adversary**: computationally bounded, may be quantum-capable

### Goals
1. **Authorization**: only the secret holder can spend a coin
2. **Double-spend prevention**: each coin spendable exactly once
3. **Privacy**: spending reveals minimal information about the coin
4. **Unlinkability**: multiple spends by same party are unlinkable

## Protocol Construction

### Secret Derivation (HD Wallet)

All coin secrets MUST be derived deterministically from a master seed using hierarchical deterministic derivation. Random generation is NOT permitted.

```
master_seed       = 256 bits of entropy (BIP-39 or equivalent)
coin_path         = "m/veil/account/coin_index"

// 384-bit serial for post-quantum margin against multi-target Grover
serial_number     = H("veil_serial_derive_v1" || master_seed || coin_path) 
                    || H("veil_serial_derive_v1.ext" || master_seed || coin_path)[0:128]
                    // concatenate 256 + 128 bits = 384 bits

serial_randomness = H("veil_rand_derive_v1" || master_seed || coin_path)
```

**Rationale**: Deterministic derivation ensures:
- Serial uniqueness is guaranteed by unique derivation paths
- Wallet recovery from seed recovers all coin secrets
- No RNG failures can cause serial collision

### Coin Creation

When a coin is created:

```
serial_commitment = H("clvm_zk_serial_v1.0" || serial_number || serial_randomness)
coin_commitment   = H("clvm_zk_coin_v2.0" || tail_hash || amount || puzzle_hash || serial_commitment)
```

Where:
- `H` is SHA-256
- `tail_hash` identifies asset type (32 bytes, all zeros for native currency)
- `amount` is 8-byte little-endian
- `puzzle_hash` is the hash of the spending program (32 bytes)

The `coin_commitment` is inserted into a global Merkle tree. Only `coin_commitment` is public.

### Spending

To spend, the prover generates a zero-knowledge proof for the entire transaction:

**Public inputs:**
- `nullifiers[]` - one per input coin
- `output_commitments[]` - one per output coin
- `merkle_root`

**Private inputs (witness per input):**
- `serial_number`
- `serial_randomness`
- `amount`
- `puzzle_hash`
- `puzzle_bytes` (actual program)
- `solution` (puzzle input)
- `tail_hash`
- `merkle_path`

**Private inputs (witness per output):**
- `serial_number`
- `serial_randomness`
- `amount`
- `puzzle_hash`
- `tail_hash`

**Proof statement (circuit constraints):**

```
// All constraints use the SAME serial_number witness variable.
// Implementations MUST NOT use separate variables for different constraints.

fn verify_transaction(
    // Public
    nullifiers: [Field],           // one per input
    output_commitments: [Field],   // one per output  
    merkle_root: Field,
    // Private (witness)
    inputs: [InputWitness],
    outputs: [OutputWitness]
) {
    // Verify each input
    for (i, input) in inputs.iter().enumerate() {
        // 1. Compute serial commitment from THE witness serial_number
        let serial_commitment = H(
            "clvm_zk_serial_v1.0" || 
            input.serial_number ||        // <-- THIS variable
            input.serial_randomness
        );
        
        // 2. Compute coin commitment using same serial_commitment
        let coin_commitment = H(
            "clvm_zk_coin_v2.0" || 
            input.tail_hash || 
            input.amount || 
            input.puzzle_hash || 
            serial_commitment
        );
        
        // 3. Verify coin exists in Merkle tree
        assert!(MerkleVerify(merkle_root, coin_commitment, input.merkle_path));
        
        // 4. Verify nullifier using THE SAME input.serial_number
        assert!(nullifiers[i] == H(
            input.serial_number ||        // <-- SAME variable as step 1
            input.puzzle_hash || 
            input.amount
        ));
        
        // 5. Execute CLVM puzzle inside circuit
        let puzzle = deserialize(input.puzzle_bytes);
        assert!(H(puzzle) == input.puzzle_hash);
        let result = clvm_execute(puzzle, input.solution);
        assert!(result.is_valid());
        
        // 6. Range check (implicit in u64, explicit for clarity)
        assert!(input.amount < 2^64);
    }
    
    // Verify each output
    for (i, output) in outputs.iter().enumerate() {
        let serial_commitment = H(
            "clvm_zk_serial_v1.0" || 
            output.serial_number || 
            output.serial_randomness
        );
        let coin_commitment = H(
            "clvm_zk_coin_v2.0" || 
            output.tail_hash || 
            output.amount || 
            output.puzzle_hash || 
            serial_commitment
        );
        
        assert!(output_commitments[i] == coin_commitment);
        assert!(output.amount < 2^64);  // Range check
    }
    
    // 7. Conservation of value PER ASSET TYPE (no fees currently)
    // Group by tail_hash and verify each balances independently
    let input_totals: Map<TailHash, u64> = group_sum(inputs, |i| (i.tail_hash, i.amount));
    let output_totals: Map<TailHash, u64> = group_sum(outputs, |o| (o.tail_hash, o.amount));
    assert!(input_totals == output_totals);
}
```

**Critical implementation note**: The `input.serial_number` variable MUST be the same variable in constraints 1 and 4. This is not merely a stylistic choice—using separate variables would allow an attacker to provide different values, breaking the nullifier binding. Circuit implementations must be audited to verify single-variable usage.

### Double-Spend Prevention

Verifiers maintain a nullifier set. A spend is valid iff:
1. The proof verifies
2. `nullifier ∉ nullifier_set`

After valid spend: `nullifier_set ← nullifier_set ∪ {nullifier}`

### Transaction Structure

Veil uses a UTXO model. A transaction consumes one or more input coins and creates one or more output coins.

```
Transaction {
    inputs: [
        { nullifier, spend_proof },  // each input is a spent coin
        ...
    ],
    outputs: [
        { coin_commitment },         // each output is a new coin
        ...
    ],
    aggregate_proof                  // single proof covering all inputs/outputs
}
```

**UTXO Model Note**: When spending a coin, you consume the ENTIRE input amount and create new output coins. For example, to send 30 tokens from a 100-token coin, you create two outputs: 30 tokens to recipient, 70 tokens back to yourself (change). The input coin's amount is fixed at creation time; only outputs are flexible.

### Amount Balancing

The circuit enforces conservation of value **per asset type**:

```
// Group amounts by tail_hash, verify each asset balances independently
for each tail_hash in (input_tail_hashes ∪ output_tail_hashes):
    assert!(sum(input_amounts where tail_hash) == sum(output_amounts where tail_hash))
```

This constraint is verified INSIDE the zkVM as part of proof generation. No external balance check is needed—an invalid proof cannot be generated if amounts don't balance.

**Privacy note**: Asset types (`tail_hash` values) are NOT revealed to verifiers. Balance checks happen inside the zkVM, and STARK zero-knowledge property hides internal constraint structure. Verifier only learns: proof valid/invalid.

**No fees**: The current protocol does not include transaction fees. Balance equation is strict equality per asset. Fees may be added in future versions as an explicit `fee` output or by allowing `sum(inputs) >= sum(outputs)` for native currency only.

### Range Proofs

To prevent negative amount attacks (e.g., creating 1000 tokens + -990 tokens that "balance" with 10 input tokens), the circuit enforces amount bounds:

```
for each amount in inputs ∪ outputs:
    assert!(amount >= 0)
    assert!(amount < 2^64)
```

Amounts are represented as unsigned 64-bit integers. The zkVM's native integer arithmetic enforces these bounds—field overflow attacks are not possible because amounts never enter field arithmetic directly.

### Puzzle Execution (CLVM)

Unlike simpler nullifier schemes that only prove "I know the preimage of puzzle_hash," Veil proves **actual program execution** inside the zkVM.

```
// Inside circuit:
let puzzle = deserialize(witness.puzzle_bytes)
assert!(H(puzzle) == witness.puzzle_hash)

let result = clvm_execute(puzzle, witness.solution)
assert!(result.is_valid())

// Puzzle output conditions become circuit constraints:
for condition in result.conditions:
    enforce_condition(condition)  // e.g., CREATE_COIN, AGG_SIG, etc.
```

**Implications**:
- Arbitrary spending conditions are provable (timelocks, multisig, atomic swaps, etc.)
- Puzzle logic is private—only puzzle_hash is committed, actual program hidden
- This is strictly more powerful than "proof of preimage knowledge"

### Delegated Proving

Proof generation is computationally intensive. Mobile/web clients may delegate proving to external services.

**Tradeoff**: Delegated proving requires sharing the full witness (including `serial_number`, `amount`, `puzzle_hash`) with the prover. This is an accepted privacy tradeoff:
- Prover learns transaction details
- Prover CANNOT steal funds (doesn't know master seed, can't derive other coins)
- Prover CANNOT front-run (proof is bound to specific outputs chosen by user)

Users requiring maximum privacy must generate proofs locally.

## Stealth Addresses

Stealth addresses provide unlinkable payments. Each payment to a stealth address produces a unique `puzzle_hash` that only the recipient can recognize and spend.

### Construction

A stealth address consists of two public keys:
```
stealth_address = (view_pubkey, spend_pubkey)
```

Where:
- `view_pubkey = view_privkey × G` - used for ECDH, allows scanning
- `spend_pubkey = spend_privkey × G` - used for spending authorization (signature mode only)

### Payment Protocol (ECDH)

**Sender** (knows only public stealth address):
```
1. ephemeral_privkey ← random()
2. ephemeral_pubkey = ephemeral_privkey × G
3. shared_secret = ephemeral_privkey × view_pubkey    // ECDH
4. derive puzzle_hash and serial secrets from shared_secret (mode-dependent)
5. create coin with derived puzzle_hash
6. publish: (coin_commitment, ephemeral_pubkey)
```

**Receiver** (knows view_privkey):
```
1. shared_secret = view_privkey × ephemeral_pubkey    // same ECDH result
2. derive expected puzzle_hash and serial secrets
3. if coin.puzzle_hash matches: "this payment is for me"
4. store shared_secret for later spending
```

### Operating Modes

Veil supports two stealth modes with different security/performance tradeoffs:

#### Nullifier Mode (Default)

```
coin_secret      = H("veil_stealth_nullifier_v1" || shared_secret)
serial_number    = H(coin_secret || "serial")
serial_randomness = H(coin_secret || "rand")
puzzle_hash      = H("(mod () ())")    // trivial puzzle, same for all
```

**Properties**:
- ~10K zkVM cycles (hash operations only)
- View key holder CAN spend (shared_secret sufficient)
- No signature verification needed
- Deterministic serial derivation (no encrypted data transmission)

**Security model**: Authorization comes from knowledge of `shared_secret`, which requires `view_privkey` to derive. Anyone with `view_privkey` can scan AND spend.

#### Signature Mode

```
derive_scalar    = H("veil_stealth_v1" || shared_secret || "spend")
derived_pubkey   = spend_pubkey + derive_scalar × G
puzzle_hash      = H(unique_puzzle(derived_pubkey))
serial_number    = random()           // must be transmitted encrypted
serial_randomness = random()
```

**Properties**:
- ~2-5M zkVM cycles (ECDSA verification)
- View key holder CANNOT spend (needs spend_privkey)
- Signature verification required in zkVM
- Random serials encrypted with shared_secret and transmitted

**Security model**: Authorization requires `derived_privkey = spend_privkey + derive_scalar`. View key holder can scan but not spend—suitable for custody/audit setups.

### Mode Selection Tradeoffs

| Property | Nullifier Mode | Signature Mode |
|----------|---------------|----------------|
| Proving time | ~10K cycles | ~2-5M cycles |
| View/spend separation | No | Yes |
| View key can spend | Yes | No |
| Serial transmission | Not needed | Encrypted in memo |
| Use case | Personal wallets | Custody, exchanges, auditors |

**Recommendation**: Default to nullifier mode for 200x faster proving. Use signature mode only when view/spend separation is required (e.g., giving auditors read-only access).

### Scanning

Receiver scans blockchain for payments by:

1. For each `(coin_commitment, ephemeral_pubkey)` pair:
2. Compute `shared_secret = view_privkey × ephemeral_pubkey`
3. Try nullifier mode: derive puzzle_hash, check if matches
4. Try signature mode: derive puzzle_hash, check if matches
5. If match found, store coin with detected mode

Mode is auto-detected from `puzzle_hash`:
- If `puzzle_hash == STEALTH_NULLIFIER_PUZZLE_HASH`: nullifier mode
- Otherwise: try signature mode derivation

### Security Considerations

**Nullifier mode tradeoff**: The view key becomes a "scan + spend" key. This is acceptable for personal wallets but inappropriate when view-only access is needed.

**ECDH security**: Relies on secp256k1 ECDH. Quantum computers running Shor's algorithm could derive `shared_secret` from public keys. However:
- The underlying coin still uses hash-based nullifiers (quantum-resistant)
- Attacker learns payment amounts but spending still requires breaking hash preimage
- Migration path: future stealth protocols could use post-quantum key exchange

**Ephemeral key reuse**: NEVER reuse `ephemeral_privkey`. Each payment must use fresh randomness.

## Security Analysis

### Assumptions

| Assumption | Formalization |
|------------|---------------|
| **Hash preimage resistance** | For random `x`, finding `x'` s.t. `H(x') = H(x)` requires `O(2^256)` work |
| **Hash collision resistance** | Finding `x ≠ y` s.t. `H(x) = H(y)` requires `O(2^128)` work |
| **zkSNARK/STARK soundness** | Adversary cannot produce valid proof for false statement (computational soundness, ~2^{-100} per proof for SP1/RISC0) |
| **zkSNARK/STARK zero-knowledge** | Proof reveals nothing beyond statement truth |
| **HD derivation uniqueness** | Unique derivation paths produce unique serial_numbers (guaranteed by collision resistance of H) |

Note: Merkle binding reduces to collision resistance and is not listed as a separate assumption.

### Security Properties

#### Theorem 1: Unforgeability

**Claim**: An adversary who does not know `serial_number` cannot spend the coin (except with negligible probability).

**Security**: 384-bit classical, 192-bit quantum (single-target Grover), ~182-bit with 2^20 multi-target

**Assumptions**: SHA-256 preimage resistance, STARK soundness

**Proof sketch**:
- To spend, adversary must produce valid proof with correct `nullifier`
- `nullifier = H(serial_number || puzzle_hash || amount)`
- Adversary knows `puzzle_hash` and `amount` (or can guess)
- Finding `serial_number` requires inverting `H` on `serial_commitment`
- By preimage resistance, this requires `O(2^256)` classical / `O(2^128)` quantum work

#### Theorem 2: Double-Spend Prevention

**Claim**: A coin can be spent at most once.

**Security**: Unconditional given nullifier set integrity

**Assumptions**: Same `serial_number` variable used in commitment and nullifier constraints (implementation requirement), HD derivation guarantees serial uniqueness

**Proof sketch**:
- Circuit enforces same `serial_number` in serial_commitment and nullifier computation
- HD derivation ensures unique serial_number per coin
- Therefore: same coin → same serial_number → same nullifier (deterministic)
- Nullifier set check prevents accepting duplicate nullifiers
- Each coin accepted at most once

#### Theorem 3: Unlinkability

**Claim**: Given two spends by the same party, an adversary cannot determine they share an owner.

**Security**: Computational, within anonymity set of size A where A = |{coins with matching (tail_hash, amount pattern)}|

**Assumptions**: Zero-knowledge property of proof system, no timing/metadata leakage

**Proof sketch**:
- Each coin has independent `serial_number` (derived from unique path)
- `nullifier = H(serial_number || ...)` where `serial_number` is unique per coin
- No common value appears in public outputs across spends
- Even same `puzzle_hash` (spending policy) is hidden in the proof
- Linking requires breaking zero-knowledge property

**Degradation note**: Transaction graph analysis, timing correlation, and amount patterns reduce effective anonymity set over time. This theorem provides computational unlinkability, not information-theoretic.

#### Theorem 4: Privacy

**Claim**: Spending reveals only nullifiers and output commitments; input amounts, puzzle_hash, and input coin identity remain hidden.

**Security**: Computational

**Assumptions**: Hiding property of hash-based commitments, zero-knowledge property of proofs

**Proof sketch**:
- Public outputs: `nullifiers[]`, `output_commitments[]`, `merkle_root`
- `merkle_root` is global (same for all spends in epoch)
- `nullifier` is a hash that cannot be inverted to recover inputs
- `output_commitments` hide their contents (amount, puzzle_hash) via hash preimage resistance
- By zero-knowledge property, proof reveals nothing about witness beyond what's computable from public outputs
- Therefore: input `amount`, `puzzle_hash`, specific input `coin_commitment` remain hidden

**What IS revealed**:
- Number of inputs and outputs (via `nullifiers.len()` and `output_commitments.len()`)
- That the transaction is valid (balances, range checks pass)

**What is NOT revealed** (contrary to some privacy coin designs):
- Which asset types are involved (balance checks happen inside zkVM, not visible to verifier)
- Internal circuit branching or constraint counts

### Quantum Security Analysis

| Attack | Classical | Quantum (Grover) | Notes |
|--------|-----------|------------------|-------|
| Forge serial_number | 2^384 | 2^192 | Single-target preimage |
| Find hash collision | 2^128 | ~2^85 (BHT) | SHA-256 output size limits this |
| Multi-target (2^20 coins) | 2^384 | 2^182 | Grover with multiple targets |
| Break ECDSA (comparison) | 2^128 | poly(n) (Shor) | Completely broken |

**Assessment**:
- 192-bit quantum security (single-target) degrades to ~182-bit with 1M active coins
- Significant margin above NIST Category 5 (256-bit classical / 128-bit quantum)
- Protocol is quantum-resistant; contrast with ECDSA/BLS broken by Shor's algorithm
- Note: Grover requires coherent quantum computation which is the practical barrier

## Comparison with Signature-Based Authorization

### Traditional Signature Approach

```
coin_commitment = H(amount || puzzle_hash || owner_pubkey)
spending_proof includes: signature = Sign(privkey, message)
verification: Verify(pubkey, message, signature)
```

### Tradeoff Analysis

| Property | Hash-Based Nullifier | Signature-Based |
|----------|---------------------|-----------------|
| Classical security | 128-bit | 128-bit |
| Quantum security | 182-192 bit | 0 (broken by Shor) |
| Key reuse | No (one serial per coin) | Yes |
| Ownership proof without spending | Via ZK proof (expensive) | Yes (cheap signature) |
| Hardware wallet compatibility | Seed storage only | Native signing |
| In-circuit verification cost | ~10K-25K cycles (SHA-256 w/ precompile) | ~2-5M cycles (ECDSA) |
| Privacy (pubkey exposure) | Never exposed | Exposed or deferred |
| Cryptographic assumptions | Hash functions only | Hash + discrete log |

### Detailed Tradeoff Discussion

#### Key Reuse

**Signature-based**: One keypair can authorize unlimited spends. Convenient for wallet UX.

**Nullifier-based**: Each coin requires unique `serial_number`. No key reuse by design.

**Mitigation**: HD derivation from master seed (see Secret Derivation section). User experience equivalent to HD wallets (BIP-32).

#### Ownership Proofs

**Signature-based**: Sign a challenge to prove ownership without spending.

**Nullifier-based**: Revealing `serial_number` to prove ownership also reveals the nullifier, effectively marking the coin as "known spent" even if not broadcast.

**Mitigation**: Zero-knowledge ownership proofs. Prove knowledge of `serial_number` for a `coin_commitment` without revealing either. More expensive than signing, but possible.

#### Hardware Wallet Integration

**Signature-based**: HSMs and hardware wallets designed for ECDSA/EdDSA signing.

**Nullifier-based**: 
- Store master seed in hardware wallet
- Derive `serial_number` on secure element via HD path
- Generate proof on host with derived values
- Hardware wallet never exposes seed; proof generation is not security-critical

#### Verification Cost in zkVM

| Operation | Approximate zkVM cycles |
|-----------|------------------------|
| SHA-256 (with precompile) | 10,000 - 25,000 |
| ECDSA verify (with precompile) | 2,000,000 - 5,000,000 |
| BLS verify | 10,000,000 - 20,000,000 |

Nullifier protocol requires ~3 hash operations per spend. Provides 80-200x reduction in proving time versus ECDSA (conservative estimate; varies by backend and precompile optimization).

## Concrete Instantiation in Veil

### Parameters

| Parameter | Value | Justification |
|-----------|-------|---------------|
| Hash function | SHA-256 | NIST standard, hardware acceleration, zkVM precompiles |
| Serial number size | 384 bits | 192-bit quantum security (single-target), ~182-bit with multi-target |
| Merkle tree depth | 20 | Supports 2^20 ≈ 1M coins per tree |
| Proof system | STARK (SP1/RISC0) | No trusted setup, quantum-resistant |
| Soundness | ~2^{-100} per proof | Degrades linearly with recursive composition |

### Domain Separation

All hash computations use domain separation tags:

**Core protocol:**
- `"clvm_zk_serial_v1.0"` - serial commitment
- `"clvm_zk_coin_v2.0"` - coin commitment

**HD wallet derivation:**
- `"veil_serial_derive_v1"` - HD serial derivation
- `"veil_rand_derive_v1"` - HD randomness derivation

**Stealth addresses:**
- `"veil_stealth_v1"` - signature mode key derivation
- `"veil_stealth_nullifier_v1"` - nullifier mode serial derivation
- `"stealth_view"` - view key derivation from seed
- `"stealth_spend"` - spend key derivation from seed
- `"stealth_puzzle_id"` - unique puzzle generation from derived pubkey

Prevents cross-protocol attacks and provides versioning for future upgrades.

### Nullifier Construction

```
nullifier = H(serial_number || puzzle_hash || amount)
```

Including `puzzle_hash` and `amount`:
- Binds nullifier to specific spending conditions
- Provides defense-in-depth if constraint binding has implementation bugs
- Note: Given correct single-variable constraint implementation and HD uniqueness, `H(serial_number)` alone would suffice, but additional binding adds safety margin

## Operational Considerations

### Nullifier Set Growth

The nullifier set grows monotonically—one 32-byte entry per spent coin, forever. At 1M transactions/year, this adds ~32MB/year to validator state.

**Current approach**: Accept unbounded growth. 32MB/year is manageable for foreseeable scale.

**Future options if growth becomes problematic**:
- State rent (charge for nullifier storage)
- Rolling windows (old nullifiers archived, very old coins require migration transactions)
- Nullifier accumulators (cryptographic compression, adds complexity)

### MEV and Frontrunning

If proofs are broadcast to a public mempool before inclusion, observers could potentially:
- Front-run by seeing transaction intent
- Sandwich attack in DeFi contexts

**Current status**: Out of scope for cryptographic design. Mitigations are at the network/mempool layer:
- Private mempools
- Commit-reveal schemes for transaction submission
- Block builder selection mechanisms

These are operational concerns, not protocol-level cryptographic issues.

## Open Questions for Review

1. **Serial randomness**: Is the two-part secret `(serial_number, serial_randomness)` necessary, or would single secret suffice?
   - Current rationale: `serial_randomness` blinds commitment; `serial_number` appears in nullifier
   - Separating them prevents nullifier from leaking commitment information

2. **Merkle tree updates**: Current design uses sparse Merkle tree. Are there concerns with append-only vs. updatable tree semantics?

3. **Proof system choice**: Using STARK for quantum resistance. Are there concerns with STARK soundness in the recursive composition used by SP1/RISC0? Current assumption: soundness degrades linearly (k * 2^{-100} for k recursive steps).

4. ~~**Multi-asset balancing**~~: RESOLVED - asset types are NOT revealed. Balance checks occur inside zkVM; verifier only sees valid/invalid. STARK zero-knowledge property hides internal constraint structure.

## References

- Zcash protocol specification (nullifier construction)
- Tornado Cash (commitment/nullifier pattern)
- BIP-32 / BIP-39 (HD wallet derivation)
- SP1/RISC0 STARK proof systems
