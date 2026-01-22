# nullifier protocol (v2.0)

the nullifier protocol prevents double-spending in veil's privacy-preserving transactions. this document describes the cryptographic design and security guarantees.

## overview

each coin has a unique serial number that generates a deterministic nullifier when spent. the nullifier is public and stored on-chain - if someone tries to spend the same coin twice, the same nullifier would be revealed, and the blockchain rejects the second spend.

## key concepts

| term | definition |
|------|------------|
| **serial_number** | 32-byte secret tied to a specific coin |
| **serial_randomness** | 32-byte random value for hiding serial in commitment |
| **serial_commitment** | `hash("clvm_zk_serial_v1.0" \|\| serial_number \|\| serial_randomness)` |
| **coin_commitment** | `hash("clvm_zk_coin_v2.0" \|\| tail_hash \|\| amount \|\| puzzle_hash \|\| serial_commitment)` |
| **nullifier** | `hash(serial_number \|\| program_hash \|\| amount)` - revealed when spending |

## protocol flow

### 1. coin creation

when a coin is created:

```
1. generate random serial_number (32 bytes)
2. generate random serial_randomness (32 bytes)
3. compute serial_commitment = hash("clvm_zk_serial_v1.0" || serial_number || serial_randomness)
4. compute coin_commitment = hash("clvm_zk_coin_v2.0" || tail_hash || amount || puzzle_hash || serial_commitment)
5. add coin_commitment to merkle tree (public)
6. store serial_number, serial_randomness privately (CRITICAL: losing these = losing funds)
```

### 2. coin spending

when spending a coin:

```
1. prove knowledge of (serial_number, serial_randomness) that matches serial_commitment
2. prove coin_commitment is in merkle tree (membership proof)
3. prove program_hash matches the coin's puzzle_hash
4. compute nullifier = hash(serial_number || program_hash || amount)
5. reveal nullifier publicly (checked by blockchain)
6. execute puzzle program and reveal conditions
```

### 3. blockchain validation

the blockchain:
- checks nullifier hasn't been used before
- verifies zk proof is valid
- adds nullifier to spent set
- applies output conditions (CREATE_COIN, etc.)

## security guarantees

### 1. double-spend prevention

each coin has exactly one valid nullifier (derived from its serial_number and program_hash). attempting to spend the same coin twice reveals the same nullifier, which the blockchain rejects.

### 2. program binding

`program_hash` is included in the nullifier, preventing spending a coin with a different program than the one committed at creation. this ensures the coin's spending conditions can't be changed.

### 3. amount binding (v2.0)

`amount` is included in the nullifier (v2.0 addition). this prevents attacks where an attacker could create multiple coins with the same serial_number but different amounts, then try to spend one to invalidate the others.

### 4. unlinkability

- serial_randomness is NOT in nullifier → nullifier doesn't reveal which coin_commitment was spent
- different nonces per payment → outputs are unlinkable
- merkle membership proves coin exists without revealing which one

### 5. hiding

- serial_number hidden inside ZK proof
- coin_commitment hides amount, puzzle_hash (can be revealed or kept private)
- only nullifier is public

## domain separation

all hash operations use domain prefixes to prevent cross-protocol attacks:

| operation | domain prefix |
|-----------|---------------|
| serial_commitment | `"clvm_zk_serial_v1.0"` |
| coin_commitment | `"clvm_zk_coin_v2.0"` |
| nullifier | (no prefix, direct concatenation) |

## v2.0 changes

v2.0 added:

1. **amount in nullifier**: `nullifier = hash(serial_number || program_hash || amount)` instead of just `hash(serial_number || program_hash)`. this prevents amount-hiding attacks.

2. **tail_hash in coin_commitment**: distinguishes XCH from CATs. `tail_hash = [0; 32]` for native XCH, `hash(TAIL_program)` for CATs.

## code references

key implementations:

```
clvm_zk_core/src/lib.rs:
  - compute_serial_commitment()
  - compute_coin_commitment()
  - compute_nullifier()

clvm_zk_core/src/coin_commitment.rs:
  - SerialCommitment
  - CoinCommitment
  - CoinSecrets

backends/risc0/guest/src/main.rs:
  - nullifier verification in guest
```

## wallet requirements

**CRITICAL: losing serial_number or serial_randomness means permanent coin loss.**

wallets must:
1. derive secrets deterministically from seed (for recovery)
2. backup seed phrase securely
3. track which indices have been used

for stealth addresses, secrets are derived from `shared_secret`:
```
coin_secret = hash("veil_stealth_nullifier_v1" || shared_secret)
serial_number = hash(coin_secret || "serial")
serial_randomness = hash(coin_secret || "rand")
```

## security considerations

1. **serial_number uniqueness**: must be unique per coin. HD derivation ensures this.

2. **serial_randomness privacy**: keeps serial_number hidden in commitment. never reveal.

3. **merkle tree attacks**: tree depth bounded (max 64) to prevent DoS.

4. **replay attacks**: nullifier set is append-only, checked before accepting spends.

5. **front-running**: nullifier revealed in mempool could be front-run. use commit-reveal or encrypted mempool.

## comparison to other systems

| system | nullifier scheme | hiding |
|--------|------------------|--------|
| zcash | `hash(note_commitment)` | yes |
| tornado cash | `hash(secret \|\| nullifier_secret)` | yes |
| veil | `hash(serial_number \|\| program_hash \|\| amount)` | yes |

veil's scheme includes program_hash to bind nullifier to specific puzzle logic, enabling programmable spending conditions.
