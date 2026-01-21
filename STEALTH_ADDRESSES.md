# stealth addresses in veil (nullifier mode)

dual-key stealth address protocol for private payments without out-of-band communication.

## overview

stealth addresses allow a sender to create a payment that only the intended receiver can find and spend, without requiring any interaction. the receiver publishes a single stealth address and can receive unlimited unlinkable payments to it.

## security model

**IMPORTANT:** veil uses nullifier protocol for authorization, NOT signatures. the stealth address protocol provides:
- payment privacy (ECDH-based)
- scanning capability (view key separation)

authorization security comes from the nullifier protocol (serial_number commitment), not from puzzle logic or signatures.

## key structure

each wallet has two keypairs:

| keypair | private | public | purpose |
|---------|---------|--------|---------|
| view | `v` | `V = v*G` | scan for incoming payments |
| spend | `s` | `S = s*G` | currently unused (future custody) |

**stealth address** (published): `(V, S)` - 66 bytes total (33 + 33 compressed secp256k1)

## protocol

### sender creates payment

```
INPUT:
  - receiver's stealth address: (V, S)
  - amount to send
  - tail_hash (asset type)

DERIVE:
  1. ephemeral_secret = random_scalar()               // TODO: make HD-derived
  2. ephemeral_pubkey = ephemeral_secret * G
  3. shared_secret = ephemeral_secret * V             // ECDH
  4. coin_secret = hash("veil_stealth_nullifier_v1" || shared_secret)
  5. serial_number = hash(coin_secret || "serial")
  6. serial_randomness = hash(coin_secret || "rand")

OUTPUT:
  - coin with puzzle_hash = STEALTH_NULLIFIER_PUZZLE_HASH  // shared by all stealth coins
  - ephemeral_pubkey (stored on-chain with coin)
```

**KEY POINT:** all nullifier-mode stealth coins share the SAME puzzle_hash. unlinkability comes from different ephemeral_pubkey values and ECDH, NOT from unique puzzles.

### receiver scans for payments

```
INPUT:
  - view_privkey: v
  - spend_pubkey: S (currently unused, reserved for future custody mode)
  - list of (coin_commitment, ephemeral_pubkey) from blockchain

FOR EACH (coin, ephemeral_pubkey):
  1. shared_secret = v * ephemeral_pubkey           // ECDH (same result as sender)
  2. check if coin.puzzle_hash == STEALTH_NULLIFIER_PUZZLE_HASH
  3. IF match:
       → this coin is ours, save (coin, shared_secret) to wallet

NOTE: scanning only requires view key (v)
```

### receiver spends coin

```
INPUT:
  - view_privkey: v
  - coin to spend
  - ephemeral_pubkey (saved during scan)

DERIVE:
  1. shared_secret = v * ephemeral_pubkey
  2. coin_secret = hash("veil_stealth_nullifier_v1" || shared_secret)
  3. serial_number = hash(coin_secret || "serial")
  4. serial_randomness = hash(coin_secret || "rand")

SPEND:
  - use serial_number + serial_randomness in nullifier protocol
  - create ZK proof (no signature verification, just nullifier)
  - reveal nullifier = hash(serial_number || program_hash || amount)
```

## ECDH math

the protocol relies on ECDH producing the same shared_secret for sender and receiver:

```
sender computes:   ephemeral_secret * V = ephemeral_secret * (v * G)
receiver computes: v * ephemeral_pubkey = v * (ephemeral_secret * G)

both equal: ephemeral_secret * v * G ✓
```

## nullifier mode details

**puzzle:**
```chialisp
(mod () ())  // trivial puzzle, always succeeds
```

**puzzle_hash:** deterministic constant `STEALTH_NULLIFIER_PUZZLE_HASH`

**security:** comes from nullifier protocol, not puzzle logic:
- serial_number + serial_randomness committed at creation
- nullifier = hash(serial_number || program_hash || amount) prevents double-spend
- ZK proof verifies coin ownership without revealing serial_number

**proving cost:** ~10K cycles (just hash operations, no signature verification)

**view key can spend:** yes, because serial secrets derive from shared_secret (view key holder knows this)

## on-chain data

each coin needs an associated `ephemeral_pubkey` for the receiver to scan:

| approach | storage | privacy |
|----------|---------|---------|
| memo field | 33 bytes per coin | ephemeral visible, unlinkable |
| separate announcement | 33 bytes | same |

**current implementation:** stored alongside coin in simulator metadata

## wallet structure

```rust
StealthKeys {
    view_privkey: [u8; 32],
    spend_privkey: [u8; 32],  // currently unused
}

StealthAddress {
    view_pubkey: [u8; 33],    // compressed secp256k1
    spend_pubkey: [u8; 33],   // reserved for future custody mode
}

// for each received coin, store:
ScannedStealthCoin {
    puzzle_hash: [u8; 32],           // always STEALTH_NULLIFIER_PUZZLE_HASH
    shared_secret: [u8; 32],         // needed to derive spending secrets
    ephemeral_pubkey: [u8; 33],      // for reference
    puzzle_source: String,           // trivial puzzle "(mod () ())"
}
```

## view key capabilities

| operation | view key only | view + spend |
|-----------|---------------|--------------|
| scan for payments | ✅ | ✅ |
| see amounts | ✅ | ✅ |
| see sender (ephemeral) | ✅ | ✅ |
| spend coins | ✅ | ✅ |

**NOTE:** in nullifier mode, view key holder CAN spend. this is by design for fast proving. view/spend separation would require a different authorization mode (not currently implemented).

give view key to auditors = they can see AND spend your coins. for audit-only access, use a different approach.

## privacy properties

| property | guarantee |
|----------|-----------|
| receiver unlinkability | different ephemeral_pubkey per payment |
| sender anonymity | ephemeral_pubkey doesn't reveal sender identity |
| amount hiding | hidden in coin_commitment |
| forward secrecy | compromise one shared_secret reveals only that payment |
| scanning privacy | only view_key holder can compute shared_secret |

**note:** all stealth coins share same puzzle_hash. this DOES NOT break privacy because ephemeral keys are unique.

## implementation

stealth addresses are implemented in `src/wallet/stealth.rs`:

**simulator usage:**
```bash
cargo run-mock -- sim wallet alice create    # creates stealth address
cargo run-mock -- sim send alice bob 1000 --coins 0
cargo run-mock -- sim scan bob               # finds stealth payments
```

## cryptographic primitives

all primitives already available in veil:

| primitive | crate | usage |
|-----------|-------|-------|
| secp256k1 points | `k256` | ECDH |
| sha256 | `sha2` | domain-separated hashing |
| scalar arithmetic | `k256` | point multiplication |

no new dependencies required.

## security considerations

1. **ephemeral_secret must be random** - reuse breaks unlinkability
   - ⚠️ CURRENT: uses thread_rng (not HD-derived)
   - 🔜 TODO: derive deterministically from master seed + counter

2. **domain separation** - all hashes prefixed with "veil_stealth_nullifier_v1"

3. **view key gives spending capability** - compromise view key = attacker can spend

4. **shared_secret storage** - wallet must persist shared_secret to derive spending secrets later

5. **nullifier protocol security** - depends on serial_number uniqueness (enforced by HD derivation in non-stealth mode)

## comparison to monero stealth addresses

| aspect | monero | veil |
|--------|--------|------|
| key derivation | additive (R*a*G + B) | ECDH + hash derivation |
| authorization | ECDSA signature | nullifier protocol (hash-based) |
| proving cost | ~high (signature verification) | ~10K cycles (hash only) |
| view key separation | view cannot spend | view CAN spend (nullifier mode) |
| puzzle diversity | unique per coin | shared constant puzzle |

## limitations

1. **no view/spend separation** in nullifier mode - view key holder can spend

2. **ephemeral key randomness** - currently uses RNG, should be HD-derived for recovery

3. **no custody mode** - spend_pubkey reserved but not used

4. **memo field required** - ephemeral_pubkey must be stored somewhere on-chain

## future work

- implement HD derivation for ephemeral keys (phase 2)
- add signature-based custody mode (requires ECDSA in-circuit)
- optimize scanning with bloom filters
- batch ECDH for faster scanning
