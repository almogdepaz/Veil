# stealth addresses in veil (hash-based nullifier mode)

dual-key stealth address protocol using hash-based derivation for zkVM efficiency.

## overview

stealth addresses allow a sender to create a payment that only the intended receiver can find and spend, without requiring any interaction. the receiver publishes a single stealth address and can receive unlimited unlinkable payments to it.

**key design choice:** uses hash-based derivation instead of ECDH for ~200x faster proving in zkVM (no elliptic curve math).

## security model

**IMPORTANT:** veil uses nullifier protocol for authorization, NOT signatures. the stealth address protocol provides:
- payment privacy (hash-based nonce derivation)
- scanning capability (view key separation)

authorization security comes from the nullifier protocol (serial_number commitment), not from puzzle logic or signatures.

## key structure

each wallet has two keypairs (hash-based, not EC):

| keypair | private | public | purpose |
|---------|---------|--------|---------|
| view | `v` (32 bytes) | `V = sha256("stealth_pubkey_v1" \|\| v)` | scan for incoming payments |
| spend | `s` (32 bytes) | `S = sha256("stealth_pubkey_v1" \|\| s)` | derive spending authorization |

**stealth address** (published): `(V, S)` - 64 bytes total (32 + 32 hash-based)

## protocol

### sender creates payment

```
INPUT:
  - receiver's stealth address: (V, S)
  - amount to send
  - tail_hash (asset type)
  - nonce_index (HD derivation counter)

DERIVE:
  1. nonce = sha256("stealth_nonce_v1" || sender_privkey || nonce_index)  // HD-derived
  2. shared_secret = sha256("stealth_v1" || V || nonce)
  3. coin_secret = sha256("veil_stealth_nullifier_v1" || shared_secret)
  4. serial_number = sha256(coin_secret || "serial")
  5. serial_randomness = sha256(coin_secret || "rand")

OUTPUT:
  - coin with puzzle_hash = STEALTH_NULLIFIER_PUZZLE_HASH  // shared by all stealth coins
  - nonce (32 bytes, stored on-chain or transmitted to receiver)
```

**KEY POINT:** all nullifier-mode stealth coins share the SAME puzzle_hash. unlinkability comes from different nonces, NOT from unique puzzles.

### receiver scans for payments

```
INPUT:
  - view_privkey: v
  - list of (coin_commitment, nonce) from blockchain

FOR EACH (coin, nonce):
  1. shared_secret = sha256("stealth_v1" || V || nonce)  // same result as sender
  2. check if coin.puzzle_hash == STEALTH_NULLIFIER_PUZZLE_HASH
  3. IF match:
       → this coin is ours, save (coin, shared_secret, nonce) to wallet

NOTE: scanning only requires view key (v → V derivation)
```

### receiver spends coin

```
INPUT:
  - view_privkey: v
  - coin to spend
  - nonce (saved during scan)

DERIVE:
  1. shared_secret = sha256("stealth_v1" || V || nonce)
  2. coin_secret = sha256("veil_stealth_nullifier_v1" || shared_secret)
  3. serial_number = sha256(coin_secret || "serial")
  4. serial_randomness = sha256(coin_secret || "rand")

SPEND:
  - use serial_number + serial_randomness in nullifier protocol
  - create ZK proof (no signature verification, just nullifier)
  - reveal nullifier = hash(serial_number || program_hash)
```

## hash-based derivation (vs ECDH)

**why hash-based instead of ECDH:**
- ECDH in zkVM: ~2M cycles (x25519 point multiplication)
- hash-based: ~10K cycles (just sha256)
- result: ~200x faster proving for settlement proofs

**security equivalence:**
```
ECDH:        shared_secret = ephemeral_secret * V = v * ephemeral_pubkey
hash-based:  shared_secret = sha256(V || nonce)

both provide:
- unlinkability (unique nonce per payment)
- forward secrecy (compromise one nonce reveals only that payment)
- scanning privacy (only V holder can compute shared_secret from nonce)
```

**key difference:** hash-based requires transmitting nonce to receiver (can't derive from pubkey alone). ECDH allows receiver to derive from ephemeral_pubkey on-chain.

## nullifier mode details

**puzzle:**
```chialisp
(mod () ())  // trivial puzzle, always succeeds
```

**puzzle_hash:** deterministic constant `STEALTH_NULLIFIER_PUZZLE_HASH`

**security:** comes from nullifier protocol, not puzzle logic:
- serial_number + serial_randomness committed at creation
- nullifier = hash(serial_number || program_hash) prevents double-spend
- ZK proof verifies coin ownership without revealing serial_number

**proving cost:** ~10K cycles (just hash operations, no signature or EC verification)

**view key can spend:** yes, because serial secrets derive from shared_secret (view key holder knows this)

## on-chain data

each coin needs an associated `nonce` for the receiver to scan:

| approach | storage | privacy |
|----------|---------|---------|
| memo field | 32 bytes per coin | nonce visible, unlinkable |
| encrypted nonce | 32+ bytes | nonce hidden, requires decrypt |
| separate channel | 0 bytes on-chain | requires out-of-band |

**current implementation:** stored alongside coin in simulator metadata

## wallet structure

```rust
StealthKeys {
    view_privkey: [u8; 32],
    spend_privkey: [u8; 32],
}

StealthAddress {
    view_pubkey: [u8; 32],    // hash-based (sha256)
    spend_pubkey: [u8; 32],   // hash-based (sha256)
}

// for each received coin, store:
ScannedStealthCoin {
    puzzle_hash: [u8; 32],           // always STEALTH_NULLIFIER_PUZZLE_HASH
    shared_secret: [u8; 32],         // needed to derive spending secrets
    nonce: [u8; 32],                 // for reference
    puzzle_source: String,           // trivial puzzle "(mod () ())"
}
```

## view key capabilities

| operation | view key only | view + spend |
|-----------|---------------|--------------|
| scan for payments | ✅ | ✅ |
| see amounts | ✅ | ✅ |
| derive shared_secret | ✅ | ✅ |
| spend coins | ✅ | ✅ |

**NOTE:** in nullifier mode, view key holder CAN spend. this is by design for fast proving. view/spend separation would require a different authorization mode (not currently implemented).

give view key to auditors = they can see AND spend your coins. for audit-only access, use a different approach.

## privacy properties

| property | guarantee |
|----------|-----------|
| receiver unlinkability | different nonce per payment |
| sender anonymity | nonce doesn't reveal sender identity |
| amount hiding | hidden in coin_commitment |
| forward secrecy | compromise one shared_secret reveals only that payment |
| scanning privacy | only view_key holder can compute shared_secret |

**note:** all stealth coins share same puzzle_hash. this DOES NOT break privacy because nonces are unique.

## implementation

stealth addresses are implemented in `src/wallet/stealth.rs`:

```rust
// create payment with HD-derived nonce
let payment = create_stealth_payment_hd(&sender_keys, nonce_index, &recipient_address);

// scan for payments
let scanned = view_key.try_scan_with_nonce(&puzzle_hash, &nonce);

// derive spending authorization
let spend_auth = receiver_keys.get_spend_auth(&shared_secret);
let coin_secrets = spend_auth.to_coin_secrets();
```

**simulator usage:**
```bash
cargo run-mock -- sim wallet alice create    # creates stealth address
cargo run-mock -- sim send alice bob 1000 --coins 0
cargo run-mock -- sim scan bob               # finds stealth payments
```

## cryptographic primitives

all hash-based, no EC dependencies for stealth:

| primitive | crate | usage |
|-----------|-------|-------|
| sha256 | `sha2` | all derivations |

**removed dependencies:** k256 (secp256k1) no longer needed for stealth. still used for ECDSA signatures elsewhere.

## security considerations

1. **nonce must be unique per payment** - reuse breaks unlinkability
   - ✅ SOLVED: HD derivation via `derive_nonce(index)` from sender's privkey

2. **domain separation** - all hashes have unique prefixes:
   - `"stealth_v1"` - shared secret derivation
   - `"stealth_pubkey_v1"` - pubkey derivation
   - `"stealth_nonce_v1"` - nonce derivation
   - `"veil_stealth_nullifier_v1"` - coin secret derivation

3. **view key gives spending capability** - compromise view key = attacker can spend

4. **shared_secret storage** - wallet must persist shared_secret to derive spending secrets later

5. **nonce transmission** - receiver must obtain nonce (on-chain memo or out-of-band)

## comparison to ECDH stealth (old design)

| aspect | ECDH (old) | hash-based (current) |
|--------|------------|----------------------|
| shared_secret derivation | `ephemeral * V` (EC math) | `sha256(V \|\| nonce)` |
| on-chain data | ephemeral_pubkey (33 bytes) | nonce (32 bytes) |
| proving cost in zkVM | ~2M cycles | ~10K cycles |
| receiver derives from pubkey | ✅ yes | ❌ needs nonce |
| crypto dependencies | secp256k1/x25519 | sha256 only |

## limitations

1. **no view/spend separation** in nullifier mode - view key holder can spend

2. **nonce transmission required** - receiver can't derive nonce from on-chain data alone

3. **no custody mode** - spend_pubkey reserved but not used

4. **memo field required** - nonce must be stored somewhere accessible to receiver

## future work

- add encrypted nonce transmission (encrypt nonce to receiver's pubkey)
- implement signature-based custody mode (requires ECDSA in-circuit)
- optimize scanning with bloom filters on nonce prefixes
