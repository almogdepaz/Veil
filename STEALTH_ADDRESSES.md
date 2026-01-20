# Stealth Addresses in Veil

Dual-key stealth address protocol for private payments without out-of-band communication.

## Overview

Stealth addresses allow a sender to create a payment that only the intended receiver can find and spend, without requiring any interaction. The receiver publishes a single stealth address and can receive unlimited unlinkable payments to it.

## Key Structure

Each wallet has two keypairs:

| keypair | private | public | purpose |
|---------|---------|--------|---------|
| view | `v` | `V = v*G` | scan for incoming payments |
| spend | `s` | `S = s*G` | authorize spending |

**Stealth address** (published): `(V, S)` - 66 bytes total (33 + 33 compressed secp256k1)

## Protocol

### Sender Creates Payment

```
INPUT:
  - receiver's stealth address: (V, S)
  - amount to send
  - tail_hash (asset type)

DERIVE:
  1. ephemeral_secret = random_scalar()
  2. ephemeral_pubkey = ephemeral_secret * G
  3. shared_secret = ephemeral_secret * V                    // ECDH
  4. derived_pubkey = S + hash("veil_stealth_v1" || shared_secret || "spend") * G
  5. puzzle_hash = hash(standard_pay_to_pubkey_puzzle(derived_pubkey))

OUTPUT:
  - coin with puzzle_hash and amount
  - ephemeral_pubkey (stored on-chain with coin)
```

### Receiver Scans for Payments

```
INPUT:
  - view_privkey: v
  - spend_pubkey: S
  - list of (coin_commitment, ephemeral_pubkey) from blockchain

FOR EACH (coin, ephemeral_pubkey):
  1. shared_secret = v * ephemeral_pubkey                   // ECDH (same result as sender)
  2. derived_pubkey = S + hash("veil_stealth_v1" || shared_secret || "spend") * G
  3. expected_puzzle_hash = hash(standard_pay_to_pubkey_puzzle(derived_pubkey))
  4. IF coin.puzzle_hash == expected_puzzle_hash:
       → this coin is ours, save (coin, shared_secret) to wallet

NOTE: scanning only requires view key (v), not spend key (s)
```

### Receiver Spends Coin

```
INPUT:
  - view_privkey: v
  - spend_privkey: s
  - coin to spend
  - ephemeral_pubkey (saved during scan)

DERIVE:
  1. shared_secret = v * ephemeral_pubkey
  2. derived_privkey = s + hash("veil_stealth_v1" || shared_secret || "spend")

SPEND:
  - sign with derived_privkey
  - create proof as normal
```

## ECDH Math

The protocol relies on ECDH producing the same shared_secret for sender and receiver:

```
sender computes:   ephemeral_secret * V = ephemeral_secret * (v * G)
receiver computes: v * ephemeral_pubkey = v * (ephemeral_secret * G)

both equal: ephemeral_secret * v * G ✓
```

## Key Derivation Details

**Shared secret to scalar:**
```
derive_scalar = hash("veil_stealth_v1" || shared_secret || "spend")
```

**Derived keypair:**
```
derived_pubkey  = S + derive_scalar * G
derived_privkey = s + derive_scalar
```

This is additive key derivation - standard technique used in BIP32, Monero, etc.

## On-Chain Data

Each coin needs an associated `ephemeral_pubkey` for the receiver to scan. Options:

| approach | storage | privacy |
|----------|---------|---------|
| memo field | 33 bytes per coin | ephemeral visible, unlinkable |
| separate announcement | 33 bytes | same |
| encrypted in commitment | complex | better but overkill |

**Recommended:** store ephemeral_pubkey in a memo/tag field alongside coin_commitment.

## Wallet Structure

```
WalletKeys {
    view_privkey: [u8; 32],
    view_pubkey: [u8; 33],      // compressed
    spend_privkey: [u8; 32],
    spend_pubkey: [u8; 33],     // compressed
}

StealthAddress {
    view_pubkey: [u8; 33],
    spend_pubkey: [u8; 33],
}

// For each received coin, store:
ReceivedCoin {
    coin: PrivateCoin,
    shared_secret: [u8; 32],    // needed to derive spending key
    ephemeral_pubkey: [u8; 33], // for reference
}
```

## View Key Capabilities

| operation | view key only | view + spend |
|-----------|---------------|--------------|
| scan for payments | ✅ | ✅ |
| see amounts | ✅ | ✅ |
| see sender (ephemeral) | ✅ | ✅ |
| spend coins | ❌ | ✅ |

Give view key to auditors, watch-only wallets, tax software without spending risk.

## Privacy Properties

| property | guarantee |
|----------|-----------|
| receiver unlinkability | each payment has unique puzzle_hash |
| sender anonymity | ephemeral_pubkey doesn't reveal sender identity |
| amount hiding | hidden in coin_commitment |
| forward secrecy | compromise one derived_key reveals only that payment |
| scanning privacy | only view_key holder can identify payments |

## Implementation

Stealth addresses are fully implemented in `src/wallet/stealth.rs`:

```rust
// Key types
StealthKeys        // view_privkey + spend_privkey (wallet stores)
StealthAddress     // view_pubkey + spend_pubkey (public, 66 bytes)
StealthViewKey     // view_privkey + spend_pubkey (for auditors)
StealthCoinData    // shared_secret + ephemeral_pubkey (per-coin)

// Functions
create_stealth_payment(&StealthAddress) -> StealthPayment
StealthViewKey::scan_coins(&[(puzzle_hash, ephemeral_pubkey)]) -> Vec<found>
StealthKeys::derive_spend_key(&shared_secret) -> [u8; 32]
```

**Simulator usage:**
```bash
cargo run-mock -- sim wallet alice create    # creates stealth address
cargo run-mock -- sim send alice bob 1000 --coins 0
cargo run-mock -- sim scan bob               # finds stealth payments
```

## Cryptographic Primitives

All primitives already available in Veil:

| primitive | crate | usage |
|-----------|-------|-------|
| secp256k1 points | `k256` | key derivation, ECDH |
| sha256 | `sha2` | domain-separated hashing |
| scalar arithmetic | `k256` | additive key derivation |

No new dependencies required.

## Security Considerations

1. **ephemeral_secret must be random** - reuse breaks unlinkability
2. **domain separation** - all hashes prefixed with "veil_stealth_v1"
3. **view key != spend key** - compromise view key doesn't allow spending
4. **shared_secret storage** - wallet must persist shared_secret to spend later
