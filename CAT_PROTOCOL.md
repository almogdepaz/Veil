# CAT Protocol in Veil

This document describes how Chia Asset Tokens (CATs) work in Veil's privacy-preserving system.

## Overview

Veil supports CATs using the same `tail_hash` asset identification as Chia, but with privacy-preserving modifications to the commitment and announcement schemes.

## Asset Identification

| Asset Type | tail_hash |
|------------|-----------|
| XCH (native) | `[0u8; 32]` (all zeros) |
| CAT | `hash(TAIL_program)` |

Coins with different `tail_hash` values cannot be mixed in the same ring spend - this is enforced in the zkVM guest.

## Commitment Scheme (v2)

```
coin_commitment = hash(
    "clvm_zk_coin_v2.0" ||
    tail_hash ||           // 32 bytes - asset identifier
    amount ||              // 8 bytes
    puzzle_hash ||         // 32 bytes
    serial_commitment      // 32 bytes
)
```

The `tail_hash` is included in the commitment, binding each coin to its asset type.

## Ring Spends

Multiple coins can be spent atomically in a single proof. Requirements:
- All coins must share the same `tail_hash`
- Each coin produces its own nullifier
- Announcements are verified across all coins in the ring

## Announcement Handling

### Chia vs Veil coin_id

Chia uses `coin_id = hash(parent_coin_id || puzzle_hash || amount)` for coin announcements. This creates a public transaction graph since each coin references its parent.

Veil uses `coin_commitment` as the coin identifier for announcements. This uniquely identifies each coin without revealing transaction lineage, preserving privacy.

### Supported Announcements

| Opcode | Condition | Hash Formula |
|--------|-----------|--------------|
| 60 | CREATE_COIN_ANNOUNCEMENT | `hash(coin_commitment \|\| message)` |
| 61 | ASSERT_COIN_ANNOUNCEMENT | verifies hash exists in set |
| 62 | CREATE_PUZZLE_ANNOUNCEMENT | `hash(puzzle_hash \|\| message)` |
| 63 | ASSERT_PUZZLE_ANNOUNCEMENT | verifies hash exists in set |

### Verification Flow

1. Each coin computes its announcement hashes using its own identifiers
2. All announcement hashes collected across the ring
3. All assertions verified against combined hash sets
4. Announcement conditions filtered from output (verified internally, not exposed publicly)

## Nullifier Scheme

```
nullifier = hash(serial_number || program_hash || amount)
```

Each coin in a ring produces its own nullifier. The nullifier set prevents double-spending without revealing which specific coin was spent.

## Privacy Properties

| Property | How Achieved |
|----------|--------------|
| Hidden amounts | Commitment hides amount |
| Hidden asset type | Commitment hides tail_hash |
| Hidden transaction graph | No parent_coin_id reference |
| Unlinkable spends | Nullifier doesn't link to commitment |
| Ring anonymity | Can't determine coin boundaries in proof |

## Differences from Chia CAT2

| Aspect | Chia CAT2 | Veil |
|--------|-----------|------|
| Announcements | Public on-chain | Verified in zkVM, hidden |
| coin_id | `hash(parent \|\| puzzle \|\| amount)` | `coin_commitment` |
| Ring accounting | Public delta verification | Private delta verification |
| CREATE_COIN output | Public (puzzle, amount) | Commitment only |
| Transaction graph | Fully visible | Broken by nullifiers |

## TAIL Programs

TAIL (Token and Asset Issuance Limitations) programs control minting and burning:
- Same Chialisp TAIL programs as Chia
- Evaluated inside zkVM guest
- `extra_delta != 0` triggers TAIL execution
- TAIL conditions verified internally

## Data Flow

```
Host constructs Input:
  - primary coin (puzzle, solution, secrets, merkle proof)
  - additional_coins[] for ring spends
  - tail_hash (None = XCH)

Guest processes:
  1. Compile and execute each coin's puzzle
  2. Verify merkle membership for each coin
  3. Compute nullifier for each coin
  4. Collect and verify announcements across ring
  5. Transform CREATE_COIN → commitments
  6. Filter announcement conditions

Output:
  - program_hash (primary coin)
  - nullifiers[] (one per coin)
  - transformed conditions (commitments only)
```
