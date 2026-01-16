# Chia-Standard CLVM Opcodes

This document describes the opcode changes made to align Veil's CLVM implementation with the Chia blockchain standard, enabling compatibility with `clvmr` (the reference Rust CLVM implementation).

## Overview

Veil originally used ASCII-based opcodes (e.g., `+` = 43, `q` = 113) for readability. These have been changed to Chia-standard numeric opcodes to enable:

1. **clvmr compatibility** - Use the battle-tested Chia CLVM runtime
2. **Ecosystem alignment** - Bytecode compatible with Chia tooling
3. **Future-proofing** - Easier to adopt Chia ecosystem improvements

## Opcode Mapping

### Core CLVM Operators

| Operator | Symbol | Old (ASCII) | New (Chia) | Description |
|----------|--------|-------------|------------|-------------|
| Quote | q | 113 | 1 | Return argument unevaluated |
| Apply | a | 97 | 2 | Apply function to arguments |
| If | i | 105 | 3 | Conditional branch |
| Cons | c | 99 | 4 | Construct pair |
| First | f | 102 | 5 | Get first element of pair |
| Rest | r | 114 | 6 | Get rest of pair |
| ListP | l | 108 | 7 | Check if value is a pair |

### Comparison Operators

| Operator | Symbol | Old (ASCII) | New (Chia) | Description |
|----------|--------|-------------|------------|-------------|
| Equal | = | 61 | 9 | Equality comparison |
| Greater | > | 62 | 21 | Greater than comparison |

### Arithmetic Operators

| Operator | Symbol | Old (ASCII) | New (Chia) | Description |
|----------|--------|-------------|------------|-------------|
| Add | + | 43 | 16 | Addition |
| Subtract | - | 45 | 17 | Subtraction |
| Multiply | * | 42 | 18 | Multiplication |
| Divide | / | 47 | 19 | Division |
| DivMod | divmod | 80 | 20 | Division with modulo |
| Modulo | % | 37 | 61 | Modulo operation |

### Cryptographic Operators

| Operator | Old | New (Chia) | Description |
|----------|-----|------------|-------------|
| SHA256 | 2 | 11 | SHA-256 hash |
| BLS Verify | 201 | 59 | BLS signature verification |
| ECDSA Verify | 200 | 200 | ECDSA signature verification (unchanged) |

### Condition Opcodes (Unchanged)

These are Chia condition opcodes used in puzzle outputs, not CLVM operators:

| Condition | Opcode | Description |
|-----------|--------|-------------|
| AGG_SIG_UNSAFE | 49 | Aggregate signature (unsafe) |
| AGG_SIG_ME | 50 | Aggregate signature (with coin ID) |
| CREATE_COIN | 51 | Create new coin |
| RESERVE_FEE | 52 | Reserve transaction fee |

### Veil-Specific Opcodes

| Operator | Opcode | Description |
|----------|--------|-------------|
| CallFunction | 150 | Runtime function call (for defun support) |

## Files Modified

### `clvm_zk_core/src/operators.rs`

- Updated `ClvmOperator::opcode()` to return Chia-standard values
- Updated `ClvmOperator::from_opcode()` to parse Chia-standard values
- Updated tests to use new opcodes

### `clvm_zk_core/src/chialisp/mod.rs`

- Changed hardcoded opcodes to use `ClvmOperator::opcode()`
- Updated `create_parameter_access()` to use dynamic opcodes
- Updated test assertions for new opcode values

### `clvm_zk_core/src/chialisp/compiler_utils.rs`

- Changed `quote_value()` to use `ClvmOperator::Quote.opcode()`
- Updated test to use `ClvmOperator::Add.opcode()`

### `clvm_zk_core/src/lib.rs`

- Updated SHA256 opcode from 2 to 11 in evaluator

## Bytecode Format

CLVM bytecode uses a simple encoding:

- `0x00-0x7F`: Small atoms (literal values 0-127)
- `0x80`: Nil (empty atom)
- `0x81-0xBF`: Atom with 1-64 byte length prefix
- `0xFF`: Cons pair marker

Example bytecode for `(+ 5 3)`:

```
Old (ASCII): [255, 43, 255, 255, 113, 5, 255, 255, 113, 3, 128]
New (Chia):  [255, 16, 255, 255,  1, 5, 255, 255,  1, 3, 128]
             [cons, +, cons, cons, q, 5, cons, cons, q, 3, nil]
```

## Migration Notes

### For Existing Bytecode

Any bytecode compiled with the old ASCII opcodes will NOT work with the new evaluator. Bytecode must be recompiled from source.

### For clvmr Integration

The opcode changes make Veil bytecode compatible with clvmr. However:

1. **CallFunction (150)** is Veil-specific and not supported by clvmr
2. Programs using `defun` will need a translation layer or function inlining

### Testing

All 69 clvm-zk-core tests pass with the new opcodes:

```bash
cargo test -p clvm-zk-core --features sha2-hasher
```

## References

- [Chia CLVM Reference](https://chialisp.com/docs/ref/clvm)
- [clvmr Repository](https://github.com/Chia-Network/clvm_rs)
- [CLVM Operator Costs](https://docs.chia.net/clvm-costs/)
