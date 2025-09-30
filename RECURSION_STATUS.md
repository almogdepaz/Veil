# Recursion Support Implementation Status

This document tracks the current state of recursive function support in clvm-zk. If you're joining to help with this implementation, this will get you up to speed quickly.

## Current Problem

We're implementing support for recursive Chialisp functions like:

```chialisp
(mod (n)
    (defun factorial (x)
        (if (= x 0)
            1
            (* x (factorial (- x 1)))))
    (factorial n)
)
```

## What Works ✅

- **Function compilation**: Functions compile successfully and create proper function tables
- **Simple function calls**: Non-recursive functions like `(defun double (n) (* n 2))` work perfectly
- **Conditional logic**: `if` statements work fine in functions
- **Mock backend logging**: We have detailed execution logs for debugging
- **✅ FIXED - Core recursion bug**: Constant `1` no longer incorrectly treated as environment reference
- **✅ FIXED - Function environment**: Parameter access via `(f 1)` now works correctly
- **✅ FIXED - Context awareness**: Environment references properly distinguished from literal constants

## Current Status 🎯

**ALL CORE FUNCTION BUGS RESOLVED!** Functions now work correctly. The remaining work is recursion implementation itself.
```

### Reproduction
- ✅ `(* n 2)` works fine
- ❌ `(* n 1)` fails with "cannot convert cons pair to number"
- ❌ `(* x (factorial (- x 1)))` fails (probably due to the same issue)

### Test Results
```bash
# Works fine
(defun test_if (n) (if (= n 0) 1 (* n 2)))

# Fails with cons pair error
(defun factorial_like (n) (if (= n 0) 1 (* n 1)))
```

## Architecture Overview

### Function Call Flow
1. **Compilation**: `compile_chialisp_with_function_table()` → bytecode + function table
2. **Execution**: `ClvmEvaluator` with function table handles `CallFunction` opcode (150)
3. **Function calls**: `handle_op_call_function()` processes function calls at runtime

### Key Files
- `clvm_zk_core/src/lib.rs:937` - `handle_op_call_function()`
- `backends/mock/src/backend.rs` - Mock backend with detailed logging
- `tests/test_mock_recursion.rs` - Test cases
- `clvm_zk_core/src/chialisp/mod.rs` - Function compilation

### Function Call Mechanism
```rust
// Opcode 150: CallFunction
// Format: (call_function "function_name" arg1 arg2 ...)
ClvmOperator::CallFunction => self.handle_op_call_function(args, conditions, parameters)
```

## Recent Changes ✅

1. **Fixed parameter conversion**: Updated `handle_op_call_function()` to better convert `ClvmValue` to `ProgramParameter`
2. **Added `clvm_value_to_number()`**: Reverse function to convert CLVM values back to integers
3. **Improved argument evaluation**: Function arguments are now evaluated before conversion

## Debugging Tools 🔧

### Mock Backend Logs
Execution logs are saved to `target/mock_logs/mock_execution_*.log` with detailed debugging info:
```
=== MOCK BACKEND EXECUTION LOG ===
Chialisp Source: ...
Parameters: [Int(3)]
✅ Compilation successful
Program hash: "..."
Function table: 1 functions
=== EXECUTION START ===
❌ EXECUTION ERROR: clvm execution failed: "cannot convert cons pair to number"
```

### Quick Test Commands
```bash
# Test simple functions
cargo test --test test_mock_recursion test_mock_simple_function --no-default-features --features mock,testing -- --nocapture

# Test the multiplication-by-1 bug
cargo test --test test_mock_recursion test_mock_factorial_like_non_recursive --no-default-features --features mock,testing -- --nocapture

# Test recursive factorial
cargo test --test test_mock_recursion test_mock_recursive_factorial --no-default-features --features mock,testing -- --nocapture
```

## Next Steps 🎯

1. **Debug the multiplication-by-1 bug**: Figure out why `(* n 1)` creates a cons pair instead of evaluating to a number
2. **Trace execution path**: Add more logging to see exactly where the cons pair is created
3. **Fix the evaluation**: Ensure arithmetic operations always produce atoms, not cons pairs
4. **Test recursion**: Once the basic bug is fixed, test actual recursive calls

## Hypotheses 💭

The issue might be in:
- **Operator precedence**: How `*` operation with constant `1` is compiled/evaluated
- **CLVM encoding**: How the constant `1` is represented in CLVM
- **Function parameter passing**: How arguments are passed between function calls
- **Environment handling**: How the CLVM environment is set up for function execution

## Code Architecture

### ClvmEvaluator Function Call Handler
```rust
pub fn handle_op_call_function(
    &self,
    args: &ClvmValue,
    conditions: &mut Vec<Condition>,
    parameters: &[ProgramParameter],
) -> Result<ClvmValue, &'static str>
```

### Function Table Structure
```rust
pub struct RuntimeFunction {
    pub parameters: Vec<String>,
    pub body: ClvmValue,
}

pub struct RuntimeFunctionTable {
    functions: BTreeMap<String, RuntimeFunction>,
}
```

### Mock Backend Features
- **No zkVM overhead**: Fast iteration for debugging
- **Detailed logging**: Every compilation and execution step logged
- **Exact same logic**: Uses the same core evaluation as real backends

## Current Todo Status
- [x] Fix function call argument evaluation
- [ ] Debug cons pair to number conversion error
- [ ] Update parameter conversion robustness
- [ ] Test recursive factorial execution
- [ ] Write recursion status documentation ← YOU ARE HERE

## Quick Start for New Contributors

1. Clone repo and run: `cargo test --test test_mock_recursion --no-default-features --features mock,testing -- --nocapture`
2. Check logs in `target/mock_logs/` to see the exact failure
3. The bug is in `clvm_zk_core/src/lib.rs` around the `handle_op_call_function()` method
4. Focus on why `(* n 1)` produces a cons pair instead of an integer atom

The mystery is: why does `(* 3 2)` work but `(* 3 1)` fail? This should be your starting point.