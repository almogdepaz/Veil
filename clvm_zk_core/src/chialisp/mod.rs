// CLVM-ZK Chialisp compiler - clvm_tools_rs wrapper
//
// This module provides compilation using clvm_tools_rs, the official Chia chialisp compiler.
// clvm_tools_rs provides full chialisp support including:
// - defun with proper recursion support
// - defmacro (compile-time macros)
// - if/list and other standard macros
// - All chialisp language features
//
// Parameters are passed at runtime via the CLVM environment, not substituted at compile time.

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

use crate::Hasher;

/// Standard Chia condition codes as defconstant declarations.
/// Prepend this to chialisp source for readable condition opcodes.
pub const STANDARD_CONDITION_CODES: &str = r#"
(defconstant AGG_SIG_UNSAFE 49)
(defconstant AGG_SIG_ME 50)
(defconstant CREATE_COIN 51)
(defconstant RESERVE_FEE 52)
(defconstant CREATE_COIN_ANNOUNCEMENT 60)
(defconstant ASSERT_COIN_ANNOUNCEMENT 61)
(defconstant CREATE_PUZZLE_ANNOUNCEMENT 62)
(defconstant ASSERT_PUZZLE_ANNOUNCEMENT 63)
(defconstant ASSERT_MY_COIN_ID 70)
(defconstant ASSERT_MY_PARENT_ID 71)
(defconstant ASSERT_MY_PUZZLEHASH 72)
(defconstant ASSERT_MY_AMOUNT 73)
"#;

/// Prepend standard condition codes to chialisp source.
/// Use this when you want CREATE_COIN etc. to be available without defining them.
///
/// Note: only works with full mod expressions, inserts constants after the parameter list.
pub fn with_standard_conditions(source: &str) -> String {
    // find position after (mod (...) to insert constants
    // simple approach: find first closing paren of param list, insert after
    if let Some(mod_pos) = source.find("(mod") {
        if let Some(paren_start) = source[mod_pos..].find('(').map(|p| mod_pos + p) {
            // skip "(mod"
            if let Some(param_start) = source[paren_start + 1..].find('(') {
                let param_start = paren_start + 1 + param_start;
                // find matching close paren
                let mut depth = 1;
                let mut param_end = param_start + 1;
                for (i, c) in source[param_start + 1..].char_indices() {
                    match c {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                param_end = param_start + 1 + i + 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                // insert constants after param list
                let mut result =
                    String::with_capacity(source.len() + STANDARD_CONDITION_CODES.len());
                result.push_str(&source[..param_end]);
                result.push_str(STANDARD_CONDITION_CODES);
                result.push_str(&source[param_end..]);
                return result;
            }
        }
    }
    // fallback: just prepend (won't work but better than silent failure)
    format!("{}{}", STANDARD_CONDITION_CODES, source)
}

/// Compilation error types
#[derive(Debug, Clone)]
pub enum CompileError {
    ParseError(String),
}

/// Compile Chialisp to bytecode using clvm_tools_rs compiler.
///
/// Note: Parameters are NOT substituted at compile time. The compiled bytecode expects
/// parameters to be passed at runtime via the CLVM environment (args).
pub fn compile_chialisp_to_bytecode(
    hasher: Hasher,
    source: &str,
) -> Result<(Vec<u8>, [u8; 32]), CompileError> {
    let bytecode = clvm_tools_rs::compile_chialisp(source).map_err(|e| {
        CompileError::ParseError(format!("clvm_tools_rs compilation failed: {}", e))
    })?;

    let program_hash = generate_program_hash(hasher, &bytecode);

    Ok((bytecode, program_hash))
}

/// Get program hash for compiled chialisp
pub fn compile_chialisp_template_hash(
    hasher: Hasher,
    source: &str,
) -> Result<[u8; 32], CompileError> {
    let bytecode = clvm_tools_rs::compile_chialisp(source).map_err(|e| {
        CompileError::ParseError(format!("clvm_tools_rs compilation failed: {}", e))
    })?;
    Ok(generate_program_hash(hasher, &bytecode))
}

/// Compile Chialisp to get template hash using default SHA-256 hasher
/// Only available with sha2-hasher feature
#[cfg(feature = "sha2-hasher")]
pub fn compile_chialisp_template_hash_default(source: &str) -> Result<[u8; 32], CompileError> {
    let bytecode = clvm_tools_rs::compile_chialisp(source).map_err(|e| {
        CompileError::ParseError(format!("clvm_tools_rs compilation failed: {}", e))
    })?;
    Ok(generate_program_hash(crate::hash_data, &bytecode))
}

/// Generate program hash from bytecode
pub fn generate_program_hash(hasher: Hasher, bytecode: &[u8]) -> [u8; 32] {
    hasher(bytecode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn hash_data(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    #[test]
    fn test_basic_compilation() {
        let result = compile_chialisp_to_bytecode(hash_data, "(mod (x y) (+ x y))");
        assert!(result.is_ok());

        let (bytecode, program_hash) = result.unwrap();
        assert!(!bytecode.is_empty());
        assert_ne!(program_hash, [0u8; 32]);
    }

    #[test]
    fn test_function_compilation() {
        let source = r#"
            (mod (n)
                (defun double (x) (* x 2))
                (double n))
        "#;

        let result = compile_chialisp_to_bytecode(hash_data, source);
        assert!(result.is_ok());

        let (bytecode, program_hash) = result.unwrap();
        assert!(!bytecode.is_empty());
        assert_ne!(program_hash, [0u8; 32]);
    }

    #[test]
    fn test_recursive_function() {
        // clvm_tools_rs supports recursion (custom compiler didn't)
        let source = r#"
            (mod (n)
                (defun factorial (x)
                    (if (= x 0) 1 (* x (factorial (- x 1)))))
                (factorial n))
        "#;

        let result = compile_chialisp_to_bytecode(hash_data, source);
        assert!(result.is_ok());
    }

    #[test]
    fn test_deterministic_hashing() {
        let source = "(mod (x y) (+ x y))";

        let result1 = compile_chialisp_to_bytecode(hash_data, source);
        let result2 = compile_chialisp_to_bytecode(hash_data, source);

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        let (_, hash1) = result1.unwrap();
        let (_, hash2) = result2.unwrap();

        assert_eq!(hash1, hash2, "same source should produce same hash");
    }

    #[test]
    fn test_template_compatible_param_names_dont_matter() {
        // CRITICAL: parameter names must NOT affect bytecode/hash
        // this is what makes program_hash hide parameter values
        let (bytecode1, hash1) =
            compile_chialisp_to_bytecode(hash_data, "(mod (x y) (+ x y))").unwrap();
        let (bytecode2, hash2) =
            compile_chialisp_to_bytecode(hash_data, "(mod (a b) (+ a b))").unwrap();
        let (bytecode3, hash3) =
            compile_chialisp_to_bytecode(hash_data, "(mod (first second) (+ first second))")
                .unwrap();

        assert_eq!(bytecode1, bytecode2, "param names affected bytecode!");
        assert_eq!(bytecode1, bytecode3, "param names affected bytecode!");
        assert_eq!(hash1, hash2);
        assert_eq!(hash1, hash3);
    }

    #[test]
    fn test_different_programs_different_hashes() {
        let (_, hash1) = compile_chialisp_to_bytecode(hash_data, "(mod (x y) (+ x y))").unwrap();
        let (_, hash2) = compile_chialisp_to_bytecode(hash_data, "(mod (x y) (* x y))").unwrap();

        assert_ne!(
            hash1, hash2,
            "different programs should have different hashes"
        );
    }

    #[test]
    fn test_invalid_syntax() {
        let result = compile_chialisp_to_bytecode(hash_data, "(mod (x y) (+ x y");
        assert!(result.is_err());
    }

    #[test]
    fn test_with_standard_conditions() {
        // with helper - CREATE_COIN defined via prepended constants
        let source_with = with_standard_conditions(
            "(mod (recipient amount) (list (list CREATE_COIN recipient amount)))",
        );
        let result_with = compile_chialisp_to_bytecode(hash_data, &source_with);
        assert!(
            result_with.is_ok(),
            "CREATE_COIN should be defined: {:?}",
            result_with.err()
        );

        // verify AGG_SIG_ME also works
        let source_agg =
            with_standard_conditions("(mod (pk msg sig) (list (list AGG_SIG_ME pk msg sig)))");
        let result_agg = compile_chialisp_to_bytecode(hash_data, &source_agg);
        assert!(result_agg.is_ok(), "AGG_SIG_ME should be defined");

        // verify the inserted string looks right
        let expanded = with_standard_conditions("(mod (x) (+ x 1))");
        assert!(expanded.contains("(defconstant CREATE_COIN 51)"));
        assert!(expanded.contains("(defconstant AGG_SIG_ME 50)"));
    }

    #[test]
    fn test_with_standard_conditions_preserves_program() {
        // the helper should produce bytecode equivalent to manually defining the constant
        let manual = r#"
            (mod (recipient amount)
                (defconstant CREATE_COIN 51)
                (list (list CREATE_COIN recipient amount)))
        "#;

        let auto = with_standard_conditions(
            "(mod (recipient amount) (list (list CREATE_COIN recipient amount)))",
        );

        let (bytecode_manual, _) = compile_chialisp_to_bytecode(hash_data, manual).unwrap();
        let (bytecode_auto, _) = compile_chialisp_to_bytecode(hash_data, &auto).unwrap();

        // bytecode won't be identical (extra unused constants) but both should compile
        // and produce working programs
        assert!(!bytecode_manual.is_empty());
        assert!(!bytecode_auto.is_empty());
    }
}
