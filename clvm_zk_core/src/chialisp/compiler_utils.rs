//! Shared CLVM compilation utilities

extern crate alloc;

use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use super::{ast::*, CompileError};
use crate::ClvmValue;

/// Convert i64 to ClvmValue using consistent encoding
pub fn number_to_clvm_value(num: i64) -> ClvmValue {
    if num == 0 {
        ClvmValue::Atom(vec![])
    } else if num > 0 && num <= 255 {
        ClvmValue::Atom(vec![num as u8])
    } else {
        // For larger numbers, use big endian encoding
        let mut bytes = Vec::new();
        let mut n = num.unsigned_abs();
        while n > 0 {
            bytes.push((n & 0xFF) as u8);
            n >>= 8;
        }
        bytes.reverse();

        // Handle negative numbers by setting high bit
        if num < 0 {
            if let Some(first) = bytes.first_mut() {
                *first |= 0x80;
            }
        }

        ClvmValue::Atom(bytes)
    }
}

/// Convert ClvmValue to i64 number - reverse of number_to_clvm_value
pub fn clvm_value_to_number(value: &ClvmValue) -> Result<i64, &'static str> {
    match value {
        ClvmValue::Atom(bytes) => {
            if bytes.is_empty() {
                Ok(0)
            } else if bytes.len() == 1 {
                Ok(bytes[0] as i64)
            } else {
                // Multi-byte number - decode from big endian
                let mut result = 0i64;
                let is_negative = bytes.first().map_or(false, |&b| b & 0x80 != 0);

                for &byte in bytes {
                    result = result.checked_shl(8).ok_or("number too large")?;
                    result += (byte & 0x7F) as i64; // Clear sign bit for calculation
                }

                if is_negative {
                    result = -result;
                }

                Ok(result)
            }
        }
        ClvmValue::Cons(_, _) => Err("cannot convert cons pair to number"),
    }
}

/// Create a cons list from operator and arguments: (operator arg1 arg2 ...)
pub fn create_cons_list(
    operator: ClvmValue,
    args: Vec<ClvmValue>,
) -> Result<ClvmValue, CompileError> {
    // Build the argument list from right to left: (arg1 . (arg2 . (arg3 . nil)))
    let mut args_list = ClvmValue::Atom(vec![]); // Start with nil

    for arg in args.into_iter().rev() {
        args_list = ClvmValue::Cons(Box::new(arg), Box::new(args_list));
    }

    // Create the final structure: (operator . args_list)
    Ok(ClvmValue::Cons(Box::new(operator), Box::new(args_list)))
}

/// Create a proper list from ClvmValues
pub fn create_list_from_values(values: Vec<ClvmValue>) -> Result<ClvmValue, CompileError> {
    let mut result = ClvmValue::Atom(vec![]); // Start with nil

    // Build list from right to left
    for value in values.into_iter().rev() {
        result = ClvmValue::Cons(Box::new(value), Box::new(result));
    }

    Ok(result)
}

/// Validate function call arguments
pub fn validate_function_call(
    name: &str,
    arguments: &[Expression],
    expected_params: usize,
    _call_stack: &[String],
) -> Result<(), CompileError> {
    // Validate argument count
    if arguments.len() != expected_params {
        return Err(CompileError::ArityMismatch {
            operator: name.to_string(),
            expected: expected_params,
            actual: arguments.len(),
        });
    }

    Ok(())
}

/// Compile basic expression types that are identical across both pipelines
pub fn compile_basic_expression_types(
    expr: &Expression,
) -> Option<Result<ClvmValue, CompileError>> {
    match expr {
        Expression::Number(value) => Some(Ok(number_to_clvm_value(*value))),
        Expression::String(value) => Some(Ok(ClvmValue::Atom(value.as_bytes().to_vec()))),
        Expression::Bytes(bytes) => Some(Ok(ClvmValue::Atom(bytes.clone()))),
        Expression::Nil => Some(Ok(ClvmValue::Atom(vec![]))),
        _ => None, // Let specific pipeline handle complex cases
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_number_encoding() {
        assert_eq!(number_to_clvm_value(0), ClvmValue::Atom(vec![]));
        assert_eq!(number_to_clvm_value(42), ClvmValue::Atom(vec![42]));
        assert_eq!(number_to_clvm_value(255), ClvmValue::Atom(vec![255]));

        // Larger numbers should be multi-byte
        let large_num = number_to_clvm_value(1000);
        if let ClvmValue::Atom(bytes) = large_num {
            assert!(bytes.len() > 1);
        } else {
            panic!("Expected atom for number");
        }
    }

    #[test]
    fn test_create_cons_list() {
        let op = ClvmValue::Atom(vec![43]); // '+' operator
        let args = vec![ClvmValue::Atom(vec![1]), ClvmValue::Atom(vec![2])];

        let result = create_cons_list(op, args).unwrap();

        // Should create nested cons structure
        assert!(matches!(result, ClvmValue::Cons(_, _)));
    }

    #[test]
    fn test_create_list_from_values() {
        let values = vec![
            ClvmValue::Atom(vec![1]),
            ClvmValue::Atom(vec![2]),
            ClvmValue::Atom(vec![3]),
        ];

        let result = create_list_from_values(values).unwrap();

        // Should create proper list structure
        assert!(matches!(result, ClvmValue::Cons(_, _)));
    }

    #[test]
    fn test_validate_function_call_arity_mismatch() {
        let args = vec![Expression::Number(1)];
        let result = validate_function_call("test", &args, 2, &[]);

        assert!(matches!(result, Err(CompileError::ArityMismatch { .. })));
    }

    #[test]
    fn test_validate_function_call_recursion_allowed() {
        let args = vec![Expression::Number(1)];
        let call_stack = vec!["test".to_string()];
        let result = validate_function_call("test", &args, 1, &call_stack);

        // Recursion is now allowed at compile time, handled at runtime
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_function_call_success() {
        let args = vec![Expression::Number(1)];
        let result = validate_function_call("test", &args, 1, &[]);

        assert!(result.is_ok());
    }
}
