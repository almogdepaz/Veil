//! Frontend processing for Chialisp
//!
//! Converts S-expressions into typed AST structures.
//! Handles mod expressions, function definitions, and semantic validation.

extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use super::{ast::*, parser::SExp};
use crate::operators::ClvmOperator;

/// Convert S-expression to ModuleAst
pub fn sexp_to_module(sexp: SExp) -> Result<ModuleAst, CompileError> {
    match sexp {
        SExp::List(items) => {
            if items.is_empty() {
                return Err(CompileError::InvalidModStructure(
                    "Empty list cannot be a module".to_string(),
                ));
            }

            // Check if this is a mod expression
            if let SExp::Atom(name) = &items[0] {
                if name == "mod" {
                    return parse_mod_expression(&items);
                }
            }

            // Not a mod expression - treat as simple expression
            let expr = sexp_to_expression(SExp::List(items))?;
            Ok(ModuleAst::new(Vec::new(), expr))
        }
        _ => {
            // Single atom - treat as simple expression
            let expr = sexp_to_expression(sexp)?;
            Ok(ModuleAst::new(Vec::new(), expr))
        }
    }
}

/// Parse a mod expression: (mod (params) body)
fn parse_mod_expression(items: &[SExp]) -> Result<ModuleAst, CompileError> {
    if items.len() < 3 {
        return Err(CompileError::InvalidModStructure(
            "mod requires at least 2 arguments: parameters and body".to_string(),
        ));
    }

    // Parse parameters: (mod (x y) ...)
    let parameters = parse_parameter_list(&items[1])?;

    // Parse body and helpers
    let mut module = ModuleAst::new(parameters, Expression::Nil);

    // Process all remaining items (helpers + main body)
    let mut main_body = None;

    for item in &items[2..] {
        if let Some(helper) = try_parse_helper(item)? {
            module.add_helper(helper);
        } else {
            // Not a helper - this should be the main body
            if main_body.is_some() {
                return Err(CompileError::InvalidModStructure(
                    "Multiple non-helper expressions in mod body".to_string(),
                ));
            }
            main_body = Some(sexp_to_expression(item.clone())?);
        }
    }

    // Set the main body
    module.body = main_body.unwrap_or(Expression::Nil);

    Ok(module)
}

/// Parse parameter list: (x y) or x
fn parse_parameter_list(sexp: &SExp) -> Result<Vec<String>, CompileError> {
    match sexp {
        SExp::List(items) => {
            let mut params = Vec::new();
            for item in items {
                if let SExp::Atom(name) = item {
                    params.push(name.clone());
                } else {
                    return Err(CompileError::InvalidModStructure(
                        "Parameter names must be atoms".to_string(),
                    ));
                }
            }
            Ok(params)
        }
        SExp::Atom(name) => {
            // Single parameter
            Ok(vec![name.clone()])
        }
    }
}

/// Try to parse a helper definition (defun, etc.)
fn try_parse_helper(sexp: &SExp) -> Result<Option<HelperDefinition>, CompileError> {
    match sexp {
        SExp::List(items) => {
            if items.is_empty() {
                return Ok(None);
            }

            if let SExp::Atom(name) = &items[0] {
                match name.as_str() {
                    "defun" => Ok(Some(parse_defun(items, false)?)),
                    "defun-inline" => Ok(Some(parse_defun(items, true)?)),
                    _ => Ok(None), // Not a helper
                }
            } else {
                Ok(None)
            }
        }
        _ => Ok(None),
    }
}

/// Parse defun: (defun name (args) body)
fn parse_defun(items: &[SExp], inline: bool) -> Result<HelperDefinition, CompileError> {
    if items.len() != 4 {
        return Err(CompileError::InvalidFunctionDefinition(
            "defun requires exactly 3 arguments: name, parameters, body".to_string(),
        ));
    }

    // Parse function name
    let name = match &items[1] {
        SExp::Atom(name) => name.clone(),
        _ => {
            return Err(CompileError::InvalidFunctionDefinition(
                "Function name must be an atom".to_string(),
            ))
        }
    };

    // Parse parameters
    let parameters = parse_parameter_list(&items[2])?;

    // Parse body
    let body = sexp_to_expression(items[3].clone())?;

    Ok(HelperDefinition::function(name, parameters, body, inline))
}

/// Convert S-expression to Expression
pub fn sexp_to_expression(sexp: SExp) -> Result<Expression, CompileError> {
    match sexp {
        SExp::Atom(atom) => parse_atom_expression(atom),
        SExp::List(items) => {
            if items.is_empty() {
                return Ok(Expression::Nil);
            }

            // Check if this is an operation or function call
            if let SExp::Atom(op_name) = &items[0] {
                // Handle special cases first
                match op_name.as_str() {
                    "q" | "quote" => {
                        // (q expr) -> quoted expression
                        if items.len() != 2 {
                            return Err(CompileError::ArityMismatch {
                                operator: "quote".to_string(),
                                expected: 1,
                                actual: items.len() - 1,
                            });
                        }
                        let quoted = sexp_to_expression(items[1].clone())?;
                        return Ok(Expression::quote(quoted));
                    }
                    "list" => {
                        // (list a b c) -> list construction
                        let args = items[1..]
                            .iter()
                            .map(|item| sexp_to_expression(item.clone()))
                            .collect::<Result<Vec<_>, _>>()?;
                        return Ok(Expression::list(args));
                    }
                    _ => {}
                }

                // Try to parse as operation
                if let Some(operator) = ClvmOperator::parse_operator(op_name) {
                    // Skip quote since we handled it above
                    if matches!(operator, ClvmOperator::Quote) {
                        // This should have been handled above, but just in case
                        let args = items[1..]
                            .iter()
                            .map(|item| sexp_to_expression(item.clone()))
                            .collect::<Result<Vec<_>, _>>()?;
                        if args.len() != 1 {
                            return Err(CompileError::ArityMismatch {
                                operator: "quote".to_string(),
                                expected: 1,
                                actual: args.len(),
                            });
                        }
                        return Ok(Expression::quote(args[0].clone()));
                    }

                    let args = items[1..]
                        .iter()
                        .map(|item| sexp_to_expression(item.clone()))
                        .collect::<Result<Vec<_>, _>>()?;

                    // Validate arity if known
                    if let Some(expected_arity) = operator.arity() {
                        if args.len() != expected_arity {
                            return Err(CompileError::ArityMismatch {
                                operator: op_name.clone(),
                                expected: expected_arity,
                                actual: args.len(),
                            });
                        }
                    }

                    return Ok(Expression::operation(operator, args));
                }

                // Unknown operator - treat as function call
                let args = items[1..]
                    .iter()
                    .map(|item| sexp_to_expression(item.clone()))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Expression::function_call(op_name.clone(), args))
            } else {
                Err(CompileError::InvalidModStructure(
                    "First element of list must be an atom".to_string(),
                ))
            }
        }
    }
}

/// Parse atomic expressions (numbers, strings, variables)
fn parse_atom_expression(atom: String) -> Result<Expression, CompileError> {
    // Check for invalid floating point syntax before parsing as integer
    if atom.contains('.') {
        return Err(CompileError::ParseError(format!(
            "Floating point numbers not supported: {}",
            atom
        )));
    }

    // Try to parse as number
    if let Ok(num) = atom.parse::<i64>() {
        return Ok(Expression::number(num));
    }

    // Check for string literals (should start and end with quotes)
    if atom.starts_with('"') && atom.ends_with('"') && atom.len() >= 2 {
        let content = &atom[1..atom.len() - 1];
        return Ok(Expression::string(content.to_string()));
    }

    // Check for special atoms
    match atom.as_str() {
        "nil" | "()" => Ok(Expression::nil()),
        // Chia consensus opcodes
        "AGG_SIG_UNSAFE" => Ok(Expression::number(49)),
        "AGG_SIG_ME" => Ok(Expression::number(50)),
        "CREATE_COIN" => Ok(Expression::number(51)),
        "RESERVE_FEE" => Ok(Expression::number(52)),
        // Output/Messaging
        "REMARK" => Ok(Expression::number(1)),
        // Announcements
        "CREATE_COIN_ANNOUNCEMENT" => Ok(Expression::number(60)),
        "ASSERT_COIN_ANNOUNCEMENT" => Ok(Expression::number(61)),
        "CREATE_PUZZLE_ANNOUNCEMENT" => Ok(Expression::number(62)),
        "ASSERT_PUZZLE_ANNOUNCEMENT" => Ok(Expression::number(63)),
        // Concurrency
        "ASSERT_CONCURRENT_SPEND" => Ok(Expression::number(64)),
        "ASSERT_CONCURRENT_PUZZLE" => Ok(Expression::number(65)),
        // Messaging
        "SEND_MESSAGE" => Ok(Expression::number(66)),
        "RECEIVE_MESSAGE" => Ok(Expression::number(67)),
        // Assertions
        "ASSERT_MY_COIN_ID" => Ok(Expression::number(70)),
        "ASSERT_MY_PARENT_ID" => Ok(Expression::number(71)),
        "ASSERT_MY_PUZZLEHASH" => Ok(Expression::number(72)),
        "ASSERT_MY_AMOUNT" => Ok(Expression::number(73)),
        _ => Ok(Expression::variable(atom)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chialisp::parser::parse_chialisp;
    use alloc::vec;

    #[test]
    fn test_simple_expression() {
        let sexp = parse_chialisp("(+ 1 2)").unwrap();
        let expr = sexp_to_expression(sexp).unwrap();

        match expr {
            Expression::Operation {
                operator,
                arguments,
            } => {
                assert_eq!(operator, ClvmOperator::Add);
                assert_eq!(arguments.len(), 2);
            }
            _ => panic!("Expected operation"),
        }
    }

    #[test]
    fn test_simple_mod() {
        let sexp = parse_chialisp("(mod (x y) (+ x y))").unwrap();
        let module = sexp_to_module(sexp).unwrap();

        assert_eq!(module.parameters, vec!["x", "y"]);
        assert_eq!(module.helpers.len(), 0);

        match module.body {
            Expression::Operation { operator, .. } => {
                assert_eq!(operator, ClvmOperator::Add);
            }
            _ => panic!("Expected operation"),
        }
    }

    #[test]
    fn test_mod_with_defun() {
        let source = r#"
            (mod (n)
                (defun double (x) (* x 2))
                (double n))
        "#;

        let sexp = parse_chialisp(source).unwrap();
        let module = sexp_to_module(sexp).unwrap();

        assert_eq!(module.parameters, vec!["n"]);
        assert_eq!(module.helpers.len(), 1);

        // Check function definition
        let func = &module.helpers[0];
        match func {
            HelperDefinition::Function {
                name,
                parameters,
                body,
                inline,
            } => {
                assert_eq!(name, "double");
                assert_eq!(parameters, &vec!["x"]);
                assert!(!inline);

                // Check function body
                match body {
                    Expression::Operation { operator, .. } => {
                        assert_eq!(*operator, ClvmOperator::Multiply);
                    }
                    _ => panic!("Expected multiply operation"),
                }
            }
        }

        // Check main body is function call
        match module.body {
            Expression::FunctionCall { name, arguments } => {
                assert_eq!(name, "double");
                assert_eq!(arguments.len(), 1);
            }
            _ => panic!("Expected function call"),
        }
    }

    #[test]
    fn test_variable_parsing() {
        let expr = sexp_to_expression(parse_chialisp("amount").unwrap()).unwrap();
        assert_eq!(expr, Expression::variable("amount"));
    }

    #[test]
    fn test_number_parsing() {
        let expr = sexp_to_expression(parse_chialisp("42").unwrap()).unwrap();
        assert_eq!(expr, Expression::number(42));

        let expr = sexp_to_expression(parse_chialisp("-10").unwrap()).unwrap();
        assert_eq!(expr, Expression::number(-10));
    }

    #[test]
    fn test_quoted_expression() {
        let expr = sexp_to_expression(parse_chialisp("(q 42)").unwrap()).unwrap();
        match expr {
            Expression::Quote(inner) => {
                assert_eq!(*inner, Expression::number(42));
            }
            _ => panic!("Expected quoted expression"),
        }
    }

    #[test]
    fn test_function_call() {
        let expr = sexp_to_expression(parse_chialisp("(factorial 5)").unwrap()).unwrap();
        match expr {
            Expression::FunctionCall { name, arguments } => {
                assert_eq!(name, "factorial");
                assert_eq!(arguments.len(), 1);
                assert_eq!(arguments[0], Expression::number(5));
            }
            _ => panic!("Expected function call"),
        }
    }

    #[test]
    fn test_nested_expressions() {
        let expr = sexp_to_expression(parse_chialisp("(+ (* 2 3) 4)").unwrap()).unwrap();
        match expr {
            Expression::Operation {
                operator,
                arguments,
            } => {
                assert_eq!(operator, ClvmOperator::Add);
                assert_eq!(arguments.len(), 2);

                // First argument should be multiplication
                match &arguments[0] {
                    Expression::Operation { operator, .. } => {
                        assert_eq!(*operator, ClvmOperator::Multiply);
                    }
                    _ => panic!("Expected multiply operation"),
                }
            }
            _ => panic!("Expected add operation"),
        }
    }

    #[test]
    fn test_arity_validation() {
        // Test too few arguments
        let result = sexp_to_expression(parse_chialisp("(+ 1)").unwrap());
        assert!(matches!(result, Err(CompileError::ArityMismatch { .. })));

        // Test too many arguments
        let result = sexp_to_expression(parse_chialisp("(+ 1 2 3)").unwrap());
        assert!(matches!(result, Err(CompileError::ArityMismatch { .. })));
    }

    #[test]
    fn test_invalid_defun() {
        let source = "(mod (x) (defun double))"; // Missing args and body
        let sexp = parse_chialisp(source).unwrap();
        let result = sexp_to_module(sexp);
        assert!(matches!(
            result,
            Err(CompileError::InvalidFunctionDefinition(_))
        ));
    }

    #[test]
    fn test_chia_opcode_constants() {
        // test that CREATE_COIN is recognized as the number 51
        let expr = sexp_to_expression(parse_chialisp("CREATE_COIN").unwrap()).unwrap();
        assert_eq!(expr, Expression::number(51));

        // test AGG_SIG_ME
        let expr = sexp_to_expression(parse_chialisp("AGG_SIG_ME").unwrap()).unwrap();
        assert_eq!(expr, Expression::number(50));

        // test in a list expression
        let expr =
            sexp_to_expression(parse_chialisp("(list CREATE_COIN puzzle_hash amount)").unwrap())
                .unwrap();
        match expr {
            Expression::List(items) => {
                assert_eq!(items.len(), 3);
                assert_eq!(items[0], Expression::number(51));
                assert_eq!(items[1], Expression::variable("puzzle_hash"));
                assert_eq!(items[2], Expression::variable("amount"));
            }
            _ => panic!("expected list expression"),
        }
    }
}
