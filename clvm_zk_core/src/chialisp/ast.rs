//! Abstract Syntax Tree definitions for Chialisp
//!
//! Defines the semantic structure of Chialisp programs after parsing.
//! These types are no_std compatible and optimized for guest execution.

extern crate alloc;

use alloc::{boxed::Box, string::String, vec::Vec};

use crate::operators::ClvmOperator;

/// A complete Chialisp module with parameters, helpers, and main expression
#[derive(Debug, Clone, PartialEq)]
pub struct ModuleAst {
    /// Module parameters: (mod (x y) ...) → ["x", "y"]
    pub parameters: Vec<String>,
    /// Function definitions and other helpers
    pub helpers: Vec<HelperDefinition>,
    /// Main expression to execute
    pub body: Expression,
}

/// Helper definitions (functions, macros, constants)
#[derive(Debug, Clone, PartialEq)]
pub enum HelperDefinition {
    /// Function definition: (defun name (args) body)
    Function {
        name: String,
        parameters: Vec<String>,
        body: Expression,
        inline: bool, // true for defun-inline
    },
    // TODO: Add Macro, Constant when needed
}

/// Core expression types in Chialisp
#[derive(Debug, Clone, PartialEq)]
pub enum Expression {
    /// Variable reference: x, y, amount, etc.
    Variable(String),

    /// Numeric literal: 42, -10, 0
    Number(i64),

    /// String literal: "hello"
    String(String),

    /// Raw bytes: for cryptographic keys, signatures, etc.
    Bytes(Vec<u8>),

    /// Empty list / nil
    Nil,

    /// CLVM operation: (+, -, *, create_coin, etc.)
    Operation {
        operator: ClvmOperator,
        arguments: Vec<Expression>,
    },

    /// Function call: (factorial 5)
    FunctionCall {
        name: String,
        arguments: Vec<Expression>,
    },

    /// List construction: (list a b c)
    List(Vec<Expression>),

    /// Quoted expression: (q . something)
    Quote(Box<Expression>),
}

/// Compilation error types
#[derive(Debug, Clone, PartialEq)]
pub enum CompileError {
    /// Parse error occurred
    ParseError(String),
    /// Unknown operator
    UnknownOperator(String),
    /// Unknown function
    UnknownFunction(String),
    /// Wrong number of arguments
    ArityMismatch {
        operator: String,
        expected: usize,
        actual: usize,
    },
    /// Variable not found in scope
    UndefinedVariable(String),
    /// Invalid mod expression structure
    InvalidModStructure(String),
    /// Invalid function definition
    InvalidFunctionDefinition(String),
    /// Recursive compilation limit hit
    RecursionLimitExceeded,
    /// Recursive function definition not supported
    RecursionNotSupported(String),
    /// Memory limit exceeded
    OutOfMemory,
}

impl ModuleAst {
    /// Create a new module with the given parameters and body
    pub fn new(parameters: Vec<String>, body: Expression) -> Self {
        Self {
            parameters,
            helpers: Vec::new(),
            body,
        }
    }

    /// Add a helper definition to the module
    pub fn add_helper(&mut self, helper: HelperDefinition) {
        self.helpers.push(helper);
    }

    /// Find a function definition by name
    pub fn find_function(&self, name: &str) -> Option<&HelperDefinition> {
        self.helpers.iter().find(|helper| match helper {
            HelperDefinition::Function {
                name: func_name, ..
            } => func_name == name,
        })
    }

    /// Get all function names defined in this module
    pub fn function_names(&self) -> Vec<&str> {
        self.helpers
            .iter()
            .map(|helper| match helper {
                HelperDefinition::Function { name, .. } => name.as_str(),
            })
            .collect()
    }
}

impl Expression {
    /// Create a variable reference
    pub fn variable(name: impl Into<String>) -> Self {
        Expression::Variable(name.into())
    }

    /// Create a number literal
    pub fn number(value: i64) -> Self {
        Expression::Number(value)
    }

    /// Create a string literal
    pub fn string(value: impl Into<String>) -> Self {
        Expression::String(value.into())
    }

    /// Create a nil expression
    pub fn nil() -> Self {
        Expression::Nil
    }

    /// Create an operation with arguments
    pub fn operation(operator: ClvmOperator, arguments: Vec<Expression>) -> Self {
        Expression::Operation {
            operator,
            arguments,
        }
    }

    /// Create a function call
    pub fn function_call(name: impl Into<String>, arguments: Vec<Expression>) -> Self {
        Expression::FunctionCall {
            name: name.into(),
            arguments,
        }
    }

    /// Create a list
    pub fn list(items: Vec<Expression>) -> Self {
        Expression::List(items)
    }

    /// Create a quoted expression
    pub fn quote(expr: Expression) -> Self {
        Expression::Quote(Box::new(expr))
    }

    /// Check if this expression is a literal value (number, string, nil)
    pub fn is_literal(&self) -> bool {
        matches!(
            self,
            Expression::Number(_) | Expression::String(_) | Expression::Nil
        )
    }

    /// Check if this expression references variables
    pub fn has_variables(&self) -> bool {
        match self {
            Expression::Variable(_) => true,
            Expression::Number(_)
            | Expression::String(_)
            | Expression::Bytes(_)
            | Expression::Nil => false,
            Expression::Operation { arguments, .. }
            | Expression::FunctionCall { arguments, .. }
            | Expression::List(arguments) => arguments.iter().any(|arg| arg.has_variables()),
            Expression::Quote(expr) => expr.has_variables(),
        }
    }

    /// Get all variable names referenced in this expression
    pub fn get_variables(&self) -> Vec<&str> {
        let mut vars = Vec::new();
        self.collect_variables(&mut vars);
        vars.sort();
        vars.dedup();
        vars
    }

    /// Recursively collect variable names
    fn collect_variables<'a>(&'a self, vars: &mut Vec<&'a str>) {
        match self {
            Expression::Variable(name) => vars.push(name),
            Expression::Operation { arguments, .. }
            | Expression::FunctionCall { arguments, .. }
            | Expression::List(arguments) => {
                for arg in arguments {
                    arg.collect_variables(vars);
                }
            }
            Expression::Quote(expr) => expr.collect_variables(vars),
            Expression::Number(_)
            | Expression::String(_)
            | Expression::Bytes(_)
            | Expression::Nil => {}
        }
    }
}

impl HelperDefinition {
    /// Create a function definition
    pub fn function(
        name: impl Into<String>,
        parameters: Vec<String>,
        body: Expression,
        inline: bool,
    ) -> Self {
        HelperDefinition::Function {
            name: name.into(),
            parameters,
            body,
            inline,
        }
    }

    /// Get the name of this helper
    pub fn name(&self) -> &str {
        match self {
            HelperDefinition::Function { name, .. } => name,
        }
    }

    /// Check if this is an inline function
    pub fn is_inline(&self) -> bool {
        match self {
            HelperDefinition::Function { inline, .. } => *inline,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};

    #[test]
    fn test_simple_module() {
        let module = ModuleAst::new(
            vec!["x".to_string(), "y".to_string()],
            Expression::operation(
                ClvmOperator::Add,
                vec![Expression::variable("x"), Expression::variable("y")],
            ),
        );

        assert_eq!(module.parameters, vec!["x", "y"]);
        assert_eq!(module.helpers.len(), 0);
    }

    #[test]
    fn test_module_with_function() {
        let mut module = ModuleAst::new(
            vec!["n".to_string()],
            Expression::function_call("double", vec![Expression::variable("n")]),
        );

        let double_func = HelperDefinition::function(
            "double",
            vec!["x".to_string()],
            Expression::operation(
                ClvmOperator::Multiply,
                vec![Expression::variable("x"), Expression::number(2)],
            ),
            false,
        );

        module.add_helper(double_func);

        assert_eq!(module.function_names(), vec!["double"]);
        assert!(module.find_function("double").is_some());
        assert!(module.find_function("unknown").is_none());
    }

    #[test]
    fn test_expression_variable_detection() {
        let expr = Expression::operation(
            ClvmOperator::Add,
            vec![
                Expression::variable("x"),
                Expression::number(5),
                Expression::variable("y"),
            ],
        );

        assert!(expr.has_variables());
        let vars = expr.get_variables();
        assert_eq!(vars, vec!["x", "y"]);
    }

    #[test]
    fn test_literal_expressions() {
        assert!(Expression::number(42).is_literal());
        assert!(Expression::string("hello").is_literal());
        assert!(Expression::nil().is_literal());
        assert!(!Expression::variable("x").is_literal());
    }

    #[test]
    fn test_nested_expression_variables() {
        let expr = Expression::operation(
            ClvmOperator::If,
            vec![
                Expression::operation(
                    ClvmOperator::GreaterThan,
                    vec![Expression::variable("amount"), Expression::number(1000)],
                ),
                Expression::variable("amount"),
                Expression::number(0),
            ],
        );

        let vars = expr.get_variables();
        assert_eq!(vars, vec!["amount"]);
    }

    #[test]
    fn test_function_call_variables() {
        let expr = Expression::function_call(
            "factorial",
            vec![Expression::operation(
                ClvmOperator::Subtract,
                vec![Expression::variable("n"), Expression::number(1)],
            )],
        );

        let vars = expr.get_variables();
        assert_eq!(vars, vec!["n"]);
    }
}

/// Compilation mode for different use cases
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompilationMode {
    /// Template mode: preserve parameter structure for consistent hashing
    /// Parameters remain as environment references (f env), (f (r env)), etc.
    Template,
    /// Instance mode: substitute actual parameter values for execution
    /// Parameters are replaced with their concrete values
    Instance,
}
