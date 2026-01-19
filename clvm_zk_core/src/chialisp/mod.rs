// CLVM-ZK Chialisp compiler

extern crate alloc;

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use crate::{encode_clvm_value, operators::ClvmOperator, types::ClvmValue, Hasher};

pub mod ast;
pub mod compiler_utils;
pub mod frontend;
pub mod parser;

pub use ast::*;
pub use compiler_utils::*;
pub use frontend::*;
pub use parser::*;

/// Compilation context for tracking functions and variables
/// Stored function definition for inlining
#[derive(Clone)]
pub struct FunctionDef {
    pub arity: usize,
    pub parameters: Vec<String>,
    pub body: Expression,
}

pub struct CompilerContext {
    /// Function definitions: name -> (arity, parameters, body)
    pub functions: BTreeMap<String, FunctionDef>,
    /// Current parameter names in scope
    parameters: Vec<String>,
    /// Call stack for recursion detection
    pub call_stack: Vec<String>,
    /// Compilation mode (Template vs Instance)
    mode: CompilationMode,
}

impl CompilerContext {
    pub fn with_parameters(parameters: Vec<String>) -> Self {
        Self {
            functions: BTreeMap::new(),
            parameters,
            call_stack: Vec::new(),
            mode: CompilationMode::Template, // Default to template mode
        }
    }

    pub fn with_parameters_and_mode(parameters: Vec<String>, mode: CompilationMode) -> Self {
        Self {
            functions: BTreeMap::new(),
            parameters,
            call_stack: Vec::new(),
            mode,
        }
    }

    pub fn add_function(&mut self, name: String, parameters: Vec<String>, body: Expression) {
        let arity = parameters.len();
        self.functions.insert(
            name,
            FunctionDef {
                arity,
                parameters,
                body,
            },
        );
    }

    pub fn get_function_arity(&self, name: &str) -> Option<usize> {
        self.functions.get(name).map(|f| f.arity)
    }

    pub fn get_function(&self, name: &str) -> Option<&FunctionDef> {
        self.functions.get(name)
    }

    pub fn get_parameter_index(&self, name: &str) -> Option<usize> {
        self.parameters.iter().position(|p| p == name)
    }

    /// Check if a function call would create recursion
    pub fn check_recursion(&self, function_name: &str) -> bool {
        self.call_stack.contains(&function_name.to_string())
    }

    /// Push a function onto the call stack
    pub fn push_call(&mut self, function_name: String) {
        self.call_stack.push(function_name);
    }

    /// Pop a function from the call stack
    pub fn pop_call(&mut self) {
        self.call_stack.pop();
    }

    /// Get the current call stack
    pub fn get_call_stack(&self) -> &[String] {
        &self.call_stack
    }

    /// Get the compilation mode
    pub fn get_mode(&self) -> CompilationMode {
        self.mode
    }
}

// Compilation using clvm_tools_rs - the official Chia chialisp compiler.
//
// This provides full chialisp support including:
// - defun with proper recursion support
// - defmacro (compile-time macros)
// - if/list and other standard macros
// - All chialisp language features
//
// Parameters are passed at runtime via the CLVM environment, not substituted at compile time.
// Use `serialize_params_to_clvm` to convert ProgramParameters to CLVM args format.

/// Compile Chialisp to bytecode using clvm_tools_rs compiler.
///
/// Note: Parameters are NOT substituted at compile time. The compiled bytecode expects
/// parameters to be passed at runtime via the CLVM environment (args).
/// Use `serialize_params_to_clvm` to convert ProgramParameters to CLVM args format.
pub fn compile_chialisp_to_bytecode(
    hasher: Hasher,
    source: &str,
) -> Result<(Vec<u8>, [u8; 32]), CompileError> {
    // Use clvm_tools_rs's full compiler with recursion support
    let bytecode = clvm_tools_rs::compile_chialisp(source).map_err(|e| {
        CompileError::ParseError(format!("clvm_tools_rs compilation failed: {}", e))
    })?;

    let program_hash = generate_program_hash(hasher, &bytecode);

    Ok((bytecode, program_hash))
}

/// Get program hash for template
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

/// Unified expression compiler with mode parameter
pub fn compile_expression_unified(
    expr: &Expression,
    context: &mut CompilerContext,
) -> Result<ClvmValue, CompileError> {
    // Handle literals - these are always quoted in BOTH modes
    // because they should be treated as values, not environment references
    if let Some(result) = compile_basic_expression_types(expr) {
        let value = result?;
        // Always quote literals so they're not treated as operators or environment refs
        return Ok(quote_value(value));
    }

    match expr {
        Expression::Variable(name) => compile_variable_unified(name, context),
        Expression::Operation {
            operator,
            arguments,
        } => {
            let compiled_args = arguments
                .iter()
                .map(|arg| compile_expression_unified(arg, context))
                .collect::<Result<Vec<_>, _>>()?;

            // Check if this is a condition operator (should be compiled as data, not operator call)
            if operator.is_condition_operator() {
                // Compile condition as a quoted list: (q . (opcode arg1 arg2 ...))
                // This creates a condition VALUE that can be returned as program output
                compile_condition_as_list(operator.opcode(), compiled_args)
            } else {
                let op_atom = ClvmValue::Atom(vec![operator.opcode()]);
                create_cons_list(op_atom, compiled_args)
            }
        }
        Expression::FunctionCall { name, arguments } => {
            compile_function_call_unified(name, arguments, context)
        }
        Expression::List(items) => {
            // Compile (list a b c) to nested cons operations: (c a (c b (c c (q ()))))
            // This builds the list at execution time, not as static structure

            if items.is_empty() {
                // Empty list: (q . nil) - quotes nil
                let nil = ClvmValue::Atom(vec![]);
                let quote_op = ClvmValue::Atom(vec![ClvmOperator::Quote.opcode()]);
                return Ok(ClvmValue::Cons(Box::new(quote_op), Box::new(nil)));
            }

            // Build nested cons operations from right to left
            // Start with (q . nil) for the tail - this quotes an empty list
            let nil = ClvmValue::Atom(vec![]);
            let quote_op = ClvmValue::Atom(vec![ClvmOperator::Quote.opcode()]);
            let mut result = ClvmValue::Cons(Box::new(quote_op), Box::new(nil));

            // Wrap each item in cons operation
            for item in items.iter().rev() {
                let compiled_item = compile_expression_unified(item, context)?;
                let cons_op = ClvmValue::Atom(vec![ClvmOperator::Cons.opcode()]);
                result = create_cons_list(cons_op, vec![compiled_item, result])?;
            }

            Ok(result)
        }
        Expression::Quote(inner) => {
            let compiled_inner = compile_expression_unified(inner, context)?;
            let quote_op = ClvmValue::Atom(vec![ClvmOperator::Quote.opcode()]);
            create_cons_list(quote_op, vec![compiled_inner])
        }
        Expression::Number(_) | Expression::String(_) | Expression::Bytes(_) | Expression::Nil => {
            unreachable!("Basic types handled by shared utilities")
        }
    }
}

fn compile_variable_unified(
    name: &str,
    context: &CompilerContext,
) -> Result<ClvmValue, CompileError> {
    if let Some(index) = context.get_parameter_index(name) {
        match context.get_mode() {
            CompilationMode::Template => Ok(create_parameter_access(index)),
            CompilationMode::Instance => Err(CompileError::UndefinedVariable(format!(
                "Parameter {} should have been substituted in Instance mode",
                name
            ))),
        }
    } else if context.get_function_arity(name).is_some() {
        Err(CompileError::InvalidModStructure(format!(
            "Bare function reference not supported: {}",
            name
        )))
    } else {
        Err(CompileError::UndefinedVariable(name.to_string()))
    }
}

fn compile_function_call_unified(
    name: &str,
    arguments: &[Expression],
    context: &mut CompilerContext,
) -> Result<ClvmValue, CompileError> {
    let func_def = context
        .get_function(name)
        .ok_or_else(|| CompileError::UnknownFunction(name.to_string()))?
        .clone();

    validate_function_call(name, arguments, func_def.arity, context.get_call_stack())?;

    // Check for recursion - if recursive, we need special handling
    if context.check_recursion(name) {
        return Err(CompileError::InvalidModStructure(format!(
            "Recursive function '{}' detected - recursion not yet supported with inlining",
            name
        )));
    }

    // Push function onto call stack to detect recursion
    context.push_call(name.to_string());

    // Inline the function using CLVM apply pattern:
    // (a (q . <function-body>) <environment>)
    //
    // Where environment is a list of the argument values

    // Compile the function body in Template mode since function parameters
    // are accessed via environment references (not substituted values)
    let mut func_context = CompilerContext::with_parameters_and_mode(
        func_def.parameters.clone(),
        CompilationMode::Template,
    );
    // Copy function definitions so nested calls work
    func_context.functions = context.functions.clone();
    func_context.call_stack = context.call_stack.clone();

    let compiled_body = compile_expression_unified(&func_def.body, &mut func_context)?;

    // Pop function from call stack
    context.pop_call();

    // Quote the function body: (q . <body>)
    let quoted_body = ClvmValue::Cons(
        Box::new(ClvmValue::Atom(vec![ClvmOperator::Quote.opcode()])),
        Box::new(compiled_body),
    );

    // Compile arguments and build environment list
    let compiled_args: Vec<ClvmValue> = arguments
        .iter()
        .map(|arg| compile_expression_unified(arg, context))
        .collect::<Result<Vec<_>, _>>()?;

    // Build environment using cons operations so arguments are EVALUATED at runtime.
    // This creates: (c arg1 (c arg2 (c arg3 (q . nil))))
    // When evaluated, this becomes (val1 val2 val3) - a list of evaluated values.
    //
    // Previously we built a quoted static structure (q . (arg1 arg2 arg3)),
    // but that meant (f 1) inside the function got the quoted code (q . 5)
    // instead of the value 5.
    let env = if compiled_args.is_empty() {
        // Empty environment: (q . nil)
        ClvmValue::Cons(
            Box::new(ClvmValue::Atom(vec![ClvmOperator::Quote.opcode()])),
            Box::new(ClvmValue::Atom(vec![])),
        )
    } else {
        // Build nested cons operations from right to left
        // Start with (q . nil) for the tail
        let mut env_expr = ClvmValue::Cons(
            Box::new(ClvmValue::Atom(vec![ClvmOperator::Quote.opcode()])),
            Box::new(ClvmValue::Atom(vec![])),
        );

        // Wrap each argument with cons: (c arg env_expr)
        for arg in compiled_args.into_iter().rev() {
            let cons_op = ClvmValue::Atom(vec![ClvmOperator::Cons.opcode()]);
            env_expr = create_cons_list(cons_op, vec![arg, env_expr])?;
        }

        env_expr
    };

    // Build apply expression: (a <quoted-body> <env>)
    let apply_op = ClvmValue::Atom(vec![ClvmOperator::Apply.opcode()]);
    create_cons_list(apply_op, vec![quoted_body, env])
}

/// Create CLVM code to access parameter at given index (for Template mode)
fn create_parameter_access(index: usize) -> ClvmValue {
    // In CLVM:
    // Parameter 0: (f 1) - first of environment
    // Parameter 1: (f (r 1)) - first of rest of environment
    // Parameter 2: (f (r (r 1))) - first of rest of rest of environment
    // etc.
    //
    // The 1 is a special environment reference and should NOT be quoted!

    if index == 0 {
        // (f 1)
        ClvmValue::Cons(
            Box::new(ClvmValue::Atom(vec![ClvmOperator::First.opcode()])),
            Box::new(ClvmValue::Cons(
                Box::new(ClvmValue::Atom(vec![1])), // environment reference (NOT quoted)
                Box::new(ClvmValue::Atom(vec![])),  // nil
            )),
        )
    } else {
        // (f (r (r ... (r 1)))) with index 'r' operations
        let mut inner = ClvmValue::Atom(vec![1]); // start with environment reference

        // Apply 'r' (rest) operations
        for _ in 0..index {
            inner = ClvmValue::Cons(
                Box::new(ClvmValue::Atom(vec![ClvmOperator::Rest.opcode()])),
                Box::new(ClvmValue::Cons(
                    Box::new(inner),
                    Box::new(ClvmValue::Atom(vec![])),
                )),
            );
        }

        // Apply 'f' (first) to get the parameter
        ClvmValue::Cons(
            Box::new(ClvmValue::Atom(vec![ClvmOperator::First.opcode()])),
            Box::new(ClvmValue::Cons(
                Box::new(inner),
                Box::new(ClvmValue::Atom(vec![])),
            )),
        )
    }
}

/// Compile a condition operator as a list-building expression
/// Instead of (opcode arg1 arg2) as an operator call, we generate:
/// (c (q . opcode) (c arg1 (c arg2 (q))))
/// This builds a list (opcode arg1 arg2) at runtime that can be returned as output
fn compile_condition_as_list(opcode: u8, args: Vec<ClvmValue>) -> Result<ClvmValue, CompileError> {
    // Start with quoted nil for the tail
    let nil = ClvmValue::Atom(vec![]);
    let quote_op = ClvmValue::Atom(vec![ClvmOperator::Quote.opcode()]);
    let mut result = ClvmValue::Cons(Box::new(quote_op), Box::new(nil));

    // Wrap each argument with cons (from right to left)
    for arg in args.into_iter().rev() {
        let cons_op = ClvmValue::Atom(vec![ClvmOperator::Cons.opcode()]);
        result = create_cons_list(cons_op, vec![arg, result])?;
    }

    // Finally, cons the quoted opcode at the front
    let quoted_opcode = ClvmValue::Cons(
        Box::new(ClvmValue::Atom(vec![ClvmOperator::Quote.opcode()])),
        Box::new(ClvmValue::Atom(vec![opcode])),
    );
    let cons_op = ClvmValue::Atom(vec![ClvmOperator::Cons.opcode()]);
    create_cons_list(cons_op, vec![quoted_opcode, result])
}

pub fn compile_module_unified(
    module: &ModuleAst,
    mode: CompilationMode,
) -> Result<Vec<u8>, CompileError> {
    let mut context = CompilerContext::with_parameters_and_mode(module.parameters.clone(), mode);

    // Register all functions with their full definitions for inlining
    for helper in &module.helpers {
        match helper {
            HelperDefinition::Function {
                name,
                parameters,
                body,
                ..
            } => {
                context.add_function(name.clone(), parameters.clone(), body.clone());
            }
        }
    }

    let clvm_value = compile_expression_unified(&module.body, &mut context)?;

    Ok(encode_clvm_value(clvm_value))
}

pub fn generate_program_hash(hasher: Hasher, template_bytecode: &[u8]) -> [u8; 32] {
    hasher(template_bytecode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProgramParameter;
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
    fn test_deterministic_hashing() {
        let source = "(mod (x y) (+ x y))";

        let result1 = compile_chialisp_to_bytecode(hash_data, source);
        let result2 = compile_chialisp_to_bytecode(hash_data, source);

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        let (_, hash1) = result1.unwrap();
        let (_, hash2) = result2.unwrap();

        // Same source should produce same program hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_different_programs_different_hashes() {
        let source1 = "(mod (x y) (+ x y))";
        let source2 = "(mod (x y) (* x y))";

        let result1 = compile_chialisp_to_bytecode(hash_data, source1);
        let result2 = compile_chialisp_to_bytecode(hash_data, source2);

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        let (_, hash1) = result1.unwrap();
        let (_, hash2) = result2.unwrap();

        // Different programs should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_invalid_syntax() {
        let result = compile_chialisp_to_bytecode(hash_data, "(mod (x y) (+ x y");
        assert!(result.is_err());
    }

    #[test]
    fn test_unified_compiler_template_mode() {
        let source = "(mod (x y) (+ x y))";
        let sexp = parse_chialisp(source).unwrap();
        let module = sexp_to_module(sexp).unwrap();

        let template_bytecode = compile_module_unified(&module, CompilationMode::Template).unwrap();
        assert!(!template_bytecode.is_empty());

        let template_bytecode2 =
            compile_module_unified(&module, CompilationMode::Template).unwrap();
        assert_eq!(template_bytecode, template_bytecode2);
    }

    #[test]
    fn test_unified_compiler_instance_mode() {
        let source = "(mod (x y) (+ x y))";
        let sexp = parse_chialisp(source).unwrap();
        let module = sexp_to_module(sexp).unwrap();

        let program_parameters = &[ProgramParameter::Int(5), ProgramParameter::Int(3)];
        let substituted_module = substitute_values_in_module(&module, program_parameters).unwrap();

        let instance_bytecode =
            compile_module_unified(&substituted_module, CompilationMode::Instance).unwrap();
        assert!(!instance_bytecode.is_empty());
    }

    #[test]
    fn test_unified_compiler_with_functions() {
        let source = r#"
            (mod (n)
                (defun double (x) (* x 2))
                (double n))
        "#;
        let sexp = parse_chialisp(source).unwrap();
        let module = sexp_to_module(sexp).unwrap();

        let template_result = compile_module_unified(&module, CompilationMode::Template);
        assert!(template_result.is_ok());

        let program_parameters = &[ProgramParameter::Int(5)];
        let substituted_module = substitute_values_in_module(&module, program_parameters).unwrap();
        let instance_result =
            compile_module_unified(&substituted_module, CompilationMode::Instance);
        assert!(instance_result.is_ok());
    }

    #[test]
    fn test_template_determinism_analysis() {
        // Test 1: Same logic, different parameter names should produce IDENTICAL bytecode
        let program1 = "(mod (x y) (+ x y))"; // Parameters: x, y
        let program2 = "(mod (a b) (+ a b))"; // Parameters: a, b
        let program3 = "(mod (first second) (+ first second))"; // Parameters: first, second

        // Compile all to templates
        let module1 = sexp_to_module(parse_chialisp(program1).unwrap()).unwrap();
        let module2 = sexp_to_module(parse_chialisp(program2).unwrap()).unwrap();
        let module3 = sexp_to_module(parse_chialisp(program3).unwrap()).unwrap();

        let template1 = compile_module_unified(&module1, CompilationMode::Template).unwrap();
        let template2 = compile_module_unified(&module2, CompilationMode::Template).unwrap();
        let template3 = compile_module_unified(&module3, CompilationMode::Template).unwrap();

        let hash1 = generate_program_hash(hash_data, &template1);
        let hash2 = generate_program_hash(hash_data, &template2);
        let hash3 = generate_program_hash(hash_data, &template3);

        // Key finding: Parameter names don't affect bytecode!
        // Only positional indices are stored: (f env), (f (r env)), etc.
        assert_eq!(template1, template2);
        assert_eq!(template1, template3);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1, hash3);

        // Test 2: Different logic should produce different hashes
        let program4 = "(mod (x y) (* x y))"; // Multiplication instead of addition
        let module4 = sexp_to_module(parse_chialisp(program4).unwrap()).unwrap();
        let template4 = compile_module_unified(&module4, CompilationMode::Template).unwrap();
        let hash4 = generate_program_hash(hash_data, &template4);

        assert_ne!(hash1, hash4);

        // Test 3: Different parameter count should produce different hashes
        let program5 = "(mod (x) (* x 2))"; // Single parameter
        let module5 = sexp_to_module(parse_chialisp(program5).unwrap()).unwrap();
        let template5 = compile_module_unified(&module5, CompilationMode::Template).unwrap();
        let hash5 = generate_program_hash(hash_data, &template5);

        assert_ne!(hash1, hash5);

        // Test 4: Function names DON'T affect bytecode because functions are inlined
        // With inlining, only the function body matters, not the name
        let program6 = r#"(mod (x)
            (defun double (y) (* y 2))
            (double x))"#;
        let program7 = r#"(mod (x)
            (defun multiply_by_two (y) (* y 2))
            (multiply_by_two x))"#;

        let module6 = sexp_to_module(parse_chialisp(program6).unwrap()).unwrap();
        let module7 = sexp_to_module(parse_chialisp(program7).unwrap()).unwrap();

        let template6 = compile_module_unified(&module6, CompilationMode::Template).unwrap();
        let template7 = compile_module_unified(&module7, CompilationMode::Template).unwrap();

        let hash6 = generate_program_hash(hash_data, &template6);
        let hash7 = generate_program_hash(hash_data, &template7);

        // With function inlining, identical function bodies produce identical bytecode
        // regardless of function names - this is the correct clvmr-compatible behavior
        assert_eq!(hash6, hash7);
    }

    #[test]
    fn test_clvm_environment_access_patterns() {
        // Test program with 4 parameters to show access patterns
        let program = "(mod (w x y z) (list w x y z))";
        let module = sexp_to_module(parse_chialisp(program).unwrap()).unwrap();
        let template = compile_module_unified(&module, CompilationMode::Template).unwrap();

        // The compiled template should contain environment access patterns
        assert!(!template.is_empty());

        // Test what the create_parameter_access function generates
        let param0 = create_parameter_access(0); // (f 1) for parameter 0
        let param1 = create_parameter_access(1); // (f (r 1)) for parameter 1
        let param2 = create_parameter_access(2); // (f (r (r 1))) for parameter 2
        let param3 = create_parameter_access(3); // (f (r (r (r 1)))) for parameter 3

        // Encode to bytecode to see the actual opcodes
        let bytes0 = encode_clvm_value(param0);
        let bytes1 = encode_clvm_value(param1);
        let bytes2 = encode_clvm_value(param2);
        let bytes3 = encode_clvm_value(param3);

        // Parameter 0: (f 1) should be shortest
        // Parameter 1: (f (r 1)) should contain 'f', 'r', and '1' opcodes
        // Pattern should get progressively longer for higher parameters
        assert!(bytes0.len() < bytes1.len());
        assert!(bytes1.len() < bytes2.len());
        assert!(bytes2.len() < bytes3.len());

        // All should contain the 'f' opcode at some point
        let f_opcode = ClvmOperator::First.opcode();
        let r_opcode = ClvmOperator::Rest.opcode();
        assert!(bytes0.contains(&f_opcode));
        assert!(bytes1.contains(&f_opcode));
        assert!(bytes1.contains(&r_opcode));
        assert!(bytes2.contains(&r_opcode));
    }
}
