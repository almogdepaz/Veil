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

use crate::{encode_clvm_value, types::ClvmValue, Hasher};

pub mod ast;
pub mod compiler_utils;
pub mod frontend;
pub mod parser;

pub use ast::*;
pub use compiler_utils::*;
pub use frontend::*;
pub use parser::*;

/// Compilation context for tracking functions and variables
pub struct CompilerContext {
    /// Function signatures: name -> parameter count
    pub functions: BTreeMap<String, usize>,
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

    pub fn add_function_signature(&mut self, name: String, arity: usize) {
        self.functions.insert(name, arity);
    }

    pub fn get_function_arity(&self, name: &str) -> Option<usize> {
        self.functions.get(name).copied()
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

// Template compilation: converts chialisp source to deterministic binary bytecode for hashing.
//
// Why binary bytecode?
// - Template mode converts variable names to positional indices: "x" → param[0] → (f env)
// - Binary CLVM format provides canonical serialization independent of variable names
// - Same program logic always produces identical bytecode hash, even with different names:
//   "(mod (x y) (+ x y))" ≡ "(mod (a b) (+ a b))" → same template_bytecode → same hash
//
// Flow: chialisp → AST → ClvmValue → binary bytecode → hash(bytecode) → program_hash
// The bytecode is then parsed back to ClvmValue for execution (see clvm_parser.rs)
fn compile_chialisp_common(
    hasher: Hasher,
    source: &str,
) -> Result<(ModuleAst, Vec<u8>, [u8; 32]), CompileError> {
    let sexp = parse_chialisp(source).map_err(|e| CompileError::ParseError(format!("{:?}", e)))?;
    let module = sexp_to_module(sexp)?;
    let template_bytecode = compile_module_unified(&module, CompilationMode::Template)?;
    let program_hash = generate_program_hash(hasher, &template_bytecode);

    Ok((module, template_bytecode, program_hash))
}

/// Compile Chialisp to bytecode with parameter substitution
pub fn compile_chialisp_to_bytecode(
    hasher: Hasher,
    source: &str,
    program_parameters: &[crate::ProgramParameter],
) -> Result<(Vec<u8>, [u8; 32]), CompileError> {
    let (module, template_bytecode, program_hash) = compile_chialisp_common(hasher, source)?;

    let instance_bytecode = if module.parameters.is_empty() {
        template_bytecode.clone()
    } else {
        compile_module_with_functions(&module, program_parameters)?
    };

    Ok((instance_bytecode, program_hash))
}

/// Get program hash for template
pub fn compile_chialisp_template_hash(
    hasher: Hasher,
    source: &str,
) -> Result<[u8; 32], CompileError> {
    let (_module, _template_bytecode, program_hash) = compile_chialisp_common(hasher, source)?;
    Ok(program_hash)
}

/// Compile Chialisp to get template hash using default SHA-256 hasher
/// Only available with sha2-hasher feature
#[cfg(feature = "sha2-hasher")]
pub fn compile_chialisp_template_hash_default(source: &str) -> Result<[u8; 32], CompileError> {
    let (_module, _template_bytecode, program_hash) =
        compile_chialisp_common(crate::hash_data, source)?;
    Ok(program_hash)
}

/// Compile Chialisp to bytecode and function table with custom hasher
/// This is the backend-agnostic version that all backends should use
pub fn compile_chialisp_to_bytecode_with_table(
    hasher: Hasher,
    source: &str,
    program_parameters: &[crate::ProgramParameter],
) -> Result<(Vec<u8>, [u8; 32], crate::RuntimeFunctionTable), CompileError> {
    let (module, template_bytecode, program_hash) = compile_chialisp_common(hasher, source)?;

    // Build function table from module
    let mut function_table = crate::RuntimeFunctionTable::new();
    for helper in &module.helpers {
        match helper {
            HelperDefinition::Function {
                name,
                parameters,
                body,
                ..
            } => {
                // Compile function body to ClvmValue
                let mut func_context = CompilerContext::with_parameters_and_mode(
                    parameters.clone(),
                    CompilationMode::Template,
                );
                // Include all module functions in context for recursive calls
                for other_helper in &module.helpers {
                    match other_helper {
                        HelperDefinition::Function {
                            name: other_name,
                            parameters: other_params,
                            ..
                        } => {
                            func_context
                                .add_function_signature(other_name.clone(), other_params.len());
                        }
                    }
                }
                let compiled_body = compile_expression_unified(body, &mut func_context)?;

                let runtime_function = crate::RuntimeFunction {
                    parameters: parameters.clone(),
                    body: compiled_body,
                };
                function_table.add_function(name.clone(), runtime_function);
            }
        }
    }

    let instance_bytecode = if module.parameters.is_empty() {
        template_bytecode.clone()
    } else {
        compile_module_with_functions(&module, program_parameters)?
    };

    Ok((instance_bytecode, program_hash, function_table))
}

/// Compile module with function definitions and parameter substitution
fn compile_module_with_functions(
    module: &ModuleAst,
    program_parameters: &[crate::ProgramParameter],
) -> Result<Vec<u8>, CompileError> {
    if module.parameters.len() != program_parameters.len() {
        return Err(CompileError::ArityMismatch {
            operator: "module parameters".to_string(),
            expected: module.parameters.len(),
            actual: program_parameters.len(),
        });
    }

    let substituted_module = substitute_values_in_module(module, program_parameters)?;

    compile_module_unified(&substituted_module, CompilationMode::Instance)
}

fn substitute_values_in_module(
    module: &ModuleAst,
    program_parameters: &[crate::ProgramParameter],
) -> Result<ModuleAst, CompileError> {
    let substituted_body =
        substitute_values_in_expression(&module.body, &module.parameters, program_parameters)?;

    let mut substituted_helpers = Vec::new();
    for helper in &module.helpers {
        match helper {
            HelperDefinition::Function {
                name,
                parameters,
                body,
                inline,
            } => {
                let substituted_function_body =
                    substitute_values_in_expression(body, &module.parameters, program_parameters)?;
                substituted_helpers.push(HelperDefinition::Function {
                    name: name.clone(),
                    parameters: parameters.clone(),
                    body: substituted_function_body,
                    inline: *inline,
                });
            }
        }
    }

    Ok(ModuleAst {
        parameters: vec![],
        helpers: substituted_helpers,
        body: substituted_body,
    })
}

fn substitute_values_in_expression(
    expr: &Expression,
    param_names: &[String],
    program_parameters: &[crate::ProgramParameter],
) -> Result<Expression, CompileError> {
    match expr {
        Expression::Variable(name) => {
            if let Some(index) = param_names.iter().position(|p| p == name) {
                match &program_parameters[index] {
                    crate::ProgramParameter::Int(val) => Ok(Expression::Number(*val as i64)),
                    crate::ProgramParameter::Bytes(bytes) => Ok(Expression::Bytes(bytes.clone())),
                }
            } else {
                Ok(expr.clone())
            }
        }
        Expression::Number(_) | Expression::String(_) | Expression::Bytes(_) | Expression::Nil => {
            Ok(expr.clone())
        }
        Expression::Operation {
            operator,
            arguments,
        } => {
            let substituted_args = arguments
                .iter()
                .map(|arg| substitute_values_in_expression(arg, param_names, program_parameters))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Expression::Operation {
                operator: operator.clone(),
                arguments: substituted_args,
            })
        }
        Expression::FunctionCall { name, arguments } => {
            let substituted_args = arguments
                .iter()
                .map(|arg| substitute_values_in_expression(arg, param_names, program_parameters))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Expression::FunctionCall {
                name: name.clone(),
                arguments: substituted_args,
            })
        }
        Expression::List(items) => {
            let substituted_items = items
                .iter()
                .map(|item| substitute_values_in_expression(item, param_names, program_parameters))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Expression::List(substituted_items))
        }
        Expression::Quote(inner) => {
            let substituted_inner =
                substitute_values_in_expression(inner, param_names, program_parameters)?;
            Ok(Expression::Quote(Box::new(substituted_inner)))
        }
    }
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

            let op_atom = ClvmValue::Atom(vec![operator.opcode()]);
            create_cons_list(op_atom, compiled_args)
        }
        Expression::FunctionCall { name, arguments } => {
            compile_function_call_unified(name, arguments, context)
        }
        Expression::List(items) => {
            let compiled_items = items
                .iter()
                .map(|item| compile_expression_unified(item, context))
                .collect::<Result<Vec<_>, _>>()?;
            create_list_from_values(compiled_items)
        }
        Expression::Quote(inner) => {
            let compiled_inner = compile_expression_unified(inner, context)?;
            let quote_op = ClvmValue::Atom(vec![113]); // 'q' opcode
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
    let arity = context
        .get_function_arity(name)
        .ok_or_else(|| CompileError::UnknownFunction(name.to_string()))?;

    validate_function_call(name, arguments, arity, context.get_call_stack())?;

    // Use CallFunction opcode to look up pre-compiled function from function table at runtime
    // This avoids infinite recursion during compilation

    // CallFunction format: (CALL_FUNCTION "function_name" arg1 arg2 ...)
    let call_function_op = ClvmValue::Atom(vec![150]); // CallFunction opcode

    // Function name as literal atom (NOT quoted - it's extracted directly)
    let function_name_atom = ClvmValue::Atom(name.as_bytes().to_vec());

    // Compile arguments
    let compiled_args: Vec<ClvmValue> = arguments
        .iter()
        .map(|arg| compile_expression_unified(arg, context))
        .collect::<Result<Vec<_>, _>>()?;

    // Build the call: (200 "name" arg1 arg2 ...)
    // First element is the operator, rest are arguments
    let mut all_args = vec![function_name_atom];
    all_args.extend(compiled_args);

    create_cons_list(call_function_op, all_args)
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
            Box::new(ClvmValue::Atom(vec![102])), // 'f' opcode
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
                Box::new(ClvmValue::Atom(vec![114])), // 'r' opcode
                Box::new(ClvmValue::Cons(
                    Box::new(inner),
                    Box::new(ClvmValue::Atom(vec![])),
                )),
            );
        }

        // Apply 'f' (first) to get the parameter
        ClvmValue::Cons(
            Box::new(ClvmValue::Atom(vec![102])), // 'f' opcode
            Box::new(ClvmValue::Cons(
                Box::new(inner),
                Box::new(ClvmValue::Atom(vec![])),
            )),
        )
    }
}

pub fn compile_module_unified(
    module: &ModuleAst,
    mode: CompilationMode,
) -> Result<Vec<u8>, CompileError> {
    let mut context = CompilerContext::with_parameters_and_mode(module.parameters.clone(), mode);

    for helper in &module.helpers {
        match helper {
            HelperDefinition::Function {
                name, parameters, ..
            } => {
                context.add_function_signature(name.clone(), parameters.len());
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
        let result = compile_chialisp_to_bytecode(
            hash_data,
            "(mod (x y) (+ x y))",
            &[ProgramParameter::Int(5), ProgramParameter::Int(3)],
        );
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

        let result = compile_chialisp_to_bytecode(hash_data, source, &[ProgramParameter::Int(5)]);
        assert!(result.is_ok());

        let (bytecode, program_hash) = result.unwrap();
        assert!(!bytecode.is_empty());
        assert_ne!(program_hash, [0u8; 32]);
    }

    #[test]
    fn test_deterministic_hashing() {
        let source = "(mod (x y) (+ x y))";

        let result1 = compile_chialisp_to_bytecode(
            hash_data,
            source,
            &[ProgramParameter::Int(5), ProgramParameter::Int(3)],
        );
        let result2 = compile_chialisp_to_bytecode(
            hash_data,
            source,
            &[ProgramParameter::Int(10), ProgramParameter::Int(20)],
        );

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        let (_, hash1) = result1.unwrap();
        let (_, hash2) = result2.unwrap();

        // Same source should produce same program hash regardless of parameter values
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_different_programs_different_hashes() {
        let source1 = "(mod (x y) (+ x y))";
        let source2 = "(mod (x y) (* x y))";

        let result1 = compile_chialisp_to_bytecode(
            hash_data,
            source1,
            &[ProgramParameter::Int(5), ProgramParameter::Int(3)],
        );
        let result2 = compile_chialisp_to_bytecode(
            hash_data,
            source2,
            &[ProgramParameter::Int(5), ProgramParameter::Int(3)],
        );

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        let (_, hash1) = result1.unwrap();
        let (_, hash2) = result2.unwrap();

        // Different programs should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_invalid_syntax() {
        let result = compile_chialisp_to_bytecode(
            hash_data,
            "(mod (x y) (+ x y",
            &[ProgramParameter::Int(5), ProgramParameter::Int(3)],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_parameter_mismatch() {
        let result = compile_chialisp_to_bytecode(
            hash_data,
            "(mod (x y) (+ x y))",
            &[ProgramParameter::Int(5)],
        );
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

        // Test 4: Function names ALSO don't affect bytecode in Template mode!
        // Functions are inlined during compilation, so only the logic matters
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

        // Surprising finding: Function names DON'T affect template bytecode!
        // Functions are compiled as apply operations, not stored by name
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

        // Parameter 0: (f 1) should be shortest - just [102, 1]
        // Parameter 1: (f (r 1)) should contain 'f', 'r', and '1' opcodes
        // Pattern should get progressively longer for higher parameters
        assert!(bytes0.len() < bytes1.len());
        assert!(bytes1.len() < bytes2.len());
        assert!(bytes2.len() < bytes3.len());

        // All should contain the 'f' opcode (102) at some point
        assert!(bytes0.contains(&102)); // 'f' opcode
        assert!(bytes1.contains(&102)); // 'f' opcode
        assert!(bytes1.contains(&114)); // 'r' opcode
        assert!(bytes2.contains(&114)); // 'r' opcode (multiple times)
    }
}
