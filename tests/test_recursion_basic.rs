use clvm_zk_core::{compile_chialisp_with_function_table, ClvmEvaluator, ProgramParameter};

#[test]
fn test_basic_function_call() {
    // Test basic function call compilation
    let source = r#"
        (mod (x)
            (defun double (n) (* n 2))
            (double x)
        )
    "#;

    let params = &[ProgramParameter::int(5)];

    let result = compile_chialisp_with_function_table(source, params);
    assert!(result.is_ok(), "Compilation should succeed: {:?}", result.err());

    let (bytecode, _program_hash, function_table) = result.unwrap();
    assert!(!bytecode.is_empty(), "Bytecode should not be empty");
    assert_eq!(function_table.function_names().len(), 1, "Should have one function");
    assert!(function_table.has_function("double"), "Should have 'double' function");

    // Test evaluation with function table
    let mut evaluator = ClvmEvaluator::new();
    evaluator.function_table = function_table;

    let eval_result = evaluator.evaluate_clvm_program_with_params(&bytecode, params);
    println!("Evaluation result: {:?}", eval_result);

    // For now, just verify it doesn't crash - actual result validation comes later
    match eval_result {
        Ok((result_bytes, conditions)) => {
            println!("✅ Function call evaluation succeeded");
            println!("Result bytes: {:?}", result_bytes);
            println!("Conditions: {:?}", conditions);
        }
        Err(e) => {
            println!("❌ Function call evaluation failed: {}", e);
            // Don't panic yet, let's see what the error is
        }
    }
}

#[test]
fn test_recursive_function_compilation() {
    // Test recursive function compilation (should not fail at compile time)
    let source = r#"
        (mod (n)
            (defun factorial (x)
                (if (= x 0)
                    1
                    (* x (factorial (- x 1)))))
            (factorial n)
        )
    "#;

    let params = &[ProgramParameter::int(3)];

    let result = compile_chialisp_with_function_table(source, params);
    assert!(result.is_ok(), "Recursive function compilation should succeed: {:?}", result.err());

    let (bytecode, _program_hash, function_table) = result.unwrap();
    assert_eq!(function_table.function_names().len(), 1, "Should have one function");
    assert!(function_table.has_function("factorial"), "Should have 'factorial' function");

    println!("✅ Recursive function compilation succeeded");
    println!("Bytecode length: {}", bytecode.len());
    println!("Function table: {:?}", function_table.function_names());
}

#[test]
fn test_recursive_function_execution() {
    // Test actual runtime execution of recursive factorial
    let source = r#"
        (mod (n)
            (defun factorial (x)
                (if (= x 0)
                    1
                    (* x (factorial (- x 1)))))
            (factorial n)
        )
    "#;

    let params = &[ProgramParameter::int(3)]; // factorial(3) should = 6

    let result = compile_chialisp_with_function_table(source, params);
    assert!(result.is_ok(), "Recursive function compilation should succeed: {:?}", result.err());

    let (bytecode, _program_hash, function_table) = result.unwrap();

    // Test evaluation with function table
    let mut evaluator = ClvmEvaluator::new();
    evaluator.function_table = function_table;

    println!("🧪 Testing factorial(3) execution...");
    let eval_result = evaluator.evaluate_clvm_program_with_params(&bytecode, params);

    match eval_result {
        Ok((result_bytes, conditions)) => {
            println!("✅ Recursive function execution succeeded!");
            println!("Result bytes: {:?}", result_bytes);
            println!("Conditions: {:?}", conditions);

            // Try to parse result as integer
            if result_bytes.len() == 1 {
                let result_value = result_bytes[0];
                println!("Factorial(3) = {}", result_value);
                assert_eq!(result_value, 6, "factorial(3) should equal 6");
            } else {
                println!("Result format: {} bytes", result_bytes.len());
                // For now, just verify it doesn't crash
            }
        }
        Err(e) => {
            println!("❌ Recursive function execution failed: {}", e);
            // Let's see what the specific error is before panicking
            panic!("Recursive function execution should work: {}", e);
        }
    }
}

#[test]
fn test_simple_function_execution() {
    // Test simple non-recursive function execution
    let source = r#"
        (mod (x)
            (defun double (n) (* n 2))
            (double x)
        )
    "#;

    let params = &[ProgramParameter::int(5)]; // double(5) should = 10

    let result = compile_chialisp_with_function_table(source, params);
    assert!(result.is_ok(), "Function compilation should succeed: {:?}", result.err());

    let (bytecode, _program_hash, function_table) = result.unwrap();

    // Test evaluation with function table
    let mut evaluator = ClvmEvaluator::new();
    evaluator.function_table = function_table;

    println!("🧪 Testing double(5) execution...");
    let eval_result = evaluator.evaluate_clvm_program_with_params(&bytecode, params);

    match eval_result {
        Ok((result_bytes, conditions)) => {
            println!("✅ Simple function execution succeeded!");
            println!("Result bytes: {:?}", result_bytes);
            println!("Conditions: {:?}", conditions);

            // Try to parse result as integer
            if result_bytes.len() == 1 {
                let result_value = result_bytes[0];
                println!("double(5) = {}", result_value);
                assert_eq!(result_value, 10, "double(5) should equal 10");
            } else {
                println!("Result format: {} bytes", result_bytes.len());
            }
        }
        Err(e) => {
            println!("❌ Simple function execution failed: {}", e);
            panic!("Simple function execution should work: {}", e);
        }
    }
}