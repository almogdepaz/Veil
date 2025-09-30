// Simple test to see if our recursion infrastructure works
use clvm_zk_core::*;

fn main() {
    println!("Testing basic function call...");

    let source = r#"
    (mod (x)
        (defun double (n) (* n 2))
        (double x)
    )
    "#;

    match compile_chialisp_with_function_table(source, &[ProgramParameter::int(5)]) {
        Ok((bytecode, hash, table)) => {
            println!("✅ Compilation worked!");
            println!("- Function table has {} functions", table.function_names().len());
            println!("- Functions: {:?}", table.function_names());

            // Try evaluation
            let mut evaluator = ClvmEvaluator::new();
            evaluator.function_table = table;

            match evaluator.evaluate_clvm_program_with_params(&bytecode, &[ProgramParameter::int(5)]) {
                Ok((result, conditions)) => {
                    println!("✅ Evaluation worked! Result: {:?}", result);
                }
                Err(e) => {
                    println!("❌ Evaluation failed: {}", e);
                }
            }
        }
        Err(e) => {
            println!("❌ Compilation failed: {:?}", e);
        }
    }

    println!("\nTesting recursive function...");
    let recursive_source = r#"
    (mod (n)
        (defun factorial (x)
            (if (= x 0) 1 (* x (factorial (- x 1)))))
        (factorial n)
    )
    "#;

    match compile_chialisp_with_function_table(recursive_source, &[ProgramParameter::int(3)]) {
        Ok((bytecode, hash, table)) => {
            println!("✅ Recursive compilation worked!");
            println!("- Function table has {} functions", table.function_names().len());
        }
        Err(e) => {
            println!("❌ Recursive compilation failed: {:?}", e);
        }
    }
}