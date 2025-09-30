use clvm_zk_core::{compile_chialisp_with_function_table, ClvmEvaluator, ProgramParameter};

fn main() {
    // Test basic function call compilation
    let source = r#"
        (mod (x)
            (defun double (n) (* n 2))
            (double x)
        )
    "#;

    let params = &[ProgramParameter::int(5)];

    match compile_chialisp_with_function_table(source, params) {
        Ok((bytecode, program_hash, function_table)) => {
            println!("✅ Compilation successful!");
            println!("Bytecode length: {}", bytecode.len());
            println!("Program hash: {:?}", program_hash);
            println!("Function table has {} functions", function_table.function_names().len());

            // Test evaluation with function table
            let mut evaluator = ClvmEvaluator::new();
            evaluator.function_table = function_table;

            match evaluator.evaluate_clvm_program_with_params(&bytecode, params) {
                Ok((result, _conditions)) => {
                    println!("✅ Evaluation successful!");
                    println!("Result: {:?}", result);
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
}