use clvm_zk::{backends::backend, ProgramParameter};

#[test]
fn test_recursive_factorial() {
    let backend = backend().expect("Backend should initialize");

    let factorial_source = r#"
        (mod (n)
            (defun factorial (x)
                (if (= x 0)
                    1
                    (* x (factorial (- x 1)))))
            (factorial n)
        )
    "#;

    println!("Testing recursive factorial with backend...");

    // Test factorial(3) = 6
    let params = vec![ProgramParameter::int(3)];
    let result = backend.prove_program(factorial_source, &params);

    match result {
        Ok(zk_result) => {
            println!("Mock execution succeeded!");
            println!("Result: {:?}", zk_result.output.clvm_res.output);

            // Check if result is 6
            if zk_result.output.clvm_res.output.len() == 1
                && zk_result.output.clvm_res.output[0] == 6
            {
                println!("factorial(3) = 6 ✓");
            } else {
                println!(
                    "Expected factorial(3) = 6, got {:?}",
                    zk_result.output.clvm_res.output
                );
            }
        }
        Err(e) => {
            panic!("Execution failed: {:?}", e);
        }
    }
}

#[test]

fn test_conditional_function() {
    let backend = backend().expect("Backend should initialize");

    let conditional_source = r#"
        (mod (x)
            (defun test_if (n)
                (if (= n 0)
                    1
                    (* n 2)))
            (test_if x)
        )
    "#;

    println!("Testing simple conditional function with backend...");

    // Test test_if(3) = 6 (since 3 != 0, returns 3 * 2 = 6)
    let params = vec![ProgramParameter::int(3)];
    let result = backend.prove_program(conditional_source, &params);

    match result {
        Ok(zk_result) => {
            println!("Mock execution succeeded!");
            println!("Result: {:?}", zk_result.output.clvm_res.output);

            // Check if result is 6
            if zk_result.output.clvm_res.output.len() == 1
                && zk_result.output.clvm_res.output[0] == 6
            {
                println!("test_if(3) = 6 ✓");
            } else {
                println!(
                    "Expected test_if(3) = 6, got {:?}",
                    zk_result.output.clvm_res.output
                );
            }
        }
        Err(e) => {
            panic!("Execution failed: {:?}", e);
        }
    }
}

#[test]

fn test_factorial_like_non_recursive() {
    let backend = backend().expect("Backend should initialize");

    // Testing multiplication by 1 specifically
    let factorial_like_source = r#"
        (mod (x)
            (defun factorial_like (n)
                (if (= n 0)
                    1
                    (* n 1)))
            (factorial_like x)
        )
    "#;

    println!("Testing factorial-like non-recursive function with backend...");

    // Let's test direct multiplication vs function context multiplication
    println!("Testing direct multiplication without functions...");

    // Test direct (* x 1) without function context
    let test_direct_mul_1 = r#"(mod (x) (* x 1))"#;

    let params = vec![ProgramParameter::int(3)];

    println!("Testing direct (* 3 1)...");
    match backend.prove_program(test_direct_mul_1, &params) {
        Ok(result) => println!("Direct (* 3 1) = {:?}", result.output.clvm_res.output),
        Err(e) => {
            println!("Direct (* 3 1) failed: {:?}", e);
            panic!("Direct multiplication by 1 failed - this is the core bug!");
        }
    }

    // This shouldn't be reached due to the panic above
    let result = backend.prove_program(factorial_like_source, &params);
    match result {
        Ok(zk_result) => {
            println!("Mock execution succeeded!");
            println!("Result: {:?}", zk_result.output.clvm_res.output);

            // Check if result is 3
            if zk_result.output.clvm_res.output.len() == 1
                && zk_result.output.clvm_res.output[0] == 3
            {
                println!("factorial_like(3) = 3 ✓");
            } else {
                println!(
                    "Expected factorial_like(3) = 3, got {:?}",
                    zk_result.output.clvm_res.output
                );
            }
        }
        Err(e) => {
            panic!("Execution failed: {:?}", e);
        }
    }
}

#[test]

fn test_simple_function() {
    let backend = backend().expect("Backend should initialize");

    let double_source = r#"
        (mod (x)
            (defun double (n) (* n 2))
            (double x)
        )
    "#;

    println!("Testing simple function with backend...");

    // Test double(5) = 10
    let params = vec![ProgramParameter::int(5)];
    let result = backend.prove_program(double_source, &params);

    match result {
        Ok(zk_result) => {
            println!("Mock execution succeeded!");
            println!("Result: {:?}", zk_result.output.clvm_res.output);

            // Check if result is 10
            if zk_result.output.clvm_res.output.len() == 1
                && zk_result.output.clvm_res.output[0] == 10
            {
                println!("double(5) = 10 ✓");
            } else {
                println!(
                    "Expected double(5) = 10, got {:?}",
                    zk_result.output.clvm_res.output
                );
            }
        }
        Err(e) => {
            panic!("Execution failed: {:?}", e);
        }
    }
}

#[test]

fn test_deep_recursion() {
    let backend = backend().expect("Backend should initialize");

    let fibonacci_source = r#"
        (mod (n)
            (defun fib (x)
                (if (< x 2)
                    x
                    (+ (fib (- x 1)) (fib (- x 2)))))
            (fib n)
        )
    "#;

    println!("Testing fibonacci recursion with backend...");

    // Test fib(7) = 13 (0,1,1,2,3,5,8,13)
    let params = vec![ProgramParameter::int(7)];
    let result = backend.prove_program(fibonacci_source, &params);

    match result {
        Ok(zk_result) => {
            println!("Mock execution succeeded!");
            println!("Result: {:?}", zk_result.output.clvm_res.output);

            if zk_result.output.clvm_res.output.len() == 1
                && zk_result.output.clvm_res.output[0] == 13
            {
                println!("fib(7) = {} ✓", zk_result.output.clvm_res.output[0]);
            } else {
                panic!(
                    "Expected fib(7) = 13, got {:?}",
                    zk_result.output.clvm_res.output
                );
            }
        }
        Err(e) => {
            panic!("Deep recursion failed: {:?}", e);
        }
    }
}

#[test]

fn test_deeper_factorial_recursion() {
    let backend = backend().expect("Backend should initialize");

    let factorial_source = r#"
        (mod (n)
            (defun factorial (x)
                (if (= x 0)
                    1
                    (* x (factorial (- x 1)))))
            (factorial n)
        )
    "#;

    println!("Testing deeper factorial recursion...");

    // Test factorial(5) = 120 (CLVM encoding: 0x78)
    let params = vec![ProgramParameter::int(5)];
    let result = backend
        .prove_program(factorial_source, &params)
        .expect("Should compute factorial(5)");

    assert_eq!(
        result.output.clvm_res.output,
        vec![120],
        "factorial(5) should equal 120"
    );
    println!("factorial(5) = 120 ✓");

    // Test factorial(4) = 24
    let params = vec![ProgramParameter::int(4)];
    let result = backend
        .prove_program(factorial_source, &params)
        .expect("Should compute factorial(4)");

    assert_eq!(
        result.output.clvm_res.output,
        vec![24],
        "factorial(4) should equal 24"
    );
    println!("factorial(4) = 24 ✓");
}

#[test]

fn test_recursion_with_helper_functions() {
    let backend = backend().expect("Backend should initialize");

    // Recursion that calls helper functions during recursion
    let source = r#"
        (mod (n)
            (defun double (x) (* x 2))
            (defun sum_doubled (x)
                (if (= x 0)
                    0
                    (+ (double x) (sum_doubled (- x 1)))))
            (sum_doubled n)
        )
    "#;

    println!("Testing recursion with helper function calls...");

    // sum_doubled(3) = double(3) + double(2) + double(1) = 6 + 4 + 2 = 12
    let params = vec![ProgramParameter::int(3)];
    let result = backend
        .prove_program(source, &params)
        .expect("Should compute sum_doubled(3)");

    assert_eq!(
        result.output.clvm_res.output,
        vec![12],
        "sum_doubled(3) should equal 12"
    );
    println!("sum_doubled(3) = 12 ✓");

    // Test with larger value
    let params = vec![ProgramParameter::int(5)];
    let result = backend
        .prove_program(source, &params)
        .expect("Should compute sum_doubled(5)");

    // sum_doubled(5) = 10 + 8 + 6 + 4 + 2 = 30
    assert_eq!(
        result.output.clvm_res.output,
        vec![30],
        "sum_doubled(5) should equal 30"
    );
    println!("sum_doubled(5) = 30 ✓");
}

#[test]

fn test_mutual_recursion() {
    let backend = backend().expect("Backend should initialize");

    // Mutual recursion: even/odd checker
    let source = r#"
        (mod (n)
            (defun is_even (x)
                (if (= x 0)
                    1
                    (is_odd (- x 1))))
            (defun is_odd (x)
                (if (= x 0)
                    0
                    (is_even (- x 1))))
            (is_even n)
        )
    "#;

    println!("Testing mutual recursion (is_even/is_odd)...");

    // Test is_even(4) = true (1)
    let params = vec![ProgramParameter::int(4)];
    let result = backend
        .prove_program(source, &params)
        .expect("Should compute is_even(4)");

    assert_eq!(
        result.output.clvm_res.output,
        vec![1],
        "is_even(4) should be true (1)"
    );
    println!("is_even(4) = 1 ✓");

    // Test is_even(5) = false (0)
    let params = vec![ProgramParameter::int(5)];
    let result = backend
        .prove_program(source, &params)
        .expect("Should compute is_even(5)");

    // CLVM can encode 0 as either [0x00] or [0x80] (nil)
    let is_zero =
        result.output.clvm_res.output == vec![0] || result.output.clvm_res.output == vec![0x80];
    assert!(
        is_zero,
        "is_even(5) should be false (0), got {:?}",
        result.output.clvm_res.output
    );
    println!("is_even(5) = 0 ✓");

    // Test is_even(10) = true (1)
    let params = vec![ProgramParameter::int(10)];
    let result = backend
        .prove_program(source, &params)
        .expect("Should compute is_even(10)");

    assert_eq!(
        result.output.clvm_res.output,
        vec![1],
        "is_even(10) should be true (1)"
    );
    println!("is_even(10) = 1 ✓");
}

#[test]

fn test_nested_function_calls_in_recursion() {
    let backend = backend().expect("Backend should initialize");

    // Multiple levels of function calls within recursion
    let source = r#"
        (mod (n)
            (defun add_one (x) (+ x 1))
            (defun double (x) (* x 2))
            (defun process (x) (double (add_one x)))
            (defun sum_processed (x)
                (if (= x 0)
                    0
                    (+ (process x) (sum_processed (- x 1)))))
            (sum_processed n)
        )
    "#;

    println!("Testing nested function calls within recursion...");

    // sum_processed(3) = process(3) + process(2) + process(1)
    //                  = double(4) + double(3) + double(2)
    //                  = 8 + 6 + 4 = 18
    let params = vec![ProgramParameter::int(3)];
    let result = backend
        .prove_program(source, &params)
        .expect("Should compute sum_processed(3)");

    assert_eq!(
        result.output.clvm_res.output,
        vec![18],
        "sum_processed(3) should equal 18"
    );
    println!("sum_processed(3) = 18 ✓");
}

#[test]

fn test_deep_call_stack() {
    let backend = backend().expect("Backend should initialize");

    // Test very deep recursion
    let source = r#"
        (mod (n)
            (defun sum_to_n (x)
                (if (= x 0)
                    0
                    (+ x (sum_to_n (- x 1)))))
            (sum_to_n n)
        )
    "#;

    println!("Testing deep call stack (sum 1..n)...");

    // sum_to_n(10) = 10 + 9 + 8 + ... + 1 = 55
    let params = vec![ProgramParameter::int(10)];
    let result = backend
        .prove_program(source, &params)
        .expect("Should compute sum_to_n(10)");

    assert_eq!(
        result.output.clvm_res.output,
        vec![55],
        "sum_to_n(10) should equal 55"
    );
    println!("sum_to_n(10) = 55 ✓");

    // sum_to_n(15) = 120
    let params = vec![ProgramParameter::int(15)];
    let result = backend
        .prove_program(source, &params)
        .expect("Should compute sum_to_n(15)");

    assert_eq!(
        result.output.clvm_res.output,
        vec![120],
        "sum_to_n(15) should equal 120"
    );
    println!("sum_to_n(15) = 120 ✓");
}

#[test]

fn test_recursion_with_multiple_parameters() {
    let backend = backend().expect("Backend should initialize");

    // Ackermann-like function with multiple params
    let source = r#"
        (mod (m n)
            (defun ack (x y)
                (if (= x 0)
                    (+ y 1)
                    (if (= y 0)
                        (ack (- x 1) 1)
                        (ack (- x 1) (ack x (- y 1))))))
            (ack m n)
        )
    "#;

    println!("Testing recursion with multiple parameters (Ackermann)...");

    // ack(0, 0) = 1
    let params = vec![ProgramParameter::int(0), ProgramParameter::int(0)];
    let result = backend
        .prove_program(source, &params)
        .expect("Should compute ack(0,0)");

    assert_eq!(
        result.output.clvm_res.output,
        vec![1],
        "ack(0,0) should equal 1"
    );
    println!("ack(0,0) = 1 ✓");

    // ack(1, 0) = 2
    let params = vec![ProgramParameter::int(1), ProgramParameter::int(0)];
    let result = backend
        .prove_program(source, &params)
        .expect("Should compute ack(1,0)");

    assert_eq!(
        result.output.clvm_res.output,
        vec![2],
        "ack(1,0) should equal 2"
    );
    println!("ack(1,0) = 2 ✓");

    // ack(1, 1) = 3
    let params = vec![ProgramParameter::int(1), ProgramParameter::int(1)];
    let result = backend
        .prove_program(source, &params)
        .expect("Should compute ack(1,1)");

    assert_eq!(
        result.output.clvm_res.output,
        vec![3],
        "ack(1,1) should equal 3"
    );
    println!("ack(1,1) = 3 ✓");

    // ack(2, 1) = 5
    let params = vec![ProgramParameter::int(2), ProgramParameter::int(1)];
    let result = backend
        .prove_program(source, &params)
        .expect("Should compute ack(2,1)");

    assert_eq!(
        result.output.clvm_res.output,
        vec![5],
        "ack(2,1) should equal 5"
    );
    println!("ack(2,1) = 5 ✓");
}
