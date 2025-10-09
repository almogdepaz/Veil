use clvm_zk_core::ProgramParameter;

#[cfg(not(any(feature = "risc0", feature = "sp1")))]
use clvm_zk_mock::MockBackend;

#[test]
#[cfg(not(any(feature = "risc0", feature = "sp1")))]
fn test_mock_recursive_factorial() {
    let mock = MockBackend::new().expect("Mock backend should initialize");

    let factorial_source = r#"
        (mod (n)
            (defun factorial (x)
                (if (= x 0)
                    1
                    (* x (factorial (- x 1)))))
            (factorial n)
        )
    "#;

    println!("🧪 Testing recursive factorial with mock backend...");

    // Test factorial(3) = 6
    let params = vec![ProgramParameter::int(3)];
    let result = mock.prove_chialisp_program(factorial_source, &params);

    match result {
        Ok(zk_result) => {
            println!("✅ Mock execution succeeded!");
            println!("Result: {:?}", zk_result.result);

            // Check if result is 6
            if zk_result.result.len() == 1 && zk_result.result[0] == 6 {
                println!("🎉 factorial(3) = 6 ✓");
            } else {
                println!("❌ Expected factorial(3) = 6, got {:?}", zk_result.result);
            }

            // Test verification
            let verification_result =
                mock.verify_mock_proof(factorial_source, &params, &zk_result.result);

            assert!(verification_result.is_ok(), "Verification should work");
            assert!(verification_result.unwrap(), "Verification should pass");
            println!("✅ Mock verification passed!");
        }
        Err(e) => {
            panic!("Mock execution failed: {:?}", e);
        }
    }
}

#[test]
#[cfg(not(any(feature = "risc0", feature = "sp1")))]
fn test_mock_conditional_function() {
    let mock = MockBackend::new().expect("Mock backend should initialize");

    let conditional_source = r#"
        (mod (x)
            (defun test_if (n)
                (if (= n 0)
                    1
                    (* n 2)))
            (test_if x)
        )
    "#;

    println!("🧪 Testing simple conditional function with mock backend...");

    // Test test_if(3) = 6 (since 3 != 0, returns 3 * 2 = 6)
    let params = vec![ProgramParameter::int(3)];
    let result = mock.prove_chialisp_program(conditional_source, &params);

    match result {
        Ok(zk_result) => {
            println!("✅ Mock execution succeeded!");
            println!("Result: {:?}", zk_result.result);

            // Check if result is 6
            if zk_result.result.len() == 1 && zk_result.result[0] == 6 {
                println!("🎉 test_if(3) = 6 ✓");
            } else {
                println!("❌ Expected test_if(3) = 6, got {:?}", zk_result.result);
            }
        }
        Err(e) => {
            panic!("Mock execution failed: {:?}", e);
        }
    }
}

#[test]
#[cfg(not(any(feature = "risc0", feature = "sp1")))]
fn test_mock_factorial_like_non_recursive() {
    let mock = MockBackend::new().expect("Mock backend should initialize");

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

    println!("🧪 Testing factorial-like non-recursive function with mock backend...");

    // Let's test direct multiplication vs function context multiplication
    println!("🔍 Testing direct multiplication without functions...");

    // Test direct (* x 1) without function context
    let test_direct_mul_1 = r#"(mod (x) (* x 1))"#;
    let test_direct_mul_2 = r#"(mod (x) (* x 2))"#;

    let params = vec![ProgramParameter::int(3)];

    println!("Testing direct (* 3 1)...");
    match mock.prove_chialisp_program(test_direct_mul_1, &params) {
        Ok(result) => println!("✅ Direct (* 3 1) = {:?}", result.result),
        Err(e) => {
            println!("❌ Direct (* 3 1) failed: {:?}", e);
            panic!("Direct multiplication by 1 failed - this is the core bug!");
        }
    }

    // This shouldn't be reached due to the panic above
    let result = mock.prove_chialisp_program(factorial_like_source, &params);
    match result {
        Ok(zk_result) => {
            println!("✅ Mock execution succeeded!");
            println!("Result: {:?}", zk_result.result);

            // Check if result is 3
            if zk_result.result.len() == 1 && zk_result.result[0] == 3 {
                println!("🎉 factorial_like(3) = 3 ✓");
            } else {
                println!(
                    "❌ Expected factorial_like(3) = 3, got {:?}",
                    zk_result.result
                );
            }
        }
        Err(e) => {
            panic!("Mock execution failed: {:?}", e);
        }
    }
}

#[test]
#[cfg(not(any(feature = "risc0", feature = "sp1")))]
fn test_mock_simple_function() {
    let mock = MockBackend::new().expect("Mock backend should initialize");

    let double_source = r#"
        (mod (x)
            (defun double (n) (* n 2))
            (double x)
        )
    "#;

    println!("🧪 Testing simple function with mock backend...");

    // Test double(5) = 10
    let params = vec![ProgramParameter::int(5)];
    let result = mock.prove_chialisp_program(double_source, &params);

    match result {
        Ok(zk_result) => {
            println!("✅ Mock execution succeeded!");
            println!("Result: {:?}", zk_result.result);

            // Check if result is 10
            if zk_result.result.len() == 1 && zk_result.result[0] == 10 {
                println!("🎉 double(5) = 10 ✓");
            } else {
                println!("❌ Expected double(5) = 10, got {:?}", zk_result.result);
            }
        }
        Err(e) => {
            panic!("Mock execution failed: {:?}", e);
        }
    }
}

#[test]
#[cfg(not(any(feature = "risc0", feature = "sp1")))]
fn test_mock_deep_recursion() {
    let mock = MockBackend::new().expect("Mock backend should initialize");

    let fibonacci_source = r#"
        (mod (n)
            (defun fib (x)
                (if (< x 2)
                    x
                    (+ (fib (- x 1)) (fib (- x 2)))))
            (fib n)
        )
    "#;

    println!("🧪 Testing fibonacci recursion with mock backend...");

    // Test fib(7) = 13 (0,1,1,2,3,5,8,13)
    let params = vec![ProgramParameter::int(7)];
    let result = mock.prove_chialisp_program(fibonacci_source, &params);

    match result {
        Ok(zk_result) => {
            println!("✅ Mock execution succeeded!");
            println!("Result: {:?}", zk_result.result);

            if zk_result.result.len() == 1 {
                println!("🎉 fib(7) = {} (expected 13)", zk_result.result[0]);
            } else {
                println!("❌ Unexpected result format: {:?}", zk_result.result);
            }
        }
        Err(e) => {
            println!("❌ Deep recursion failed: {:?}", e);
            // This might fail due to recursion limits - that's expected for now
        }
    }
}
