use clvm_zk::{ClvmZkProver, ProgramParameter};
use clvm_zk_core::chialisp::compile_chialisp_template_hash_default;
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // detect which backend is active
    let backend_name = if cfg!(all(feature = "risc0", not(feature = "sp1"))) {
        "risc0".to_string()
    } else if cfg!(all(feature = "sp1", not(feature = "risc0"))) {
        let mode = std::env::var("SP1_PROOF_MODE").unwrap_or_else(|_| "core".to_string());
        format!("sp1 ({})", mode)
    } else if cfg!(all(feature = "risc0", feature = "sp1")) {
        "risc0 (default when both enabled)".to_string()
    } else {
        "unknown".to_string()
    };

    println!("clvm-zk backend benchmark");
    println!("backend: {}\n", backend_name);

    // test expressions with varying complexity
    let test_cases = vec![
        (
            "simple addition",
            "(mod (a b) (+ a b))",
            vec![ProgramParameter::int(42), ProgramParameter::int(13)],
        ),
        (
            "multiplication",
            "(mod (a b) (* a b))",
            vec![ProgramParameter::int(7), ProgramParameter::int(8)],
        ),
        (
            "nested operations",
            "(mod (a b c d) (+ (* a b) (+ c d)))",
            vec![
                ProgramParameter::int(3),
                ProgramParameter::int(4),
                ProgramParameter::int(5),
                ProgramParameter::int(6),
            ],
        ),
        (
            "comparison",
            "(mod (a b) (> a b))",
            vec![ProgramParameter::int(10), ProgramParameter::int(5)],
        ),
        (
            "blockchain condition",
            "(mod (a b) (create_coin a b))",
            vec![ProgramParameter::int(1000), ProgramParameter::int(500)],
        ),
    ];

    run_benchmark(&test_cases)?;

    Ok(())
}

fn run_benchmark(
    test_cases: &[(impl AsRef<str>, &str, Vec<ProgramParameter>)],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut total_prove_time = Duration::new(0, 0);
    let mut total_verify_time = Duration::new(0, 0);
    let mut total_proof_size = 0;
    let mut successful_tests = 0;

    for (test_name, expression, params) in test_cases {
        print!("📋 testing {}: ", test_name.as_ref());

        // prove using high-level api (uses automatic backend selection)
        let prove_start = Instant::now();
        let result = match ClvmZkProver::prove(expression, params) {
            Ok(r) => r,
            Err(e) => {
                println!("proving failed: {}", e);
                continue;
            }
        };
        let prove_time = prove_start.elapsed();

        // verify
        let verify_start = Instant::now();
        match ClvmZkProver::verify_proof(
            compile_chialisp_template_hash_default(expression).unwrap(),
            &result.proof_bytes,
            Some(&result.proof_output.clvm_res.output),
        ) {
            Ok((true, _)) => {
                let verify_time = verify_start.elapsed();
                total_prove_time += prove_time;
                total_verify_time += verify_time;
                total_proof_size += result.proof_bytes.len();
                successful_tests += 1;

                println!(
                    "prove: {}ms, verify: {}ms (result: {}B, proof: {}KB, cost: {})",
                    prove_time.as_millis(),
                    verify_time.as_millis(),
                    result.proof_output.clvm_res.output.len(),
                    result.proof_bytes.len() / 1024,
                    result.proof_output.clvm_res.cost
                );
            }
            Ok((false, _)) => println!("verification failed"),
            Err(e) => println!("verification error: {}", e),
        }
    }

    println!("\n📊 benchmark summary:");
    println!(
        "  successful tests: {}/{}",
        successful_tests,
        test_cases.len()
    );
    if successful_tests > 0 {
        println!(
            "  average prove time: {}ms",
            total_prove_time.as_millis() / successful_tests as u128
        );
        println!(
            "  average verify time: {}ms",
            total_verify_time.as_millis() / successful_tests as u128
        );
        println!(
            "  average proof size: {}KB",
            total_proof_size / successful_tests / 1024
        );
    }

    Ok(())
}
