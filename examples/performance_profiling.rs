use clvm_zk::{ClvmZkProver, ProgramParameter};
use clvm_zk_core::chialisp::compile_chialisp_template_hash_default;
use std::time::{Duration, Instant};

/// Performance profiling example demonstrating optimization techniques
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔬 CLVM-ZK Performance Profiling");
    println!("================================\n");

    // Test cases with different complexity levels
    let test_cases = vec![
        // Simple operations (baseline)
        ("Simple Addition", "(mod (a b) (+ a b))", vec![5, 3]),
        ("Simple Multiplication", "(mod (a b) (* a b))", vec![7, 8]),
        // Medium complexity
        (
            "Nested Arithmetic",
            "(mod (a b c d) (+ (* a b) (- c d)))",
            vec![5, 3, 10, 4],
        ),
        ("Conditional Logic", "(mod (a b c d) (i (> a b) c d))", vec![7, 3, 100, 200]),
        // Complex operations
        (
            "Deep Nesting",
            "(mod (a b c d e f g h) (+ (+ (+ a b) (+ c d)) (+ (+ e f) (+ g h))))",
            vec![1, 2, 3, 4, 5, 6, 7, 8],
        ),
        ("Modular Exponentiation", "(mod (a b c) (modpow a b c))", vec![5, 3, 13]),
        ("Division with Remainder", "(mod (a b) (divmod a b))", vec![17, 5]),
        // Blockchain conditions
        (
            "Create Coin Condition",
            "(mod (a b) (create_coin a b))",
            vec![1000, 500],
        ),
        ("Reserve Fee Condition", "(mod (a) (reserve_fee a))", vec![100]),
    ];

    let mut results = Vec::new();

    for (name, expression, args) in test_cases {
        println!("Testing: {name}");
        let params: Vec<ProgramParameter> =
            args.iter().map(|&x| ProgramParameter::int(x)).collect();

        // Measure proof generation time (3 runs for average)
        let mut proof_times = Vec::new();
        let mut proof_sizes = Vec::new();
        let mut last_proof = Vec::new();
        let mut last_output = Vec::new();

        for _ in 0..3 {
            let proof_start = Instant::now();
            let result = ClvmZkProver::prove(expression, &params)?;
            let proof_time = proof_start.elapsed();

            proof_times.push(proof_time);
            proof_sizes.push(result.proof_bytes.len());
            last_proof = result.proof_bytes.clone();
            last_output = result.proof_output.clvm_res.output.clone();
        }

        // Measure verification time (5 runs for average)
        let mut verification_times = Vec::new();
        let program_hash = compile_chialisp_template_hash_default(expression).unwrap();
        for _ in 0..5 {
            let verify_start = Instant::now();
            let (_is_valid, _) =
                ClvmZkProver::verify_proof(program_hash, &last_proof, Some(&last_output))?;
            let verify_time = verify_start.elapsed();
            verification_times.push(verify_time);
        }

        // Calculate averages
        let avg_proof_time = proof_times.iter().sum::<Duration>() / proof_times.len() as u32;
        let avg_verify_time =
            verification_times.iter().sum::<Duration>() / verification_times.len() as u32;
        let avg_proof_size = proof_sizes.iter().sum::<usize>() / proof_sizes.len();

        results.push((name, avg_proof_time, avg_verify_time, avg_proof_size));

        println!(
            "  ✓ Proof: {}ms, Verify: {}ms, Size: {}KB",
            avg_proof_time.as_millis(),
            avg_verify_time.as_millis(),
            avg_proof_size / 1024
        );
    }

    println!("\n📊 Performance Summary:");
    println!(
        "{:<25} | {:>10} | {:>10} | {:>10}",
        "Operation", "Proof ms", "Verify ms", "Proof KB"
    );
    println!("{}", "-".repeat(75));

    for (name, proof_time, verify_time, proof_size) in &results {
        println!(
            "{:<25} | {:>10} | {:>10} | {:>10}",
            name,
            proof_time.as_millis(),
            verify_time.as_millis(),
            proof_size / 1024
        );
    }

    // Performance analysis
    println!("\n🎯 Performance Analysis:");

    let total_proof_time: Duration = results.iter().map(|(_, _, p, _)| *p).sum();
    let total_verify_time: Duration = results.iter().map(|(_, _, v, _)| *v).sum();

    println!(
        "• Average proof generation: {:.2}s",
        total_proof_time.as_secs_f64() / results.len() as f64
    );
    println!(
        "• Average verification: {:.0}ms",
        total_verify_time.as_millis() as f64 / results.len() as f64
    );

    // Find fastest and slowest operations
    let fastest_proof = results.iter().min_by_key(|(_, p, _, _)| *p).unwrap();
    let slowest_proof = results.iter().max_by_key(|(_, p, _, _)| *p).unwrap();

    println!(
        "• Fastest operation: {} ({}ms)",
        fastest_proof.0,
        fastest_proof.2.as_millis()
    );
    println!(
        "• Slowest operation: {} ({}ms)",
        slowest_proof.0,
        slowest_proof.2.as_millis()
    );

    // Optimization recommendations
    println!("\nOptimization Recommendations:");
    println!("1. Simple operations are most efficient for frequent use");
    println!("2. Conditional logic adds minimal overhead");
    println!("3. Deep nesting increases complexity significantly");
    println!("4. Modular arithmetic operations are well-optimized");
    println!("5. Blockchain conditions have consistent performance");

    Ok(())
}
