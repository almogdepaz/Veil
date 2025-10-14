#![allow(dead_code)]
use clvm_zk::{ClvmZkProver, ProgramParameter};
use clvm_zk_core::chialisp::compile_chialisp_template_hash_default;
use once_cell::sync::Lazy;
use std::env;
use std::sync::Once;
static TRACING_INIT: Once = Once::new();

/// Internal helper for formatted logging
#[macro_export]
macro_rules! log_with_level {
    ($level:literal, $($arg:tt)*) => {
        println!("[{}] [{}] [{}] {}",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            $level,
            std::thread::current().name().unwrap_or("test"),
            format!($($arg)*))
    };
}

/// Internal helper for error logging (uses stderr)
#[macro_export]
macro_rules! error_log_with_level {
    ($level:literal, $($arg:tt)*) => {
        eprintln!("[{}] [{}] [{}] {}",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            $level,
            std::thread::current().name().unwrap_or("test"),
            format!($($arg)*))
    };
}

/// Test logging macros that include timestamp, level, and test name
#[macro_export]
macro_rules! test_info {
    ($($arg:tt)*) => {
        log_with_level!("INFO", $($arg)*)
    };
}

#[macro_export]
macro_rules! test_error {
    ($($arg:tt)*) => {
        error_log_with_level!("ERROR", $($arg)*)
    };
}

#[macro_export]
macro_rules! test_warn {
    ($($arg:tt)*) => {
        log_with_level!("WARN", $($arg)*)
    };
}

#[macro_export]
macro_rules! test_debug {
    ($($arg:tt)*) => {
        log_with_level!("DEBUG", $($arg)*)
    };
}

/// Test result for a single expression
#[derive(Debug)]
pub enum TestResult {
    Success(Vec<u8>),
    ProofFailed(String),
    VerifyFailed(String),
}

/// Execute a complete test: prove → verify
pub fn test_expression(expr: &str, params: &[i64]) -> TestResult {
    let param_list: Vec<ProgramParameter> =
        params.iter().map(|&x| ProgramParameter::int(x)).collect();
    match ClvmZkProver::prove(expr, &param_list) {
        Ok(result) => {
            let output = result.proof_output.clvm_res;
            let proof = result.proof_bytes;

            // Verify proof using new approach
            let program_hash = match compile_chialisp_template_hash_default(expr) {
                Ok(hash) => hash,
                Err(e) => {
                    return TestResult::VerifyFailed(format!(
                        "compile_chialisp_template_hash failed: {:?}",
                        e
                    ))
                }
            };
            match ClvmZkProver::verify_proof(program_hash, &proof, Some(&output.output)) {
                Ok((true, _)) => TestResult::Success(output.output),
                Ok((false, _)) => {
                    TestResult::VerifyFailed("verification returned false".to_string())
                }
                Err(e) => TestResult::VerifyFailed(e.to_string()),
            }
        }
        Err(e) => TestResult::ProofFailed(e.to_string()),
    }
}

pub static BATCH_SIZE: Lazy<usize> = Lazy::new(|| {
    env::var("BATCH_SIZE")
        .ok()
        .and_then(|val| val.parse::<usize>().ok())
        .unwrap_or(4) // fallback default
});
