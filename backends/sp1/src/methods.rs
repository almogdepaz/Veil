//! SP1 program ELFs

use sp1_sdk::include_elf;

/// The ELF for the base CLVM execution program
pub const CLVM_ZK_SP1_ELF: &[u8] = include_elf!("clvm-zk-sp1-program");

/// The ELF for the recursive aggregation program
pub const RECURSIVE_SP1_ELF: &[u8] = include_elf!("clvm-zk-sp1-recursive");

/// The ELF for the settlement program
pub const SETTLEMENT_SP1_ELF: &[u8] = include_elf!("settlement");
