//! SP1 program ELF

use sp1_sdk::include_elf;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const CLVM_ZK_SP1_ELF: &[u8] = include_elf!("clvm-zk-sp1-program");
