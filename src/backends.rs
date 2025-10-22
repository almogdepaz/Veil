use crate::{ClvmZkError, ProgramParameter};

pub use clvm_zk_core::ZKClvmResult;

pub trait ZKCLVMBackend {
    fn prove_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
    ) -> Result<ZKClvmResult, ClvmZkError>;

    fn prove_with_nullifier(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        spend_secret: [u8; 32],
    ) -> Result<ZKClvmResult, ClvmZkError>;

    fn verify_proof(&self, proof: &[u8]) -> Result<(bool, [u8; 32], Vec<u8>), ClvmZkError>;

    fn backend_name(&self) -> &'static str;

    fn is_available(&self) -> bool;
}

pub fn backend() -> Result<Box<dyn ZKCLVMBackend>, ClvmZkError> {
    #[cfg(feature = "risc0")]
    {
        println!("initializing risc0 zkvm backend");
        return Ok(Box::new(Risc0Backend::new()?));
    }

    #[cfg(all(not(feature = "risc0"), feature = "sp1"))]
    {
        println!("initializing sp1 zkvm backend");
        return Ok(Box::new(Sp1Backend::new()?));
    }

    #[cfg(all(not(feature = "risc0"), not(feature = "sp1"), feature = "mock"))]
    {
        println!("initializing mock zkvm backend");
        Ok(Box::new(MockBackend::new()?))
    }

    #[cfg(not(any(feature = "risc0", feature = "sp1", feature = "mock")))]
    {
        return Err(ClvmZkError::ConfigurationError(
            "no zkvm backend enabled - enable one of 'risc0', 'sp1', or 'mock'".to_string(),
        ));
    }
}

#[cfg(feature = "risc0")]
use clvm_zk_risc0::Risc0Backend;

#[cfg(feature = "sp1")]
use clvm_zk_sp1::Sp1Backend;

#[cfg(feature = "mock")]
use clvm_zk_mock::MockBackend;

#[cfg(feature = "mock")]
pub use clvm_zk_mock as mock;

#[cfg(feature = "risc0")]
impl ZKCLVMBackend for Risc0Backend {
    fn prove_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
    ) -> Result<ZKClvmResult, ClvmZkError> {
        self.prove_chialisp_program(chialisp_source, program_parameters)
    }

    fn prove_with_nullifier(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        spend_secret: [u8; 32],
    ) -> Result<ZKClvmResult, ClvmZkError> {
        let input = clvm_zk_core::Input {
            chialisp_source: chialisp_source.to_string(),
            program_parameters: program_parameters.to_vec(),
            spend_secret: Some(spend_secret),
            serial_randomness: None,
            serial_commitment: None,
            merkle_path: None,
            coin_commitment: None,
            merkle_root: None,
            puzzle_hash: None,
        };
        self.prove_with_input(input)
    }

    fn verify_proof(&self, proof: &[u8]) -> Result<(bool, [u8; 32], Vec<u8>), ClvmZkError> {
        self.verify_proof_and_extract(proof)
    }

    fn backend_name(&self) -> &'static str {
        self.backend_name()
    }

    fn is_available(&self) -> bool {
        self.is_available()
    }
}

#[cfg(feature = "sp1")]
impl ZKCLVMBackend for Sp1Backend {
    fn prove_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
    ) -> Result<ZKClvmResult, ClvmZkError> {
        self.prove_chialisp_program(chialisp_source, program_parameters)
    }

    fn prove_with_nullifier(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        spend_secret: [u8; 32],
    ) -> Result<ZKClvmResult, ClvmZkError> {
        let input = clvm_zk_core::Input {
            chialisp_source: chialisp_source.to_string(),
            program_parameters: program_parameters.to_vec(),
            spend_secret: Some(spend_secret),
            serial_randomness: None,
            serial_commitment: None,
            merkle_path: None,
            coin_commitment: None,
            merkle_root: None,
            puzzle_hash: None,
        };
        self.prove_with_input(input)
    }

    fn verify_proof(&self, proof: &[u8]) -> Result<(bool, [u8; 32], Vec<u8>), ClvmZkError> {
        self.verify_proof_and_extract(proof)
    }

    fn backend_name(&self) -> &'static str {
        self.backend_name()
    }

    fn is_available(&self) -> bool {
        self.is_available()
    }
}

#[cfg(feature = "mock")]
impl ZKCLVMBackend for MockBackend {
    fn prove_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
    ) -> Result<ZKClvmResult, ClvmZkError> {
        self.prove_chialisp_program(chialisp_source, program_parameters)
    }

    fn prove_with_nullifier(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        spend_secret: [u8; 32],
    ) -> Result<ZKClvmResult, ClvmZkError> {
        let input = clvm_zk_core::Input {
            chialisp_source: chialisp_source.to_string(),
            program_parameters: program_parameters.to_vec(),
            spend_secret: Some(spend_secret),
            serial_randomness: None,
            serial_commitment: None,
            merkle_path: None,
            coin_commitment: None,
            merkle_root: None,
            puzzle_hash: None,
        };
        self.prove_with_input(input)
    }

    fn verify_proof(&self, proof: &[u8]) -> Result<(bool, [u8; 32], Vec<u8>), ClvmZkError> {
        self.verify_proof_and_extract(proof)
    }

    fn backend_name(&self) -> &'static str {
        self.backend_name()
    }

    fn is_available(&self) -> bool {
        self.is_available()
    }
}
