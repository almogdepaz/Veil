//! zkvm backend stuff
//!
//! simple wrapper so you can swap between risc0, sp1, etc without changing your code

use crate::{ClvmZkError, ProgramParameter};

pub use clvm_zk_core::{ZKClvmNullifierResult, ZKClvmResult};

/// What every zkvm backend needs to do
pub trait ZKCLVMBackend {
    /// Make a zk proof with guest-side compilation
    fn prove_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        legacy_parameters: &[ProgramParameter], // For backward compatibility
    ) -> Result<ZKClvmResult, ClvmZkError>;

    /// Make a zk proof with nullifier for spending coins
    fn prove_with_nullifier(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        legacy_parameters: &[ProgramParameter], // For backward compatibility
        spend_secret: [u8; 32],
    ) -> Result<ZKClvmNullifierResult, ClvmZkError>;

    /// Check proof and extract program hash and output
    fn verify_proof(&self, proof: &[u8]) -> Result<(bool, [u8; 32], Vec<u8>), ClvmZkError>;

    /// Backend name for debugging
    fn backend_name(&self) -> &'static str;

    /// Is this backend actually available?
    fn is_available(&self) -> bool;
}

/// Pick which zkvm to use based on features
pub fn backend() -> Result<Box<dyn ZKCLVMBackend>, ClvmZkError> {
    #[cfg(feature = "risc0")]
    {
        println!("🔧 initializing risc0 zkvm backend");
        return Ok(Box::new(Risc0Backend::new()?));
    }

    #[cfg(feature = "sp1")]
    {
        println!("🔧 initializing sp1 zkvm backend");
        return Ok(Box::new(Sp1Backend::new()?));
    }

    #[cfg(feature = "mock")]
    {
        println!("🔧 initializing mock zkvm backend");
        Ok(Box::new(MockBackend::new()?))
    }

    #[cfg(not(any(feature = "risc0", feature = "sp1", feature = "mock")))]
    {
        Err(ClvmZkError::ConfigurationError(
            "no zkvm backend enabled - enable one of 'risc0', 'sp1', or 'mock'".to_string(),
        ))
    }
}

// use backends directly - no wrapper needed since types are unified
#[cfg(feature = "risc0")]
use clvm_zk_risc0::Risc0Backend;

#[cfg(feature = "sp1")]
use clvm_zk_sp1::Sp1Backend;

#[cfg(feature = "mock")]
use clvm_zk_mock::MockBackend;

// expose mock backend module for testing
#[cfg(feature = "mock")]
pub use clvm_zk_mock as mock;

// implement the trait for the risc0 backend
#[cfg(feature = "risc0")]
impl ZKCLVMBackend for Risc0Backend {
    fn prove_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        _legacy_parameters: &[ProgramParameter], // Unused in new implementation
    ) -> Result<ZKClvmResult, ClvmZkError> {
        let result = self.prove_chialisp_program(chialisp_source, program_parameters)?;
        Ok(ZKClvmResult {
            result: result.result,
            cost: result.cost,
            proof: result.proof,
        })
    }

    fn prove_with_nullifier(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        _legacy_parameters: &[ProgramParameter], // Unused in new implementation
        spend_secret: [u8; 32],
    ) -> Result<ZKClvmNullifierResult, ClvmZkError> {
        let result =
            self.prove_chialisp_with_nullifier(chialisp_source, program_parameters, spend_secret)?;
        Ok(ZKClvmNullifierResult {
            nullifier: result.nullifier,
            result: result.result,
            cost: result.cost,
            proof: result.proof,
        })
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

// implement the trait for the sp1 backend
#[cfg(feature = "sp1")]
impl ZKCLVMBackend for Sp1Backend {
    fn prove_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        _legacy_parameters: &[ProgramParameter], // ignored for consistency with trait
    ) -> Result<ZKClvmResult, ClvmZkError> {
        let result = self.prove_chialisp_program(chialisp_source, program_parameters)?;
        Ok(ZKClvmResult {
            result: result.result,
            cost: result.cost,
            proof: result.proof,
        })
    }

    fn prove_with_nullifier(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        _legacy_parameters: &[ProgramParameter], // ignored for consistency with trait
        spend_secret: [u8; 32],
    ) -> Result<ZKClvmNullifierResult, ClvmZkError> {
        let result =
            self.prove_chialisp_with_nullifier(chialisp_source, program_parameters, spend_secret)?;
        Ok(ZKClvmNullifierResult {
            nullifier: result.nullifier,
            result: result.result,
            cost: result.cost,
            proof: result.proof,
        })
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

// implement the trait for the mock backend
#[cfg(feature = "mock")]
impl ZKCLVMBackend for MockBackend {
    fn prove_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        _legacy_parameters: &[ProgramParameter], // ignored for mock
    ) -> Result<ZKClvmResult, ClvmZkError> {
        self.prove_chialisp_program(chialisp_source, program_parameters)
    }

    fn prove_with_nullifier(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        _legacy_parameters: &[ProgramParameter], // ignored for mock
        spend_secret: [u8; 32],
    ) -> Result<ZKClvmNullifierResult, ClvmZkError> {
        self.prove_chialisp_with_nullifier(chialisp_source, program_parameters, spend_secret)
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
