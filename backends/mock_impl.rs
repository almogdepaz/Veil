// implement the trait for the mock backend
#[cfg(feature = "mock")]
impl ZKCLVMBackend for MockBackend {
    fn prove_program(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        _legacy_parameters: &[ProgramParameter], // unused in mock implementation
    ) -> Result<ZKClvmResult, ClvmZkError> {
        self.prove_chialisp_program(chialisp_source, program_parameters)
    }

    fn prove_with_nullifier(
        &self,
        chialisp_source: &str,
        program_parameters: &[ProgramParameter],
        _legacy_parameters: &[ProgramParameter], // unused in mock implementation
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