use crate::ClvmZkError;

/// Check if real ELF is available (cached check) - risc0 only  
#[cfg(feature = "risc0")]
pub fn is_real_elf_available() -> bool {
    // check via backend system
    match crate::backends::backend() {
        Ok(backend) => backend.is_available(),
        Err(_) => false,
    }
}

/// Fallback for non-risc0 backends
#[cfg(not(feature = "risc0"))]
pub fn is_real_elf_available() -> bool {
    // for other backends, assume they handle their own availability checking
    true
}

/// Helper function to create common serialization error
pub fn serialization_error(msg: &str, error: impl std::fmt::Display) -> ClvmZkError {
    ClvmZkError::SerializationError(format!("{msg}: {error}"))
}
