use serde::{Deserialize, Serialize};

extern crate alloc;
use alloc::vec::Vec;

// re-export from clvm_zk_core (no_std compatible)
pub use clvm_zk_core::AggregatedOutput;

/// aggregated proof combining multiple transaction proofs (host-side only)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedProof {
    /// single recursive proof replacing N child proofs
    pub zk_proof: Vec<u8>,
    
    /// all nullifiers from aggregated transactions
    pub nullifiers: Vec<[u8; 32]>,
    
    /// all conditions from aggregated transactions
    pub conditions: Vec<Vec<u8>>,
    
    /// metadata
    pub proof_count: usize,
}
