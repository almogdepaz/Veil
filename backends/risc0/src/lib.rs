//! risc0 backend library - provides self-contained risc0 integration

mod methods;
mod backend;

// include common backend utilities
mod common;

// include global common with prepare_guest_inputs
#[path = "../../common.rs"]
pub mod global_common;

// re-export the methods constants
pub use methods::*;
// re-export everything from the backend implementation
pub use backend::*;