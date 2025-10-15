//! SP1 backend library - provides self-contained sp1 integration

mod backend;
mod methods;

// re-export the methods constants
pub use methods::*;
// re-export everything from the backend implementation
pub use backend::*;
