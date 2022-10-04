//! Array types.
#[allow(clippy::module_inception)]
mod array;
mod per_cpu_array;
mod program_array;

pub use array::*;
pub use per_cpu_array::PerCpuArray;
pub use program_array::ProgramArray;
