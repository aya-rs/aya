//! Array types.

#[expect(
    clippy::module_inception,
    reason = "module name matches the exported type"
)]
mod array;
mod array_of_maps;
mod per_cpu_array;
mod program_array;

pub use array::*;
pub use array_of_maps::ArrayOfMaps;
pub use per_cpu_array::PerCpuArray;
pub use program_array::ProgramArray;
