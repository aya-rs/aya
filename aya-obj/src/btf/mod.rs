//! BTF loading, parsing and relocation.

#[expect(clippy::module_inception, reason = "TODO")]
mod btf;
mod extern_types;
mod info;
mod relocation;
mod types;
pub(crate) mod view;

pub use btf::*;
pub use info::*;
pub use relocation::BtfRelocationError;
pub use types::*;
