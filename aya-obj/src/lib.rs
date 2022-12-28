//! A library for loading and relocating eBPF object files.
//!
//! ## Overview
//!
//! eBPF programs written with [libbpf] or [aya-bpf] are usually compiled
//! into an ELF object file, using various section to store information
//! about the eBPF programs.
//!
//! `aya-obj` is a library that loads, parses and processes such eBPF
//! object files.
//!
//! [libbpf]: https://github.com/libbpf/libbpf
//! [aya-bpf]: https://github.com/aya-rs/aya
//!
//! ## Example
//!
//! This example loads a simple eBPF program and runs it with [rbpf].
//!
//! ```no_run
//! use aya_obj::{generated::bpf_insn, Object};
//!
//! // Parse the object file
//! let bytes = std::fs::read("program.o").unwrap();
//! let mut object = Object::parse(&bytes).unwrap();
//! // Relocate the programs
//! object.relocate_calls().unwrap();
//! object.relocate_maps(std::iter::empty()).unwrap();
//!
//! // Run with rbpf
//! let program = object.programs.iter().next().unwrap().1;
//! let instructions = &program.function.instructions;
//! let data = unsafe {
//!     core::slice::from_raw_parts(
//!         instructions.as_ptr() as *const u8,
//!         instructions.len() * core::mem::size_of::<bpf_insn>(),
//!     )
//! };
//! let vm = rbpf::EbpfVmNoData::new(Some(data)).unwrap();
//! let _return = vm.execute_program().unwrap();
//! ```
//!
//! [rbpf]: https://github.com/qmonnet/rbpf

#![no_std]
#![doc(
    html_logo_url = "https://aya-rs.dev/assets/images/crabby.svg",
    html_favicon_url = "https://aya-rs.dev/assets/images/crabby.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(clippy::all, missing_docs)]
#![allow(clippy::missing_safety_doc, clippy::len_without_is_empty)]

#![cfg_attr(feature = "no_std", feature(error_in_core))]

#[cfg(not(feature = "no_std"))]
pub(crate) use thiserror_std as thiserror;
#[cfg(feature = "no_std")]
pub(crate) use thiserror_core as thiserror;

extern crate alloc;
#[cfg(not(feature = "no_std"))]
extern crate std;

pub mod btf;
pub mod generated;
pub mod maps;
pub mod obj;
pub mod programs;
pub mod relocation;
mod util;

pub use maps::Map;
pub use obj::*;
