//! An eBPF object file parsing library with BTF and relocation support.
//!
//! # Status
//!
//! This crate includes code that started as internal API used by
//! the [aya] crate. It has been split out so that it can be used by
//! other projects that deal with eBPF object files. Unless you're writing
//! low level eBPF plumbing tools, you should not need to use this crate
//! but see the [aya] crate instead.
//!
//! The API as it is today has a few rough edges and is generally not as
//! polished nor stable as the main [aya] crate API. As always,
//! improvements welcome!
//!
//! [aya]: https://github.com/aya-rs/aya
//!
//! # Overview
//!
//! eBPF programs written with [libbpf] or [aya-bpf] are usually compiled
//! into an ELF object file, using various sections to store information
//! about the eBPF programs.
//!
//! `aya-obj` is a library for parsing such eBPF object files, with BTF and
//! relocation support.
//!
//! [libbpf]: https://github.com/libbpf/libbpf
//! [aya-bpf]: https://github.com/aya-rs/aya
//!
//! # Example
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
//! #[cfg(feature = "std")]
//! let text_sections = std::collections::HashSet::new();
//! #[cfg(not(feature = "std"))]
//! let text_sections = hashbrown::HashSet::new();
//! object.relocate_calls(&text_sections).unwrap();
//! object.relocate_maps(std::iter::empty(), &text_sections).unwrap();
//!
//! // Run with rbpf
//! let function = object.functions.get(&object.programs["prog_name"].function_key()).unwrap();
//! let instructions = &function.instructions;
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

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;
#[cfg(not(feature = "std"))]
mod std {
    pub mod error {
        pub use core_error::Error;
    }
    pub use core::*;

    pub mod os {
        pub mod fd {
            pub type RawFd = core::ffi::c_int;
        }
    }
}

pub mod btf;
pub mod generated;
pub mod maps;
pub mod obj;
pub mod programs;
pub mod relocation;
pub mod stats;
mod util;

pub use maps::Map;
pub use obj::*;
pub use stats::BpfStatsType;

/// An error returned from the verifier.
///
/// Provides a [`Debug`] implementation that doesn't escape newlines.
pub struct VerifierLog(alloc::string::String);

impl VerifierLog {
    /// Create a new verifier log.
    pub fn new(log: alloc::string::String) -> Self {
        Self(log)
    }
}

impl std::fmt::Debug for VerifierLog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Self(log) = self;
        f.write_str(log)
    }
}

impl std::fmt::Display for VerifierLog {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        <Self as std::fmt::Debug>::fmt(self, f)
    }
}
