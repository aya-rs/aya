//! [![](https://aya-rs.dev/assets/images/aya_logo_docs.svg)](https://aya-rs.dev)
//!
//! A library to work with eBPF programs.
//!
//! eBPF is a technology that allows running user-supplied programs inside the
//! Linux kernel. For more info see
//! [https://ebpf.io/what-is-ebpf](https://ebpf.io/what-is-ebpf).
//!
//! Aya is an eBPF library built with a focus on operability and developer experience. It does not
//! rely on [libbpf](https://github.com/libbpf/libbpf) nor [bcc](https://github.com/iovisor/bcc) -
//! it's built from the ground up purely in Rust, using only the [libc](https://crates.io/libc)
//! crate to execute syscalls. With BTF support and when linked with musl, it offers a true
//! [compile once, run everywhere
//! solution](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html),
//! where a single self-contained binary can be deployed on many linux distributions
//! and kernel versions.
//!
//! Some of the major features provided include:
//!
//! * Support for the **BPF Type Format** (BTF), which is transparently enabled when
//!   supported by the target kernel. This allows eBPF programs compiled against
//!   one kernel version to run on different kernel versions without the need to
//!   recompile.
//! * Support for function call relocation and global data maps, which
//!   allows eBPF programs to make **function calls** and use **global variables
//!   and initializers**.
//! * **Async support** with both [tokio] and [async-std].
//! * Easy to deploy and fast to build: aya doesn't require a kernel build or
//!   compiled headers, and not even a C toolchain; a release build completes in a matter
//!   of seconds.
//!
//! [tokio]: https://docs.rs/tokio
//! [async-std]: https://docs.rs/async-std

#![doc(
    html_logo_url = "https://aya-rs.dev/assets/images/crabby.svg",
    html_favicon_url = "https://aya-rs.dev/assets/images/crabby.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(
    clippy::all,
    clippy::use_self,
    absolute_paths_not_starting_with_crate,
    deprecated_in_future,
    elided_lifetimes_in_paths,
    explicit_outlives_requirements,
    ffi_unwind_calls,
    keyword_idents,
    //let_underscore_drop,
    macro_use_extern_crate,
    meta_variable_misuse,
    missing_abi,
    //missing_copy_implementations,
    missing_docs,
    non_ascii_idents,
    noop_method_call,
    rust_2021_incompatible_closure_captures,
    rust_2021_incompatible_or_patterns,
    rust_2021_prefixes_incompatible_syntax,
    rust_2021_prelude_collisions,
    single_use_lifetimes,
    trivial_numeric_casts,
    unreachable_pub,
    //unsafe_op_in_unsafe_fn,
    unstable_features,
    unused_crate_dependencies,
    unused_extern_crates,
    unused_import_braces,
    unused_lifetimes,
    unused_macro_rules,
    //unused_qualifications, https://github.com/rust-lang/rust/commit/9ccc7b7 added size_of to the prelude, but we need to continue to qualify it so that we build on older compilers.
    //unused_results,
)]
#![allow(clippy::missing_safety_doc, clippy::len_without_is_empty)]
#![cfg_attr(
    all(feature = "async_tokio", feature = "async_std"),
    allow(unused_crate_dependencies)
)]

mod bpf;
use aya_obj::generated;
pub mod maps;
use aya_obj as obj;
pub mod pin;
pub mod programs;
pub use programs::loaded_programs;
mod sys;
pub mod util;

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

pub use bpf::*;
pub use obj::btf::{Btf, BtfError};
pub use object::Endianness;
#[doc(hidden)]
pub use sys::netlink_set_link_up;

// See https://github.com/rust-lang/rust/pull/124210; this structure exists to avoid crashing the
// process when we try to close a fake file descriptor.
#[derive(Debug)]
struct MockableFd {
    #[cfg(not(test))]
    fd: OwnedFd,
    #[cfg(test)]
    fd: Option<OwnedFd>,
}

impl MockableFd {
    #[cfg(test)]
    const fn mock_signed_fd() -> i32 {
        1337
    }

    #[cfg(test)]
    const fn mock_unsigned_fd() -> u32 {
        1337
    }

    #[cfg(not(test))]
    fn from_fd(fd: OwnedFd) -> Self {
        Self { fd }
    }

    #[cfg(test)]
    fn from_fd(fd: OwnedFd) -> Self {
        Self { fd: Some(fd) }
    }

    #[cfg(not(test))]
    fn try_clone(&self) -> std::io::Result<Self> {
        let Self { fd } = self;
        let fd = fd.try_clone()?;
        Ok(Self { fd })
    }

    #[cfg(test)]
    fn try_clone(&self) -> std::io::Result<Self> {
        let Self { fd } = self;
        let fd = fd.as_ref().map(OwnedFd::try_clone).transpose()?;
        Ok(Self { fd })
    }
}

impl AsFd for MockableFd {
    #[cfg(not(test))]
    fn as_fd(&self) -> BorrowedFd<'_> {
        let Self { fd } = self;
        fd.as_fd()
    }

    #[cfg(test)]
    fn as_fd(&self) -> BorrowedFd<'_> {
        let Self { fd } = self;
        fd.as_ref().unwrap().as_fd()
    }
}

impl Drop for MockableFd {
    #[cfg(not(test))]
    fn drop(&mut self) {
        // Intentional no-op.
    }

    #[cfg(test)]
    fn drop(&mut self) {
        use std::os::fd::AsRawFd as _;

        let Self { fd } = self;
        if fd.as_ref().unwrap().as_raw_fd() >= Self::mock_signed_fd() {
            let fd: OwnedFd = fd.take().unwrap();
            std::mem::forget(fd)
        }
    }
}
