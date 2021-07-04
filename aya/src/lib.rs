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
#![deny(clippy::all)]
#![allow(clippy::missing_safety_doc, clippy::len_without_is_empty)]

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate bitflags;

mod bpf;
mod generated;
pub mod maps;
mod obj;
pub mod programs;
mod sys;
pub mod util;

pub use bpf::*;
pub use obj::btf::{Btf, BtfError};
pub use object::Endianness;
