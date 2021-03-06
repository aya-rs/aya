//! A library to work with eBPF programs.
//!
//! eBPF is a technology that allows running user-supplied programs inside the
//! Linux kernel. For more info see
//! [https://ebpf.io/what-is-ebpf](https://ebpf.io/what-is-ebpf).
//!
//! Aya is an eBPF library built with a focus on operability and developer experience. It does not
//! rely on [libbpf](https://github.com/libbpf/libbpf) nor [bcc](https://github.com/iovisor/bcc) -
//! it's built from the ground up purely in Rust, using the Linux system call interface directly to
//! load and interact with programs. When linked with musl and in conjunction with BTF, it provides
//! a true [compile once, run everywhere solution](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html).
//!
//! Some of the major features provided include:
//!
//! * Support for the BPF Type Format (BTF), which is transparently enabled when
//!   supported by the target kernel.
//! * Support for global data maps, which means that eBPF programs can make use of global
//!   data and variables. This is especially useful when the eBPF code itself is written
//!   in Rust, and makes use of byte literals and other initializers that result
//!   in global data being created.
//! * Support for function calls, so eBPF programs can call other functions and are not
//!   forced to inline everything.
//! * Async support with both [tokio](https://docs.rs/tokio) and [async-std](https://docs.rs/async-std).
//! * Easy to deploy and fast to build: aya doesn't require kernel headers nor a
//!   C toolchain and a release build completes in a matter of seconds.
//!
//!
//! # Minimum kernel version
//!
//! Aya currently supports kernels version 5.4 (latest LTS) and newer.
#![deny(clippy::all)]

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
