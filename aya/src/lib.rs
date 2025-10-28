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
#![deny(missing_docs)]

mod bpf;
pub mod maps;
pub mod pin;
pub mod programs;
pub mod sys;
pub mod util;

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

pub use aya_obj::btf::{Btf, BtfError};
pub use bpf::*;
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
        let fd = Some(fd);
        Self { fd }
    }

    #[cfg(not(test))]
    fn inner(&self) -> &OwnedFd {
        let Self { fd } = self;
        fd
    }

    #[cfg(test)]
    fn inner(&self) -> &OwnedFd {
        let Self { fd } = self;
        fd.as_ref().unwrap()
    }

    #[cfg(not(test))]
    fn into_inner(self) -> OwnedFd {
        self.fd
    }

    #[cfg(test)]
    fn into_inner(mut self) -> OwnedFd {
        self.fd.take().unwrap()
    }

    fn try_clone(&self) -> std::io::Result<Self> {
        let fd = self.inner();
        let fd = fd.try_clone()?;
        Ok(Self::from_fd(fd))
    }
}

impl<T> From<T> for MockableFd
where
    OwnedFd: From<T>,
{
    fn from(value: T) -> Self {
        let fd = OwnedFd::from(value);
        Self::from_fd(fd)
    }
}

impl AsFd for MockableFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner().as_fd()
    }
}

impl AsRawFd for MockableFd {
    fn as_raw_fd(&self) -> RawFd {
        self.inner().as_raw_fd()
    }
}

impl FromRawFd for MockableFd {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Self::from_fd(fd)
    }
}

#[cfg(test)]
impl Drop for MockableFd {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd as _;

        let Self { fd } = self;
        let fd = fd.take().unwrap();
        if fd.as_raw_fd() < Self::mock_signed_fd() {
            std::mem::drop(fd)
        } else {
            std::mem::forget(fd)
        }
    }
}
