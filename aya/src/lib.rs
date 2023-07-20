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
#![deny(clippy::all, missing_docs)]
#![allow(clippy::missing_safety_doc, clippy::len_without_is_empty)]

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate bitflags;

mod bpf;
use aya_obj::generated;
pub mod maps;
use aya_obj as obj;
pub mod pin;
pub mod programs;
pub use programs::loaded_programs;
mod sys;
pub mod util;

pub use bpf::*;
pub use obj::btf::{Btf, BtfError};
pub use object::Endianness;

#[cfg(test)]
mod tests {
    use cargo_metadata::{Metadata, MetadataCommand};
    use std::{
        env,
        fs::{read_to_string, File},
        io::Write,
    };

    #[test]
    #[cfg_attr(miri, ignore = "uses open() which is not supported by miri")]
    fn public_api() {
        let rustdoc_json = rustdoc_json::Builder::default()
            .toolchain("nightly")
            .package("aya")
            .all_features(true)
            .build()
            .unwrap();

        let public_api = public_api::Builder::from_rustdoc_json(rustdoc_json)
            .build()
            .unwrap();

        let metadata = MetadataCommand::new()
            .no_deps()
            .exec()
            .expect("failed to run cargo metadata");
        let Metadata { workspace_root, .. } = &metadata;

        let path = workspace_root.join("aya/src/public-api.txt");

        if env::var("UPDATE_EXPECT").is_ok() {
            let mut f = File::create(&path).expect("failed to create aya/src/public-api.txt");
            f.write_all(public_api.to_string().as_bytes())
                .expect("failed to write aya/src/public-api.txt");
        }
        let current_api = read_to_string(path).expect("failed to read aya/src/public-api.txt");

        if current_api != public_api.to_string() {
            panic!("public api has changed. please bless by re-running tests with UPDATE_EXPECT=1");
        }
    }
}
