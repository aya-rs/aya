//! A library for loading and relocating eBPF object files.

#![doc(
    html_logo_url = "https://aya-rs.dev/assets/images/crabby.svg",
    html_favicon_url = "https://aya-rs.dev/assets/images/crabby.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(clippy::all)]
#![allow(clippy::missing_safety_doc, clippy::len_without_is_empty)]

pub mod btf;
pub mod generated;
pub mod maps;
pub mod obj;
pub mod programs;
pub mod relocation;
mod util;

pub use obj::*;
