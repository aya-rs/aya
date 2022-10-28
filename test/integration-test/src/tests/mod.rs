use anyhow::bail;
use lazy_static::lazy_static;
use libc::{uname, utsname};
use regex::Regex;
use std::{ffi::CStr, mem};

pub mod elf;
pub mod load;
pub mod smoke;

pub use integration_test_macros::integration_test;
#[derive(Debug)]
pub struct IntegrationTest {
    pub name: &'static str,
    pub test_fn: fn(),
}

pub(crate) fn kernel_version() -> anyhow::Result<(u8, u8, u8)> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"^([0-9]+)\.([0-9]+)\.([0-9]+)").unwrap();
    }
    let mut data: utsname = unsafe { mem::zeroed() };
    let ret = unsafe { uname(&mut data) };
    assert!(ret >= 0, "libc::uname failed.");
    let release_cstr = unsafe { CStr::from_ptr(data.release.as_ptr()) };
    let release = release_cstr.to_string_lossy();
    if let Some(caps) = RE.captures(&release) {
        let major = caps.get(1).unwrap().as_str().parse().unwrap();
        let minor = caps.get(2).unwrap().as_str().parse().unwrap();
        let patch = caps.get(3).unwrap().as_str().parse().unwrap();
        Ok((major, minor, patch))
    } else {
        bail!("no kernel version found");
    }
}

inventory::collect!(IntegrationTest);
