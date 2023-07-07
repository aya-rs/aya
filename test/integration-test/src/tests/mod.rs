use anyhow::bail;
use libc::{uname, utsname};
use regex::Regex;
use std::{cell::OnceCell, ffi::CStr, mem};

pub mod bpf_probe_read;
pub mod btf_relocations;
pub mod elf;
pub mod load;
pub mod log;
pub mod rbpf;
pub mod relocations;
pub mod smoke;

#[derive(Debug)]
pub struct IntegrationTest {
    pub name: &'static str,
    pub test_fn: fn(),
}

pub(crate) fn kernel_version() -> anyhow::Result<(u8, u8, u8)> {
    static mut RE: OnceCell<Regex> = OnceCell::new();
    let re =
        unsafe { &mut RE }.get_or_init(|| Regex::new(r"^([0-9]+)\.([0-9]+)\.([0-9]+)").unwrap());
    let mut data: utsname = unsafe { mem::zeroed() };
    let ret = unsafe { uname(&mut data) };
    assert!(ret >= 0, "libc::uname failed.");
    let release_cstr = unsafe { CStr::from_ptr(data.release.as_ptr()) };
    let release = release_cstr.to_string_lossy();
    if let Some(caps) = re.captures(&release) {
        let major = caps.get(1).unwrap().as_str().parse().unwrap();
        let minor = caps.get(2).unwrap().as_str().parse().unwrap();
        let patch = caps.get(3).unwrap().as_str().parse().unwrap();
        Ok((major, minor, patch))
    } else {
        bail!("no kernel version found");
    }
}

inventory::collect!(IntegrationTest);
