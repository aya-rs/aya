use anyhow::{anyhow, Context as _};
use libc::{uname, utsname};
use std::{ffi::CStr, io::Error, mem};

pub fn kernel_version() -> anyhow::Result<(u8, u8, u8)> {
    let mut data: utsname = unsafe { mem::zeroed() };
    let ret = unsafe { uname(&mut data) };
    if ret != 0 {
        return Err(Error::last_os_error()).context("uname failed");
    }
    let utsname { release, .. } = data;
    let release: &[u8] =
        unsafe { std::slice::from_raw_parts(release.as_ptr() as _, release.len()) };
    let s = CStr::from_bytes_until_nul(release)?;
    let s = s.to_str()?;

    // Adapted from https://github.com/eminence/procfs/blob/d7ea846/procfs/src/sys/kernel/mod.rs#L51-L70.
    let pos = s.find(|c: char| c != '.' && !c.is_ascii_digit());
    let kernel = if let Some(pos) = pos {
        let (s, _) = s.split_at(pos);
        s
    } else {
        s
    };
    let mut kernel_split = kernel.split('.');

    let major = kernel_split
        .next()
        .ok_or(anyhow!("Missing major version component"))?;
    let minor = kernel_split
        .next()
        .ok_or(anyhow!("Missing minor version component"))?;
    let patch = kernel_split
        .next()
        .ok_or(anyhow!("Missing patch version component"))?;

    let major = major.parse().context("Failed to parse major version")?;
    let minor = minor.parse().context("Failed to parse minor version")?;
    let patch = patch.parse().context("Failed to parse patch version")?;

    Ok((major, minor, patch))
}
