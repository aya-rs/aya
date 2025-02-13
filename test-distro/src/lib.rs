use std::path::PathBuf;

use anyhow::Context as _;
use nix::sys::utsname::uname;

/// Kernel modules are in `/lib/modules`.
/// They may be in the root of this directory,
/// or in subdirectory named after the kernel release.
pub fn resolve_modules_dir() -> anyhow::Result<PathBuf> {
    let modules_dir = PathBuf::from("/lib/modules");
    let stat = modules_dir
        .metadata()
        .with_context(|| format!("{modules_dir:?} doesn't exist"))?;
    if stat.is_dir() {
        return Ok(modules_dir);
    }

    let utsname = uname().context("failed to get kernel release")?;
    let release = utsname.release();
    let modules_dir = modules_dir.join(release);
    let stat = modules_dir
        .metadata()
        .with_context(|| format!("{modules_dir:?} doesn't exist"))?;
    anyhow::ensure!(stat.is_dir(), "{modules_dir:?} is not a directory",);
    Ok(modules_dir)
}
