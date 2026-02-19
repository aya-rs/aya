use std::{borrow::Cow, path::Path};

use anyhow::Context as _;
use nix::sys::utsname::uname;

/// Kernel modules are in `/lib/modules`.
/// They may be in the root of this directory,
/// or in subdirectory named after the kernel release.
pub fn resolve_modules_dir() -> anyhow::Result<Cow<'static, Path>> {
    let modules_dir = Path::new("/lib/modules");
    let stat = modules_dir
        .metadata()
        .with_context(|| format!("stat(): {}", modules_dir.display()))?;
    if stat.is_dir() {
        return Ok(modules_dir.into());
    }

    let utsname = uname().context("uname()")?;
    let release = utsname.release();
    let modules_dir = modules_dir.join(release);
    let stat = modules_dir
        .metadata()
        .with_context(|| format!("stat(): {}", modules_dir.display()))?;
    anyhow::ensure!(
        stat.is_dir(),
        "{} is not a directory",
        modules_dir.display()
    );
    Ok(modules_dir.into())
}

pub fn read_to_end(path: &std::path::Path, compressed: bool) -> anyhow::Result<Vec<u8>> {
    use std::io::Read as _;

    let mut f = std::fs::File::open(path).context("open()")?;

    let mut contents = Vec::new();

    if compressed {
        #[cfg(feature = "xz2")]
        {
            let stat = f.metadata().context("metadata()")?;
            #[expect(clippy::manual_ok_err)]
            let len = match usize::try_from(stat.len()) {
                Ok(len) => Some(len),
                Err(std::num::TryFromIntError { .. }) => None,
            }
            .and_then(|len| len.checked_mul(2))
            .ok_or_else(|| anyhow::anyhow!("2 * {stat:?}.len() is too large to fit in a usize"))?;
            contents.reserve(len);

            xz2::read::XzDecoder::new(f).read_to_end(&mut contents)
        }

        #[cfg(not(feature = "xz2"))]
        {
            anyhow::bail!("cannot read {} without xz2 feature", path.display());
        }
    } else {
        f.read_to_end(&mut contents)
    }
    .context("read_to_end()")?;

    Ok(contents)
}
