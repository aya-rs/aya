use std::path::Path;

use anyhow::Context as _;

#[derive(Clone, Copy)]
pub enum Compression {
    None,
    Xz,
    Zstd,
}

/// The VM stores kernel modules directly in `/lib/modules`.
pub fn resolve_modules_dir() -> anyhow::Result<&'static str> {
    let modules_dir = "/lib/modules";
    let stat = std::fs::metadata(modules_dir).with_context(|| format!("stat(): {modules_dir}"))?;
    anyhow::ensure!(stat.is_dir(), "{modules_dir} is not a directory");
    Ok(modules_dir)
}

pub fn read_to_end(path: &Path, compression: Compression) -> anyhow::Result<Vec<u8>> {
    use std::io::Read as _;

    let mut f = std::fs::File::open(path).context("open()")?;

    let mut contents = Vec::new();

    match compression {
        #[expect(
            clippy::verbose_file_reads,
            reason = "https://github.com/rust-lang/rust-clippy/issues/8051"
        )]
        Compression::None => f.read_to_end(&mut contents),
        Compression::Xz => {
            cfg_select! {
                feature = "xz2" => {
                    reserve_decompressed_capacity(&mut contents, &f)?;
                    xz2::read::XzDecoder::new(f).read_to_end(&mut contents)
                }
                _ => anyhow::bail!("cannot read {} without xz2 feature", path.display()),
            }
        }
        Compression::Zstd => {
            cfg_select! {
                feature = "zstd" => {
                    reserve_decompressed_capacity(&mut contents, &f)?;
                    zstd::stream::read::Decoder::new(f)
                        .context("zstd decoder")?
                        .read_to_end(&mut contents)
                }
                _ => anyhow::bail!("cannot read {} without zstd feature", path.display()),
            }
        }
    }
    .context("read_to_end()")?;

    Ok(contents)
}

#[cfg(any(feature = "xz2", feature = "zstd"))]
fn reserve_decompressed_capacity(
    contents: &mut Vec<u8>,
    file: &std::fs::File,
) -> anyhow::Result<()> {
    let stat = file.metadata().context("metadata()")?;
    let len = usize::try_from(stat.len())
        .ok()
        .and_then(|len| len.checked_mul(2))
        .ok_or_else(|| anyhow::anyhow!("2 * {stat:?}.len() is too large to fit in a usize"))?;
    contents.reserve(len);
    Ok(())
}
