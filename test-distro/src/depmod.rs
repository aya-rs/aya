//! depmod is used to build the modules.alias file to assist with loading
//! kernel modules.
//!
//! This implementation is incredibly naive and is only designed to work within
//! the constraints of the test environment. Not for production use.

use std::{
    fs::File,
    io::{BufWriter, Read, Write as _},
    path::PathBuf,
};

use anyhow::Context as _;
use clap::Parser;
use object::{Object, ObjectSection, ObjectSymbol};
use test_distro::resolve_modules_dir;
use walkdir::WalkDir;
use xz2::read::XzDecoder;

#[derive(Parser)]
struct Args {
    #[clap(long, short)]
    base_dir: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let Args { base_dir } = Parser::parse();

    let modules_dir = if let Some(base_dir) = base_dir {
        base_dir
    } else {
        resolve_modules_dir().context("Failed to resolve modules dir")?
    };

    let modules_alias = modules_dir.join("modules.alias");
    let f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&modules_alias)
        .with_context(|| format!("failed to open: {}", modules_alias.display()))?;
    let mut output = BufWriter::new(&f);
    for entry in WalkDir::new(modules_dir) {
        let entry = entry.context("failed to read entry in walkdir")?;
        if entry.file_type().is_file() {
            let path = entry.path();
            if let Some(extension) = path.extension() {
                if extension != "ko" && extension != "xz" {
                    continue;
                }
                let module_name = path
                    .file_stem()
                    .ok_or(anyhow::anyhow!("failed to get file stem"))?
                    .to_os_string()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("failed to convert to string"))?
                    .replace(".ko", "");
                let mut f = File::open(path)
                    .with_context(|| format!("failed to open: {}", path.display()))?;
                let stat = f
                    .metadata()
                    .with_context(|| format!("Failed to get metadata for {}", path.display()))?;
                if extension == "xz" {
                    let mut decoder = XzDecoder::new(f);
                    let mut decompressed = Vec::with_capacity(stat.len() as usize * 2);
                    decoder.read_to_end(&mut decompressed)?;
                    read_aliases_from_module(&decompressed, &module_name, &mut output)
                } else {
                    let mut buf = Vec::with_capacity(stat.len() as usize);
                    f.read_to_end(&mut buf)
                        .with_context(|| format!("Failed to read: {}", path.display()))?;
                    read_aliases_from_module(&buf, &module_name, &mut output)
                }
                .with_context(|| {
                    format!("Failed to read aliases from module {}", path.display())
                })?;
            }
        }
    }

    Ok(())
}

fn read_aliases_from_module(
    contents: &[u8],
    module_name: &str,
    output: &mut BufWriter<&File>,
) -> Result<(), anyhow::Error> {
    let obj = object::read::File::parse(contents).context("not an object file")?;

    let (section_idx, data) = obj
        .sections()
        .filter_map(|s| {
            if let Ok(name) = s.name() {
                if name == ".modinfo" {
                    if let Ok(data) = s.data() {
                        return Some((s.index(), data));
                    }
                }
            }
            None
        })
        .next()
        .context("no .modinfo section")?;

    obj.symbols()
        .try_for_each(|s| -> Result<(), anyhow::Error> {
            let name = s.name().context("failed to get symbol name")?;
            if name.contains("alias") && s.section_index() == Some(section_idx) {
                let start = s.address() as usize;
                let end = start + s.size() as usize;
                let sym_data = &data[start..end];
                let cstr = std::ffi::CStr::from_bytes_with_nul(sym_data)
                    .context("failed to convert to cstr")?;
                let sym_str = cstr.to_str().context("failed to convert to str")?;
                let alias = sym_str.replace("alias=", "");
                writeln!(output, "alias {} {}", alias, module_name).expect("write");
            }
            Ok(())
        })?;
    Ok(())
}
