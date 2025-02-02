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

use anyhow::{Context as _, anyhow};
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
        resolve_modules_dir().context("failed to resolve modules dir")?
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

            let module_name = path
                .file_name()
                .ok_or_else(|| anyhow!("{} does not have a file name", path.display()))?
                .to_str()
                .ok_or_else(|| anyhow!("{} is not valid utf-8", path.display()))?;

            let (module_name, compressed) =
                if let Some(module_name) = module_name.strip_suffix(".xz") {
                    (module_name, true)
                } else {
                    (module_name, false)
                };

            let module_name = if let Some(module_name) = module_name.strip_suffix(".ko") {
                module_name
            } else {
                // Not a kernel module
                continue;
            };

            let mut f =
                File::open(path).with_context(|| format!("failed to open: {}", path.display()))?;
            let stat = f
                .metadata()
                .with_context(|| format!("failed to get metadata for {}", path.display()))?;

            if compressed {
                let mut decoder = XzDecoder::new(f);
                // We don't know the size of the decompressed data, so we assume it's
                // no more than twice the size of the compressed data.
                let mut decompressed = Vec::with_capacity(stat.len() as usize * 2);
                decoder.read_to_end(&mut decompressed)?;
                read_aliases_from_module(&decompressed, module_name, &mut output)
            } else {
                let mut buf = Vec::with_capacity(stat.len() as usize);
                f.read_to_end(&mut buf)
                    .with_context(|| format!("failed to read: {}", path.display()))?;
                read_aliases_from_module(&buf, module_name, &mut output)
            }
            .with_context(|| format!("failed to read aliases from module {}", path.display()))?;
        }
    }
    Ok(())
}

fn read_aliases_from_module(
    contents: &[u8],
    module_name: &str,
    output: &mut BufWriter<&File>,
) -> Result<(), anyhow::Error> {
    let obj = object::read::File::parse(contents).context("failed to parse")?;

    let section = obj
        .sections()
        .find(|s| s.name() == Ok(".modinfo"))
        .context("no .modinfo section")?;
    let section_idx = section.index();
    let data = section
        .data()
        .context("failed to get modinfo section data")?;

    for s in obj.symbols() {
        if s.section_index() != Some(section_idx) {
            continue;
        }
        let name = s
            .name()
            .with_context(|| format!("failed to get name of symbol idx {}", s.index()))?;
        if name.contains("alias") {
            let start = s.address() as usize;
            let end = start + s.size() as usize;
            let sym_data = &data[start..end];
            let cstr = std::ffi::CStr::from_bytes_with_nul(sym_data)
                .with_context(|| format!("failed to convert {:?} to cstr", sym_data))?;
            let sym_str = cstr
                .to_str()
                .with_context(|| format!("failed to convert {:?} to str", cstr))?;
            let alias = sym_str
                .strip_prefix("alias=")
                .with_context(|| format!("failed to strip prefix 'alias=' from {}", sym_str))?;
            writeln!(output, "alias {} {}", alias, module_name).expect("write");
        }
    }
    Ok(())
}
