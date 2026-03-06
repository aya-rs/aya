//! depmod is used to build the modules.alias file to assist with loading
//! kernel modules.
//!
//! This implementation is incredibly naive and is only designed to work within
//! the constraints of the test environment. Not for production use.

use std::{io::BufWriter, path::PathBuf};

use anyhow::{Context as _, anyhow};
use clap::Parser;
use object::{Object, ObjectSection, Section};
use test_distro::{read_to_end, resolve_modules_dir};
use walkdir::WalkDir;

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
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();

        let module_name = path
            .file_name()
            .ok_or_else(|| anyhow!("{} does not have a file name", path.display()))?
            .to_str()
            .ok_or_else(|| anyhow!("{} is not valid utf-8", path.display()))?;

        let (module_name, compressed) = if let Some(module_name) = module_name.strip_suffix(".xz") {
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

        let contents = read_to_end(path, compressed)
            .with_context(|| format!("read_to_end({})", path.display()))?;

        read_aliases_from_module(&contents, module_name, &mut output)
            .with_context(|| format!("failed to read aliases from module {}", path.display()))?;
    }
    Ok(())
}

fn read_aliases_from_module(
    contents: &[u8],
    module_name: &str,
    output: &mut impl std::io::Write,
) -> Result<(), anyhow::Error> {
    let obj = object::read::File::parse(contents).context("failed to parse")?;

    let section = (|| -> anyhow::Result<Option<Section<'_, '_, &[u8]>>> {
        for s in obj.sections() {
            let name = s
                .name_bytes()
                .with_context(|| format!("failed to get name of section idx {}", s.index()))?;
            if name == b".modinfo" {
                return Ok(Some(s));
            }
        }
        Ok(None)
    })()?;
    let section = section.context("failed to find .modinfo section")?;
    let data = section
        .data()
        .context("failed to get modinfo section data")?;

    write_aliases_from_modinfo(data, module_name, output)
}

fn modinfo_entries(data: &[u8]) -> Result<Vec<&str>, anyhow::Error> {
    data.split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            std::str::from_utf8(entry)
                .with_context(|| format!("failed to convert .modinfo entry {entry:?} to str"))
        })
        .collect()
}

fn write_aliases_from_modinfo(
    data: &[u8],
    module_name: &str,
    output: &mut impl std::io::Write,
) -> Result<(), anyhow::Error> {
    for entry in modinfo_entries(data).context("failed to iterate .modinfo entries")? {
        if let Some(alias) = entry.strip_prefix("alias=") {
            writeln!(output, "alias {alias} {module_name}").expect("write");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{modinfo_entries, write_aliases_from_modinfo};

    #[test]
    fn modinfo_entries_reads_nul_delimited_records() {
        let entries = modinfo_entries(
            b"description=test module\0alias=net-sch-clsact\0alias=net-sch-ingress\0",
        )
        .unwrap();

        assert_eq!(
            entries,
            vec![
                "description=test module",
                "alias=net-sch-clsact",
                "alias=net-sch-ingress"
            ]
        );
    }

    #[test]
    fn modinfo_entries_rejects_invalid_utf8() {
        let err = modinfo_entries(b"alias=\xff\0").unwrap_err();

        assert!(format!("{err:#}").contains("failed to convert .modinfo entry"));
    }

    #[test]
    fn write_aliases_from_modinfo_extracts_multiple_aliases() {
        let modinfo =
            b"description=test module\0alias=net-sch-clsact\0alias=net-sch-ingress\0name=sch_ingress\0";
        let mut output = Vec::new();

        write_aliases_from_modinfo(modinfo, "sch_ingress", &mut output).unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("alias net-sch-clsact sch_ingress"));
        assert!(output.contains("alias net-sch-ingress sch_ingress"));
    }
}
