//! modprobe is used to load kernel modules into the kernel.
//!
//! This implementation is incredibly naive and is only designed to work within
//! the constraints of the test environment. Not for production use.

use std::{fs::File, io::BufRead, path::Path};

use anyhow::{Context as _, anyhow, bail};
use clap::Parser;
use glob::glob;
use nix::kmod::init_module;
use test_distro::{Compression, read_to_end, resolve_modules_dir};

macro_rules! output {
    ($quiet:expr, $($arg:tt)*) => {
        if !$quiet {
            println!($($arg)*);
        }
    };
}

#[derive(Parser)]
struct Args {
    /// Suppress all output and don't return an error code.
    #[clap(short, long, default_value = "false")]
    quiet: bool,

    /// The name of the module to load.
    /// This can be either an alias like `net-sched-sch-ingress` or a module
    /// name like `sch_ingress`.
    name: String,
}

fn main() -> anyhow::Result<()> {
    let Args { quiet, name } = Parser::parse();
    let ret = try_main(quiet, name);
    if quiet { Ok(()) } else { ret }
}

fn try_main(quiet: bool, name: String) -> anyhow::Result<()> {
    let modules_dir = resolve_modules_dir()?;

    output!(quiet, "resolving alias for module: {}", name);
    let modules_alias = modules_dir.join("modules.alias");
    let alias_file = File::open(&modules_alias)
        .with_context(|| format!("open(): {}", modules_alias.display()))?;
    resolve_module(std::io::BufReader::new(alias_file), &name, |module| {
        load_module(quiet, &modules_dir, module)
    })
}

fn load_module(quiet: bool, modules_dir: &Path, module: &str) -> anyhow::Result<()> {
    let pattern = format!(
        "{}/kernel/**/{}.ko*",
        modules_dir
            .to_str()
            .ok_or_else(|| anyhow!("failed to convert {} to string", modules_dir.display()))?,
        module
    );
    let module_path = glob(&pattern)
        .with_context(|| format!("failed to glob: {pattern}"))?
        .next()
        .ok_or_else(|| anyhow!("module not found: {module}"))?
        .context("glob error")?;

    output!(quiet, "loading module: {}", module_path.display());

    let compression = match module_path
        .as_path()
        .extension()
        .and_then(|extension| extension.to_str())
    {
        Some("xz") => Compression::Xz,
        Some("zst") => Compression::Zstd,
        _ => Compression::None,
    };

    let contents = read_to_end(&module_path, compression)
        .with_context(|| format!("read_to_end({})", module_path.display()))?;

    if !contents.starts_with(&[0x7f, 0x45, 0x4c, 0x46]) {
        bail!("module is not an valid ELF file");
    }

    match init_module(&contents, c"") {
        Ok(()) => {
            output!(quiet, "module loaded successfully");
            Ok(())
        }
        Err(e) => {
            if e == nix::errno::Errno::EEXIST {
                Err(anyhow!("module already loaded"))
            } else {
                Err(anyhow!("failed to load module: {e}"))
            }
        }
    }
}

fn resolve_module<T>(
    aliases: impl BufRead,
    name: &str,
    use_module: impl FnOnce(&str) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    for line in aliases.lines() {
        let line = line?;
        let Some((alias, module)) = parse_alias_line(&line)? else {
            continue;
        };
        if alias == name {
            return use_module(module);
        }
    }
    // A module need not declare an alias for its own name. The subsequent
    // module lookup reports an error if neither an alias nor that name exists.
    use_module(name)
}

fn parse_alias_line(line: &str) -> anyhow::Result<Option<(&str, &str)>> {
    let Some(line) = line.strip_prefix("alias ") else {
        return Ok(None);
    };
    // modules.alias entries may have spaces in the alias; the final field is
    // the module name.
    let (alias, module) = line
        .rsplit_once(' ')
        .with_context(|| format!("alias line missing module: alias {line}"))?;
    if alias.is_empty() || module.is_empty() {
        bail!("alias line missing field: alias {line}");
    }
    Ok(Some((alias, module)))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::resolve_module;

    #[rstest]
    #[case::alias("net-sch-clsact", "sch_ingress")]
    #[case::alias_with_spaces("mt8195_mt6359 soc card", "mt8195-mt6359")]
    #[case::module_name("cls_bpf", "cls_bpf")]
    fn resolves_aliases_and_module_names(#[case] name: &str, #[case] expected: &str) {
        let aliases =
            b"alias net-sch-clsact sch_ingress\nalias mt8195_mt6359 soc card mt8195-mt6359\n";
        resolve_module(aliases.as_slice(), name, |module| {
            assert_eq!(module, expected);
            Ok(())
        })
        .unwrap();
    }
}
